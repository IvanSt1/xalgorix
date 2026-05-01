// Package sqlmaptool exposes a structured `sqlmap_scan` tool.
//
// The generic `terminal_execute` tool lets the LLM write any shell
// command it wants, which in practice means it hallucinates sqlmap
// flags (--json, --auto, --full, ...) and keeps omitting --batch/--data
// on POST login forms. Those failures are counted against the single
// shared `terminal_execute` circuit breaker, blocking every other
// shell command for 60 seconds.
//
// This tool pins the shape of the invocation to one of five canonical
// recipes (GET, form-urlencoded POST, JSON POST, CSRF-protected POST,
// cookie-based) and assembles the command itself. The LLM cannot forget
// --batch, cannot invent flags, and failures only block sqlmap, not the
// whole shell.
package sqlmaptool

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/tools"
	"github.com/xalgord/xalgorix/v4/internal/tools/terminal"
)

// Register attaches the sqlmap_scan tool to the registry.
func Register(r *tools.Registry) {
	r.Register(&tools.Tool{
		Name: "sqlmap_scan",
		Description: "Run sqlmap against a confirmed injection point using one of five canonical recipes (get/form/json/csrf/cookie). Use this INSTEAD of constructing sqlmap commands by hand in terminal_execute — it guarantees correct flag shape, always sets --batch, and isolates failures from other shell commands. Call only after manual testing has surfaced an actual SQLi indicator.",
		Parameters: []tools.Parameter{
			{Name: "recipe", Description: "Required. One of: get | form | json | csrf | cookie. Pick by the request shape of the vulnerable endpoint — do not guess.", Required: true},
			{Name: "url", Description: "Required. Full target URL. For `get`, include the vulnerable query string. For `form`/`json`/`csrf`, point at the form action URL. For `cookie`, point at any URL that accepts the cookie.", Required: true},
			{Name: "data", Description: "Body to send. Required for `form`/`json`/`csrf`. Mark the injection point with '*' if you want to limit testing to one field, or use the `params` field to pass -p.", Required: false},
			{Name: "params", Description: "Comma-separated list of parameter names to test. Passed through to sqlmap -p. Useful when `data` contains many fields but only one is interesting.", Required: false},
			{Name: "headers", Description: "Extra request headers, one per line (e.g. `X-Api-Key: abc`). JSON recipe automatically adds `Content-Type: application/json`; do not repeat it here.", Required: false},
			{Name: "cookie", Description: "Cookie header value. Required for `cookie` recipe — must contain a '*' marker on the injectable cookie value, e.g. `session_hint=*; lang=en`.", Required: false},
			{Name: "csrf_token", Description: "Name of the CSRF token field as it appears in the HTML or header. Required for `csrf` recipe.", Required: false},
			{Name: "csrf_url", Description: "URL sqlmap should fetch to scrape a fresh CSRF token before each request. Required for `csrf` recipe; usually the GET version of the login page.", Required: false},
			{Name: "dbms", Description: "Optional DBMS hint (mysql|postgresql|mssql|oracle|sqlite|...). Speeds detection when the backend is known.", Required: false},
			{Name: "technique", Description: "Optional subset of BEUSTQ (default all). Example: `BT` for boolean+time-based only.", Required: false},
			{Name: "level", Description: "Detection level 1-5 (default 3). Raise to 4-5 when headers/cookies need testing.", Required: false},
			{Name: "risk", Description: "Risk level 1-3 (default 2). Level 3 enables OR-based and stacked queries — only use against throwaway targets.", Required: false},
			{Name: "ignore_code", Description: "HTTP status codes to ignore, comma-separated (passed to --ignore-code). Example: `401,403`.", Required: false},
			{Name: "extract", Description: "Optional post-detection action: `dbs` | `tables` | `dump` | `current-user`. Leave empty to stop after detection.", Required: false},
			{Name: "timeout_seconds", Description: "Per-request timeout passed to --timeout. Default 30. Maximum 180.", Required: false},
		},
		Execute: execute,
	})
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

var validRecipe = map[string]bool{
	"get": true, "form": true, "json": true, "csrf": true, "cookie": true,
}

var validTechnique = regexp.MustCompile(`^[BEUSTQ]{1,6}$`)

var validDBMS = map[string]bool{
	"mysql": true, "postgresql": true, "mssql": true, "oracle": true,
	"sqlite": true, "sybase": true, "db2": true, "hsqldb": true,
	"informix": true, "mariadb": true, "firebird": true, "h2": true,
	"cockroachdb": true, "ibm db2": true,
}

var validExtract = map[string]bool{
	"dbs": true, "tables": true, "dump": true, "current-user": true,
	"current-db": true, "users": true, "passwords": true,
}

// slugSafe keeps filenames sane on any filesystem sqlmap is pointed at.
var slugRE = regexp.MustCompile(`[^a-zA-Z0-9._-]+`)

func slug(s string) string {
	out := slugRE.ReplaceAllString(s, "_")
	if len(out) > 48 {
		out = out[:48]
	}
	return strings.Trim(out, "_")
}

// clampInt parses args[key] as an integer in [lo, hi]; falls back to def.
func clampInt(args map[string]string, key string, lo, hi, def int) int {
	raw := strings.TrimSpace(args[key])
	if raw == "" {
		return def
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return def
	}
	if n < lo {
		return lo
	}
	if n > hi {
		return hi
	}
	return n
}

// ---------------------------------------------------------------------------
// Command assembly
// ---------------------------------------------------------------------------

// buildCommand assembles the canonical sqlmap command for a recipe. It
// is kept pure (no I/O) so it can be unit-tested without running anything.
func buildCommand(args map[string]string, outputDir string) (string, error) {
	recipe := strings.ToLower(strings.TrimSpace(args["recipe"]))
	if !validRecipe[recipe] {
		return "", fmt.Errorf("recipe must be one of: get, form, json, csrf, cookie (got %q)", recipe)
	}
	url := strings.TrimSpace(args["url"])
	if url == "" {
		return "", fmt.Errorf("url is required")
	}
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		return "", fmt.Errorf("url must start with http:// or https:// (got %q)", url)
	}

	level := clampInt(args, "level", 1, 5, 3)
	risk := clampInt(args, "risk", 1, 3, 2)
	timeoutSecs := clampInt(args, "timeout_seconds", 5, 180, 30)

	parts := []string{"sqlmap"}

	switch recipe {
	case "get":
		parts = append(parts, shellQuoteArg("-u", url))
	case "form", "json", "csrf":
		data := strings.TrimSpace(args["data"])
		if data == "" {
			return "", fmt.Errorf("recipe %q requires `data` (request body)", recipe)
		}
		parts = append(parts,
			shellQuoteArg("-u", url),
			"--method=POST",
			shellQuoteArg("--data", data),
		)
	case "cookie":
		parts = append(parts, shellQuoteArg("-u", url))
	}

	// Params filter
	if ps := strings.TrimSpace(args["params"]); ps != "" {
		// Strip spaces, validate tokens look like identifiers.
		cleaned := cleanParamList(ps)
		if cleaned != "" {
			parts = append(parts, "-p", shellEscape(cleaned))
		}
	}

	// Headers (JSON recipe auto-adds Content-Type)
	headers := []string{}
	if recipe == "json" {
		headers = append(headers, "Content-Type: application/json")
	}
	if raw := strings.TrimSpace(args["headers"]); raw != "" {
		for _, line := range strings.Split(raw, "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			if strings.ContainsAny(line, "\r\x00") {
				return "", fmt.Errorf("headers contain control characters")
			}
			// Avoid duplicating Content-Type when user supplied one on json recipe.
			if recipe == "json" && strings.HasPrefix(strings.ToLower(line), "content-type:") {
				continue
			}
			headers = append(headers, line)
		}
	}
	if len(headers) > 0 {
		parts = append(parts, shellQuoteArg("--headers", strings.Join(headers, `\n`)))
	}

	// Cookie
	if recipe == "cookie" {
		cookie := strings.TrimSpace(args["cookie"])
		if cookie == "" {
			return "", fmt.Errorf("recipe cookie requires `cookie` (include '*' on the injectable value)")
		}
		if !strings.Contains(cookie, "*") {
			return "", fmt.Errorf("cookie recipe requires '*' marker on the injectable value, e.g. session_hint=*")
		}
		parts = append(parts, shellQuoteArg("--cookie", cookie))
	} else if cookie := strings.TrimSpace(args["cookie"]); cookie != "" {
		// Cookie is fine to pass on non-cookie recipes (e.g. authenticated scan).
		parts = append(parts, shellQuoteArg("--cookie", cookie))
	}

	// CSRF
	if recipe == "csrf" {
		tok := strings.TrimSpace(args["csrf_token"])
		cURL := strings.TrimSpace(args["csrf_url"])
		if tok == "" || cURL == "" {
			return "", fmt.Errorf("recipe csrf requires csrf_token and csrf_url")
		}
		if !strings.HasPrefix(cURL, "http://") && !strings.HasPrefix(cURL, "https://") {
			return "", fmt.Errorf("csrf_url must start with http(s)://")
		}
		parts = append(parts,
			shellQuoteArg("--csrf-token", tok),
			shellQuoteArg("--csrf-url", cURL),
		)
	}

	// DBMS hint
	if d := strings.ToLower(strings.TrimSpace(args["dbms"])); d != "" {
		if !validDBMS[d] {
			return "", fmt.Errorf("unknown dbms hint %q", d)
		}
		parts = append(parts, shellQuoteArg("--dbms", d))
	}

	// Technique
	if t := strings.ToUpper(strings.TrimSpace(args["technique"])); t != "" {
		if !validTechnique.MatchString(t) {
			return "", fmt.Errorf("technique must be 1-6 chars from BEUSTQ, got %q", t)
		}
		parts = append(parts, shellQuoteArg("--technique", t))
	}

	if codes := cleanIgnoreCodes(args["ignore_code"]); codes != "" {
		parts = append(parts, shellQuoteArg("--ignore-code", codes))
	}

	// Post-detection extraction
	if e := strings.ToLower(strings.TrimSpace(args["extract"])); e != "" {
		if !validExtract[e] {
			return "", fmt.Errorf("extract must be one of dbs|tables|dump|current-user|current-db|users|passwords, got %q", e)
		}
		parts = append(parts, "--"+e)
	}

	// Baseline flags we ALWAYS set. This is the whole point of the tool —
	// these cannot be forgotten and cannot be hallucinated away.
	parts = append(parts,
		fmt.Sprintf("--level=%d", level),
		fmt.Sprintf("--risk=%d", risk),
		"--batch",
		"--random-agent",
		"--flush-session",
		"--threads=5",
		fmt.Sprintf("--timeout=%d", timeoutSecs),
		"--retries=1",
		shellQuoteArg("--output-dir", outputDir),
	)

	return strings.Join(parts, " "), nil
}

// ---------------------------------------------------------------------------
// Execute
// ---------------------------------------------------------------------------

func execute(args map[string]string) (tools.Result, error) {
	// Derive a deterministic-ish output dir under the current workdir.
	base := terminal.GetWorkDir()
	if base == "" {
		base = os.TempDir()
	}
	outputDir := filepath.Join(
		base,
		"sqlmap_"+slug(args["recipe"])+"_"+slug(args["url"])+"_"+time.Now().Format("150405"),
	)
	// Best-effort; sqlmap will create it itself but we try to ensure
	// writability early so errors show up in the result rather than deep
	// inside sqlmap.
	_ = os.MkdirAll(outputDir, 0o755)

	cmd, err := buildCommand(args, outputDir)
	if err != nil {
		return tools.Result{
			Output:  fmt.Sprintf("[sqlmap_scan] invalid arguments: %s\nFix your arguments — do NOT fall back to constructing sqlmap by hand via terminal_execute.", err),
			Success: false,
		}, nil
	}

	output, exitCode := terminal.RunShell(cmd)

	header := fmt.Sprintf(
		"[sqlmap_scan] recipe=%s url=%s exit=%d output_dir=%s\n$ %s\n",
		args["recipe"], args["url"], exitCode, outputDir, cmd,
	)
	metadata := map[string]any{
		"recipe":     args["recipe"],
		"url":        args["url"],
		"exit_code":  exitCode,
		"output_dir": outputDir,
		"command":    cmd,
	}
	return tools.Result{
		Output:   header + output,
		Success:  exitCode == 0,
		Metadata: metadata,
	}, nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// shellEscape single-quotes a value so the shell passes it to sqlmap
// verbatim. Single quotes inside the value are handled by closing the
// quote, inserting '\'' and re-opening.
func shellEscape(v string) string {
	return "'" + strings.ReplaceAll(v, "'", `'\''`) + "'"
}

// shellQuoteArg renders `flag=value` with proper quoting. Using = avoids
// any ambiguity between the flag and the value when the value starts
// with a dash.
func shellQuoteArg(flag, value string) string {
	return flag + "=" + shellEscape(value)
}

var paramTokenRE = regexp.MustCompile(`^[A-Za-z0-9_.\[\]-]+$`)

func cleanParamList(raw string) string {
	tokens := strings.Split(raw, ",")
	keep := make([]string, 0, len(tokens))
	for _, t := range tokens {
		t = strings.TrimSpace(t)
		if paramTokenRE.MatchString(t) {
			keep = append(keep, t)
		}
	}
	return strings.Join(keep, ",")
}

var ignoreCodeRE = regexp.MustCompile(`^[0-9]{3}$`)

func cleanIgnoreCodes(raw string) string {
	tokens := strings.Split(raw, ",")
	keep := make([]string, 0, len(tokens))
	for _, t := range tokens {
		t = strings.TrimSpace(t)
		if ignoreCodeRE.MatchString(t) {
			keep = append(keep, t)
		}
	}
	return strings.Join(keep, ",")
}
