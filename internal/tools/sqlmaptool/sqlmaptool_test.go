package sqlmaptool

import (
	"strings"
	"testing"
)

func TestBuildCommand_GETRecipe(t *testing.T) {
	cmd, err := buildCommand(map[string]string{
		"recipe": "get",
		"url":    "http://127.0.0.1:8088/login5?user=admin&pass=x",
	}, "/tmp/out")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	mustContain(t, cmd, "sqlmap")
	mustContain(t, cmd, "-u='http://127.0.0.1:8088/login5?user=admin&pass=x'")
	mustContain(t, cmd, "--batch")
	mustContain(t, cmd, "--random-agent")
	mustContain(t, cmd, "--level=3")
	mustContain(t, cmd, "--risk=2")
	mustContain(t, cmd, "--output-dir='/tmp/out'")
	mustNotContain(t, cmd, "--method=POST")
}

func TestBuildCommand_FormRecipe(t *testing.T) {
	cmd, err := buildCommand(map[string]string{
		"recipe": "form",
		"url":    "http://127.0.0.1:8088/login1",
		"data":   "username=admin&password=x",
		"params": "username,password",
		"level":  "5",
		"risk":   "3",
	}, "/tmp/out")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	mustContain(t, cmd, "--method=POST")
	mustContain(t, cmd, "--data='username=admin&password=x'")
	mustContain(t, cmd, "-p 'username,password'")
	mustContain(t, cmd, "--level=5")
	mustContain(t, cmd, "--risk=3")
	mustContain(t, cmd, "--batch")
}

func TestBuildCommand_JSONRecipeAddsContentType(t *testing.T) {
	cmd, err := buildCommand(map[string]string{
		"recipe": "json",
		"url":    "http://127.0.0.1:8088/login2",
		"data":   `{"username":"admin","password":"x"}`,
	}, "/tmp/out")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	mustContain(t, cmd, "--headers='Content-Type: application/json'")
	mustContain(t, cmd, `--data='{"username":"admin","password":"x"}'`)
}

func TestBuildCommand_CSRFRequiresTokenAndURL(t *testing.T) {
	_, err := buildCommand(map[string]string{
		"recipe": "csrf",
		"url":    "http://127.0.0.1:8088/login3",
		"data":   "username=admin&password=x&csrf_token=_",
	}, "/tmp/out")
	if err == nil {
		t.Fatalf("expected error for missing csrf_token/csrf_url")
	}

	cmd, err := buildCommand(map[string]string{
		"recipe":     "csrf",
		"url":        "http://127.0.0.1:8088/login3",
		"data":       "username=admin&password=x&csrf_token=_",
		"csrf_token": "csrf_token",
		"csrf_url":   "http://127.0.0.1:8088/login3",
	}, "/tmp/out")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	mustContain(t, cmd, "--csrf-token='csrf_token'")
	mustContain(t, cmd, "--csrf-url='http://127.0.0.1:8088/login3'")
}

func TestBuildCommand_CookieRecipeRequiresMarker(t *testing.T) {
	_, err := buildCommand(map[string]string{
		"recipe": "cookie",
		"url":    "http://127.0.0.1:8088/",
		"cookie": "session_hint=guest; lang=en",
	}, "/tmp/out")
	if err == nil {
		t.Fatalf("expected error for cookie without * marker")
	}

	cmd, err := buildCommand(map[string]string{
		"recipe": "cookie",
		"url":    "http://127.0.0.1:8088/",
		"cookie": "session_hint=*; lang=en",
	}, "/tmp/out")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	mustContain(t, cmd, "--cookie='session_hint=*; lang=en'")
}

func TestBuildCommand_RejectsUnknownRecipe(t *testing.T) {
	if _, err := buildCommand(map[string]string{"recipe": "blind"}, "/tmp/out"); err == nil {
		t.Fatalf("expected error on unknown recipe")
	}
}

func TestBuildCommand_RejectsNonHTTPURL(t *testing.T) {
	if _, err := buildCommand(map[string]string{
		"recipe": "get",
		"url":    "file:///etc/passwd",
	}, "/tmp/out"); err == nil {
		t.Fatalf("expected error on file:// url")
	}
}

func TestBuildCommand_ValidatesTechnique(t *testing.T) {
	if _, err := buildCommand(map[string]string{
		"recipe":    "get",
		"url":       "http://x/",
		"technique": "BadFlag",
	}, "/tmp/out"); err == nil {
		t.Fatalf("expected technique validation error")
	}

	cmd, err := buildCommand(map[string]string{
		"recipe":    "get",
		"url":       "http://x/",
		"technique": "BT",
	}, "/tmp/out")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	mustContain(t, cmd, "--technique='BT'")
}

func TestBuildCommand_ClampsLevelRiskTimeout(t *testing.T) {
	cmd, err := buildCommand(map[string]string{
		"recipe":          "get",
		"url":             "http://x/",
		"level":           "99",
		"risk":            "0",
		"timeout_seconds": "99999",
	}, "/tmp/out")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	mustContain(t, cmd, "--level=5")
	mustContain(t, cmd, "--risk=1")
	mustContain(t, cmd, "--timeout=180")
}

func TestBuildCommand_AlwaysSetsBaselineFlags(t *testing.T) {
	cmd, err := buildCommand(map[string]string{
		"recipe": "get",
		"url":    "http://x/",
	}, "/tmp/out")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, mandatory := range []string{
		"--batch",
		"--random-agent",
		"--flush-session",
		"--threads=5",
		"--timeout=30",
		"--retries=1",
		"--output-dir='/tmp/out'",
	} {
		mustContain(t, cmd, mandatory)
	}
}

func TestShellEscapeQuotesEmbeddedSingleQuotes(t *testing.T) {
	got := shellEscape("a'b")
	want := `'a'\''b'`
	if got != want {
		t.Fatalf("shellEscape: got %q want %q", got, want)
	}
}

func TestCleanParamListDropsGarbage(t *testing.T) {
	if got := cleanParamList("user, pass, $evil, id"); got != "user,pass,id" {
		t.Fatalf("cleanParamList dropped: got %q", got)
	}
}

func TestCleanIgnoreCodesDropsNonNumeric(t *testing.T) {
	if got := cleanIgnoreCodes("401, 500, foo, 4xx, 403"); got != "401,500,403" {
		t.Fatalf("cleanIgnoreCodes: got %q", got)
	}
}

// helpers ------------------------------------------------------------------

func mustContain(t *testing.T, s, sub string) {
	t.Helper()
	if !strings.Contains(s, sub) {
		t.Fatalf("expected %q to contain %q\nfull: %s", sub, sub, s)
	}
}

func mustNotContain(t *testing.T, s, sub string) {
	t.Helper()
	if strings.Contains(s, sub) {
		t.Fatalf("expected NOT to find %q in %s", sub, s)
	}
}
