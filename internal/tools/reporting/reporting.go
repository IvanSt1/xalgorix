// Package reporting provides vulnerability reporting tools with exploit-before-report validation.
package reporting

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/tools"
)

// Valid verification methods — the agent must specify one when reporting.
var validVerificationMethods = map[string]bool{
	"exploited":         true, // Full exploitation with proof
	"time_based":        true, // Time-based blind confirmation (SQLi, command injection)
	"data_extracted":    true, // Actual data was extracted
	"callback_received": true, // SSRF/XXE/RCE callback received
	"error_based":       true, // Error-based confirmation (SQL error, stack trace)
	"blind_confirmed":   true, // Blind vulnerability confirmed via side-channel
	"reflected":         true, // Payload reflected in response (XSS)
	"authenticated":     true, // Auth bypass / IDOR with evidence
	"manual_verified":   true, // Manually verified via browser / curl
}

// Minimum evidence keywords per severity — used for auto-downgrade heuristics.
var evidenceKeywords = map[string][]string{
	"critical": {"rce", "remote code", "shell", "reverse shell", "command execution", "dump", "database",
		"full access", "admin takeover", "account takeover", "full compromise", "root access",
		"aws key", "secret key", "private key", "all user", "mass data"},
	"high": {"sqli", "sql injection", "data extract", "xss", "cross-site", "ssrf", "idor",
		"auth bypass", "token", "session hijack", "file inclusion", "sensitive data",
		"personal data", "pii", "email address", "phone number", "credit card",
		"password hash", "api key", "access token", "user data", "private information",
		"unauthorized access", "privilege escalation"},
	"medium": {"reflected", "csrf", "redirect", "disclosure", "injection", "traversal",
		"internal ip", "internal path", "config", "source code", "debug", "stack trace"},
}

// Vulnerability represents a found vulnerability.
type Vulnerability struct {
	ID                 string  `json:"id"`
	Title              string  `json:"title"`
	Severity           string  `json:"severity"`
	OriginalSeverity   string  `json:"original_severity,omitempty"` // if auto-downgraded
	Description        string  `json:"description"`
	Impact             string  `json:"impact"`
	Target             string  `json:"target"`
	Endpoint           string  `json:"endpoint"`
	Method             string  `json:"method"`
	CVE                string  `json:"cve"`
	CVSS               float64 `json:"cvss"`
	CVSSVector         string  `json:"cvss_vector,omitempty"` // CVSS 3.1 vector string
	TechnicalAnalysis  string  `json:"technical_analysis"`
	PoCDescription     string  `json:"poc_description"`
	PoCScript          string  `json:"poc_script_code"`
	Remediation        string  `json:"remediation_steps"`
	ExploitationProof  string  `json:"exploitation_proof"`
	VerificationMethod string  `json:"verification_method"`
	Verified           bool    `json:"verified"`
	Timestamp          string  `json:"timestamp"`
	AgentName          string  `json:"agent_name"`
}

var (
	vulnerabilities []Vulnerability
	vulnMu          sync.RWMutex
)

// Register adds reporting tools to the registry.
func Register(r *tools.Registry) {
	r.Register(&tools.Tool{
		Name: "report_vulnerability",
		Description: `Report a VERIFIED, EXPLOITABLE vulnerability with proof. CRITICAL RULES:
1. You MUST have already EXPLOITED this vulnerability before calling this tool.
2. You MUST provide exploitation_proof showing concrete evidence (extracted data, reflected payload, command output, callback, timing proof).
3. Reports without exploitation proof for severity >= medium will be REJECTED — exploit first, then report.
4. Do NOT report missing headers, version disclosure, or scanner-only findings as vulnerabilities — those are INFO at best.
5. SEVERITY MUST MATCH CVSS SCORE per HackerOne standards:
   - Critical (9.0-10.0): RCE, full DB dump, mass account takeover, admin access
   - High (7.0-8.9): SQLi with data extraction, stored XSS with session hijack, SSRF to internal services, auth bypass, IDOR exposing PII
   - Medium (4.0-6.9): Reflected XSS, CSRF on non-critical actions, open redirect, info disclosure of internal data
   - Low (0.1-3.9): Clickjacking, missing cookie flags, CORS without credential theft, path disclosure
   - None/Info (0.0): Missing headers, version disclosure, self-XSS, DNS config issues`,
		Parameters: []tools.Parameter{
			{Name: "title", Description: "Vulnerability title", Required: true},
			{Name: "severity", Description: "Severity per HackerOne CVSS ranges: critical (CVSS 9.0-10.0), high (7.0-8.9), medium (4.0-6.9), low (0.1-3.9), info (0.0). Must match your CVSS score.", Required: true},
			{Name: "description", Description: "Detailed description of the vulnerability", Required: true},
			{Name: "exploitation_proof", Description: "REQUIRED for medium+. Concrete evidence of exploitation: extracted data, reflected payload text, command output, timing measurement, callback confirmation. Paste actual output here.", Required: true},
			{Name: "verification_method", Description: "How you verified: exploited, time_based, data_extracted, callback_received, error_based, blind_confirmed, reflected, authenticated, manual_verified", Required: true},
			{Name: "impact", Description: "Real-world impact assessment", Required: false},
			{Name: "target", Description: "Target URL/host", Required: false},
			{Name: "endpoint", Description: "Affected endpoint", Required: false},
			{Name: "method", Description: "HTTP method", Required: false},
			{Name: "cve", Description: "CVE identifier if known", Required: false},
			// cvss is intentionally NOT Required. reportVuln auto-derives a
			// sensible default from `severity` when missing (see the
			// switch around `if cvss == 0` below). Marking it required
			// caused the registry to reject calls before that fallback
			// could run, sending the LLM into the same retry loop as
			// the old read_skill bug.
			{Name: "cvss", Description: "CVSS 3.1 base score (0.0-10.0). Should match severity: critical=9.0-10.0, high=7.0-8.9, medium=4.0-6.9, low=0.1-3.9, info=0.0. If omitted, a default is auto-derived from `severity`.", Required: false},
			{Name: "cvss_vector", Description: "CVSS 3.1 vector string, e.g. CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H. Components: AV(Attack Vector):N/A/L/P, AC(Attack Complexity):L/H, PR(Privileges Required):N/L/H, UI(User Interaction):N/R, S(Scope):U/C, C(Confidentiality):N/L/H, I(Integrity):N/L/H, A(Availability):N/L/H", Required: false},
			{Name: "technical_analysis", Description: "Technical details of the vulnerability", Required: false},
			{Name: "poc_description", Description: "Step-by-step PoC description", Required: false},
			{Name: "poc_script_code", Description: "Reproducible PoC code (curl, python, etc.)", Required: false},
			{Name: "remediation_steps", Description: "Remediation recommendations", Required: false},
		},
		Execute: reportVuln,
	})
}

func reportVuln(args map[string]string) (tools.Result, error) {
	severity := strings.ToLower(strings.TrimSpace(args["severity"]))
	proof := strings.TrimSpace(args["exploitation_proof"])
	method := strings.ToLower(strings.TrimSpace(args["verification_method"]))
	title := strings.TrimSpace(args["title"])

	// ── Gate 1: Validate verification method ──
	if method == "" || !validVerificationMethods[method] {
		return tools.Result{
			Output: fmt.Sprintf("❌ REJECTED: Invalid verification_method '%s'. Must be one of: %s\n\nYou must EXPLOIT the vulnerability first, then report with the correct verification method.",
				method, formatValidMethods()),
		}, nil
	}

	// ── Gate 2: Require exploitation proof for medium+ severity ──
	isHighSeverity := severity == "critical" || severity == "high" || severity == "medium"
	if isHighSeverity && (proof == "" || len(proof) < 20) {
		return tools.Result{
			Output: fmt.Sprintf(`❌ REJECTED: '%s' reported as %s but has NO exploitation proof.

XALGORIX RULE: You MUST exploit the vulnerability BEFORE reporting it.

Required steps:
1. You found a potential %s → Good, but not enough to report.
2. Now EXPLOIT it safely — extract data, trigger the payload, confirm the behavior.
3. Paste the ACTUAL OUTPUT of exploitation into 'exploitation_proof'.
4. Then call report_vulnerability again with the proof.

If you cannot exploit it, downgrade severity to 'info' and report as informational.`,
				title, strings.ToUpper(severity), title),
		}, nil
	}

	// ── Gate 3: Check for common false positive patterns ──
	if rejection := checkFalsePositive(title, args["description"], severity, proof); rejection != "" {
		return tools.Result{Output: rejection}, nil
	}

	// ── Gate 4: Smart Deduplication — same vuln type on same endpoint = duplicate ──
	endpoint := strings.TrimSpace(args["endpoint"])
	vulnType := extractVulnType(title, args["description"])
	normalizedEndpoint := normalizeEndpoint(endpoint)

	vulnMu.RLock()
	for _, existing := range vulnerabilities {
		existingType := extractVulnType(existing.Title, existing.Description)
		existingNormEndpoint := normalizeEndpoint(existing.Endpoint)
		
		// Check 1: Exact title + endpoint match
		if strings.EqualFold(existing.Title, title) && existing.Endpoint == endpoint {
			vulnMu.RUnlock()
			return tools.Result{
				Output: fmt.Sprintf("⚠️ DUPLICATE: '%s' at endpoint '%s' already reported as %s. Skipping.", title, endpoint, existing.ID),
			}, nil
		}
		
		// Check 2: Same vulnerability TYPE on same normalized endpoint
		if vulnType != "" && vulnType == existingType && normalizedEndpoint == existingNormEndpoint && normalizedEndpoint != "" {
			vulnMu.RUnlock()
			return tools.Result{
				Output: fmt.Sprintf("⚠️ DUPLICATE: Same vulnerability type '%s' already reported on endpoint '%s' as %s ('%s'). Skipping.\nIf this is genuinely different, use a distinct endpoint or describe how it differs.",
					vulnType, endpoint, existing.ID, existing.Title),
			}, nil
		}
	}
	vulnMu.RUnlock()

	// ── Gate 5: Severity classification — enforce max severity per vuln type ──
	originalSeverity := ""
	if cappedSev, reason := classifySeverity(title, args["description"], severity, proof); cappedSev != severity {
		originalSeverity = severity
		severity = cappedSev
		_ = reason // will be included in output message below
	}

	// ── Auto-downgrade: weak proof for high severity ──
	if originalSeverity == "" && isHighSeverity && !hasStrongEvidence(severity, proof, args["description"]) {
		originalSeverity = severity
		severity = "info"
	}

	var cvss float64
	if c := args["cvss"]; c != "" {
		fmt.Sscanf(c, "%f", &cvss)
	}
	cvssVector := strings.TrimSpace(args["cvss_vector"])

	// ── Gate 6: CVSS-to-Severity enforcement (HackerOne standard) ──
	// If CVSS was provided, ensure severity matches the HackerOne CVSS ranges.
	// CVSS is authoritative: Critical=9.0-10.0, High=7.0-8.9, Medium=4.0-6.9, Low=0.1-3.9, None=0.0
	if cvss > 0 {
		cvssSeverity := severityFromCVSS(cvss)
		if severityRank[severity] > severityRank[cvssSeverity] {
			// Severity label is higher than what CVSS justifies → downgrade
			if originalSeverity == "" {
				originalSeverity = severity
			}
			severity = cvssSeverity
		} else if severityRank[severity] < severityRank[cvssSeverity] && originalSeverity == "" {
			// Severity label is lower than CVSS justifies → upgrade to match
			originalSeverity = severity
			severity = cvssSeverity
		}
	}

	// If no CVSS provided, auto-assign a default CVSS based on severity
	if cvss == 0 {
		switch severity {
		case "critical":
			cvss = 9.5
		case "high":
			cvss = 8.0
		case "medium":
			cvss = 5.5
		case "low":
			cvss = 2.5
		default:
			cvss = 0.0
		}
	}

	vulnMu.Lock()
	vuln := Vulnerability{
		ID:                 fmt.Sprintf("XALG-%d", len(vulnerabilities)+1),
		Title:              title,
		Severity:           severity,
		OriginalSeverity:   originalSeverity,
		Description:        args["description"],
		Impact:             args["impact"],
		Target:             args["target"],
		Endpoint:           endpoint,
		Method:             args["method"],
		CVE:                args["cve"],
		CVSS:               cvss,
		CVSSVector:         cvssVector,
		TechnicalAnalysis:  args["technical_analysis"],
		PoCDescription:     args["poc_description"],
		PoCScript:          args["poc_script_code"],
		ExploitationProof:  proof,
		VerificationMethod: method,
		Verified:           proof != "" && method != "",
		Remediation:        args["remediation_steps"],
		Timestamp:          time.Now().Format(time.RFC3339),
	}

	vulnerabilities = append(vulnerabilities, vuln)
	vulnMu.Unlock()

	msg := fmt.Sprintf("✅ Vulnerability reported: [%s] %s (%s | CVSS %.1f) — Verified: %v", vuln.ID, vuln.Title, strings.ToUpper(vuln.Severity), vuln.CVSS, vuln.Verified)
	if originalSeverity != "" {
		msg += fmt.Sprintf("\n⚠️ SEVERITY ADJUSTED from %s → %s (CVSS %.1f maps to %s per HackerOne standards)", strings.ToUpper(originalSeverity), strings.ToUpper(severity), cvss, strings.ToUpper(severity))
	}

	return tools.Result{
		Output:   msg,
		Metadata: map[string]any{"vuln_id": vuln.ID, "verified": vuln.Verified},
	}, nil
}

// checkFalsePositive detects common false positive patterns and rejects them.
func checkFalsePositive(title, description, severity, proof string) string {
	lower := strings.ToLower(title + " " + description)
	isHighSev := severity == "critical" || severity == "high" || severity == "medium"

	// Pattern 1: Missing security headers reported as vulnerability
	headerKeywords := []string{"missing header", "x-frame-options", "x-content-type", "content-security-policy",
		"strict-transport", "x-xss-protection", "referrer-policy", "permissions-policy", "hsts"}
	for _, kw := range headerKeywords {
		if strings.Contains(lower, kw) && isHighSev {
			return fmt.Sprintf("❌ REJECTED: Missing security headers are INFORMATIONAL, not %s. Re-report as severity 'info' if needed.", strings.ToUpper(severity))
		}
	}

	// Pattern 2: Version/technology disclosure
	disclosureKeywords := []string{"version disclosure", "server header", "x-powered-by", "technology disclosure",
		"software version", "banner grabbing"}
	for _, kw := range disclosureKeywords {
		if strings.Contains(lower, kw) && isHighSev {
			return "❌ REJECTED: Version/technology disclosure is INFORMATIONAL unless you can exploit a specific CVE. Provide CVE + exploitation proof, or re-report as 'info'."
		}
	}

	// Pattern 3: Scanner-only findings without manual verification
	scannerKeywords := []string{"nuclei detected", "nuclei found", "scanner reported", "automated scan found",
		"wpscan found", "nmap detected"}
	for _, kw := range scannerKeywords {
		if strings.Contains(lower, kw) && proof == "" {
			return "❌ REJECTED: Scanner-only findings require MANUAL VERIFICATION. Run the scanner, then manually exploit the finding to confirm it. Paste the exploitation output as proof."
		}
	}

	// Pattern 4: CORS without exploitation proof
	if strings.Contains(lower, "cors") && isHighSev {
		corsProofKeywords := []string{"cookie", "token", "session", "steal", "extract", "hijack", "javascript", "xmlhttprequest", "fetch("}
		hasExploitProof := false
		lowerProof := strings.ToLower(proof)
		for _, kw := range corsProofKeywords {
			if strings.Contains(lowerProof, kw) {
				hasExploitProof = true
				break
			}
		}
		if !hasExploitProof {
			return "❌ REJECTED: CORS misconfiguration alone is INFORMATIONAL. To report as medium+, you must demonstrate cookie/token theft via CORS (provide PoC JavaScript that exfiltrates data). Otherwise re-report as 'info'."
		}
	}

	// Pattern 5: Open redirect without chaining
	if strings.Contains(lower, "open redirect") && isHighSev {
		chainKeywords := []string{"oauth", "token", "ssrf", "phishing", "chain", "exfiltrate", "steal"}
		hasChain := false
		lowerProof := strings.ToLower(proof + " " + description)
		for _, kw := range chainKeywords {
			if strings.Contains(lowerProof, kw) {
				hasChain = true
				break
			}
		}
		if !hasChain {
			return "❌ REJECTED: Open redirect alone is INFORMATIONAL. To report as medium+, chain it with OAuth token theft, SSRF, or demonstrate real impact. Otherwise re-report as 'info'."
		}
	}

	// Pattern 6: SSL/TLS issues (weak ciphers, old TLS versions)
	sslKeywords := []string{"ssl", "tls", "cipher", "certificate", "sweet32", "poodle", "heartbleed", "beast", "crime"}
	for _, kw := range sslKeywords {
		if strings.Contains(lower, kw) {
			return "❌ REJECTED: SSL/TLS configuration issues (weak ciphers, old versions) are OUT OF SCOPE. Do not report them."
		}
	}

	// Pattern 7: DNS configuration issues (SPF, DMARC, TXT)
	dnsKeywords := []string{"spf", "dmarc", "dkim", "domain-based message authentication", "sender policy framework", "txt record", "email spoofing"}
	for _, kw := range dnsKeywords {
		if strings.Contains(lower, kw) {
			return "❌ REJECTED: DNS and email configuration issues (SPF, DMARC, TXT, DKIM) are OUT OF SCOPE. Do not report them."
		}
	}

	// Pattern 8: CSV injection (almost always Informative on HackerOne)
	csvKeywords := []string{"csv injection", "formula injection", "spreadsheet injection", "csv formula", "dde injection", "excel injection"}
	for _, kw := range csvKeywords {
		if strings.Contains(lower, kw) && isHighSev {
			return "❌ REJECTED: CSV/formula injection is almost always marked INFORMATIVE on HackerOne. It requires victim action (opening file + enabling macros). Re-report as 'low' or 'info' at most."
		}
	}

	// Pattern 9: Clickjacking without exploitation proof
	if strings.Contains(lower, "clickjacking") || strings.Contains(lower, "click jacking") || strings.Contains(lower, "ui redressing") {
		if isHighSev {
			return "❌ REJECTED: Clickjacking is LOW severity (CVSS 2.0-3.9) per HackerOne. To report as medium+, you must demonstrate a sensitive state-changing action that can be performed via the iframe PoC (e.g., delete account, change email). Re-report as 'low'."
		}
	}

	// Pattern 10: Directory listing without sensitive file access
	if strings.Contains(lower, "directory listing") || strings.Contains(lower, "directory index") || strings.Contains(lower, "autoindex") {
		lowerProof := strings.ToLower(proof)
		sensitiveFileEvidence := []string{"password", "credential", "secret", "key", "token", "config", ".env", "database", "backup", ".sql", ".bak"}
		hasSensitive := false
		for _, kw := range sensitiveFileEvidence {
			if strings.Contains(lowerProof, kw) {
				hasSensitive = true
				break
			}
		}
		if !hasSensitive && isHighSev {
			return "❌ REJECTED: Directory listing alone is INFORMATIONAL unless sensitive files (credentials, configs, backups) are exposed AND accessed. Show the actual sensitive file contents in your proof."
		}
	}

	// Pattern 11: TRACE/OPTIONS HTTP method enabled
	traceKeywords := []string{"trace method", "trace enabled", "options method", "http method enabled", "http verb"}
	for _, kw := range traceKeywords {
		if strings.Contains(lower, kw) {
			return "❌ REJECTED: TRACE/OPTIONS methods enabled is INFORMATIONAL. Modern browsers block cross-site TRACE (XST), making this unexploitable. Do not report."
		}
	}

	// Pattern 12: Analytics API writeKey "bypass" — these are public client-side tokens by design
	analyticsKeywords := []string{"writekey", "write_key", "write key", "analytics key", "segment key", "analytics api"}
	analyticsEndpoints := []string{"/v1/i", "/v1/t", "/v1/p", "/v1/batch", "/v1/identify", "/v1/track", "/v1/page", "/v1/screen", "/v1/group", "/v1/alias"}
	isAnalyticsFP := false
	for _, kw := range analyticsKeywords {
		if strings.Contains(lower, kw) {
			isAnalyticsFP = true
			break
		}
	}
	if !isAnalyticsFP {
		for _, ep := range analyticsEndpoints {
			if strings.Contains(lower, ep) {
				isAnalyticsFP = true
				break
			}
		}
	}
	if isAnalyticsFP && (strings.Contains(lower, "analytics") || strings.Contains(lower, "validation") || strings.Contains(lower, "writekey") || strings.Contains(lower, "write_key") || strings.Contains(lower, "write key")) {
		return "❌ REJECTED: Analytics API writeKey bypass is NOT a vulnerability. writeKeys are PUBLIC client-side tokens shipped in JavaScript (Segment, Amplitude, Mixpanel, etc.). They are designed to be exposed. Bug bounty programs mark this as N/A or Informational. Do not report."
	}

	// Pattern 13: Rate limiting / brute force — almost always informational
	rateLimitKeywords := []string{"rate limit", "rate-limit", "no rate limit", "brute force", "brute-force",
		"account lockout", "missing rate limit", "unlimited requests", "no lockout", "login throttling"}
	for _, kw := range rateLimitKeywords {
		if strings.Contains(lower, kw) && isHighSev {
			return "❌ REJECTED: Missing rate limiting / brute force is INFORMATIONAL on HackerOne. Most programs explicitly exclude this. Re-report as 'info' at most."
		}
	}

	// Pattern 14: Success response without actual impact — APIs returning success:true
	if strings.Contains(lower, "success") && strings.Contains(lower, "true") &&
		(strings.Contains(lower, "any value") || strings.Contains(lower, "arbitrary") || strings.Contains(lower, "without validation")) {
		// Check if proof shows actual data modification or access
		lowerProof := strings.ToLower(proof)
		hasRealImpact := false
		impactWords := []string{"admin access", "modified", "deleted", "created user", "escalat", "bypass", "account", "password", "database"}
		for _, iw := range impactWords {
			if strings.Contains(lowerProof, iw) {
				hasRealImpact = true
				break
			}
		}
		if !hasRealImpact && isHighSev {
			return "❌ REJECTED: API returning success:true without input validation is NOT automatically a vulnerability. You must demonstrate ACTUAL IMPACT — data was modified, accounts were affected, or access was gained. A success response alone proves nothing. Re-report as 'info' with real impact proof, or move on."
		}
	}

	// Pattern 15: Client-side JavaScript config disclosure — PUBLIC_ENV, Sentry DSN, etc.
	// These are intentionally public client-side configurations, not secrets.
	jsConfigKeywords := []string{"sentry dsn", "public_env", "publicenv", "public env",
		"client-side javascript", "client side javascript", "javascript source",
		"next_public_", "react_app_", "vite_", "nuxt_public_",
		"window.__singletons", "window.__next", "window.__nuxt",
		"bundled javascript", "js chunk", "js bundle", "webpack chunk",
		"/_next/static", "/_nuxt/", "/static/js/",
		"application version", "app version"}
	jsConfigHits := 0
	for _, kw := range jsConfigKeywords {
		if strings.Contains(lower, kw) {
			jsConfigHits++
		}
	}
	// If 2+ JS config keywords match AND the "proof" is just viewing source/devtools
	if jsConfigHits >= 2 && isHighSev {
		lowerProof := strings.ToLower(proof)
		realExploitKeywords := []string{"rce", "shell", "admin access", "account takeover", "database",
			"password", "credential", "private key", "secret key", "aws_secret", "payment", "credit card"}
		hasRealExploit := false
		for _, ek := range realExploitKeywords {
			if strings.Contains(lowerProof, ek) {
				hasRealExploit = true
				break
			}
		}
		if !hasRealExploit {
			return "❌ REJECTED: Client-side JavaScript configuration (Sentry DSN, PUBLIC_ENV, API endpoints, app version) is NOT a vulnerability. These are PUBLIC client-side values shipped intentionally in JS bundles. Sentry DSNs are public by design. NEXT_PUBLIC_* vars are meant to be public. Bug bounty programs mark this as Informational or N/A. Do not report."
		}
	}

	// Pattern 16: Sentry DSN specifically — always public, never a vuln
	if strings.Contains(lower, "sentry") && (strings.Contains(lower, "dsn") || strings.Contains(lower, "ingest.sentry.io")) {
		return "❌ REJECTED: Sentry DSN is a PUBLIC client-side key designed to be embedded in JavaScript. It only allows sending error reports — no read access, no data extraction. This is NOT a vulnerability. Do not report."
	}

	// Pattern 17: Generic "information found in JavaScript source" without real impact
	if (strings.Contains(lower, "javascript") || strings.Contains(lower, "js source") || strings.Contains(lower, "source code")) &&
		(strings.Contains(lower, "information disclosure") || strings.Contains(lower, "sensitive information") || strings.Contains(lower, "exposed in")) {
		lowerProof := strings.ToLower(proof)
		// Only reject if proof is just "view source" style — not actual secret leakage
		if !strings.Contains(lowerProof, "password") && !strings.Contains(lowerProof, "private key") &&
			!strings.Contains(lowerProof, "aws_secret") && !strings.Contains(lowerProof, "database_url") &&
			isHighSev {
			return "❌ REJECTED: Finding configuration in client-side JavaScript is expected behavior — frontend apps MUST include API endpoints, service URLs, and public keys to function. This is only a vulnerability if ACTUAL SECRETS (passwords, private keys, database credentials) are exposed. Sentry DSNs, API base URLs, and app versions are NOT secrets."
		}
	}

	return ""
}

// hasStrongEvidence checks if the proof actually contains meaningful exploitation evidence.
// Uses impact-based analysis rather than just keyword matching.
func hasStrongEvidence(severity, proof, description string) bool {
	if proof == "" {
		return false
	}

	lowerProof := strings.ToLower(proof)
	lowerDesc := strings.ToLower(description)
	combined := lowerProof + " " + lowerDesc

	// Severity-specific keywords
	keywords, ok := evidenceKeywords[severity]
	if !ok {
		return true // low/info don't need strong evidence
	}
	for _, kw := range keywords {
		if strings.Contains(lowerProof, kw) {
			return true
		}
	}

	// Impact-based indicators (works for all severities)
	impactIndicators := []string{
		// Data exfiltration proof
		"extracted", "leaked", "exposed", "dumped", "obtained",
		"retrieved", "exfiltrated", "downloaded", "accessed",
		// Concrete data in proof
		"root:", "uid=", "gid=", "password", "passwd", "shadow",
		"select ", "union ", "from ", "where ",
		"alert(", "<script", "onerror=", "onload=", "document.cookie",
		"etc/passwd", "etc/shadow", "proc/self",
		"internal", "metadata", "169.254", "127.0.0.1", "localhost",
		// Response/output evidence
		"response:", "output:", "result:", "HTTP/",
		"200 ok", "302 found", "401 unauthorized",
		// Auth/session indicators
		"bearer ", "jwt", "session_id", "auth_token", "access_token",
		"set-cookie", "authorization:",
		// PII evidence
		"@", "email", "phone", "address", "name:",
		"user_id", "account", "profile",
		// Timing/blind evidence
		"sleep(", "delay", "benchmark", "elapsed", "seconds",
		"time-based", "response time",
		// Callback evidence
		"callback", "dns query", "http request received", "burp collaborator",
		"interact.sh", "oast", "webhook",
	}
	for _, ind := range impactIndicators {
		if strings.Contains(lowerProof, ind) {
			return true
		}
	}

	// If proof references concrete impact in the description
	impactPhrases := []string{"account takeover", "data breach", "privilege escalation",
		"arbitrary code", "remote execution", "unauthorized access",
		"sensitive data", "personal information", "financial", "payment",
		"credential", "authentication bypass", "session hijack"}
	for _, phrase := range impactPhrases {
		if strings.Contains(combined, phrase) {
			return true
		}
	}

	// If proof is substantial (>150 chars) and contains URLs or structured data, likely real
	if len(proof) > 150 && (strings.Contains(lowerProof, "http") || strings.Contains(lowerProof, "{") || strings.Contains(lowerProof, "<")) {
		return true
	}

	return false
}

func formatValidMethods() string {
	methods := make([]string, 0, len(validVerificationMethods))
	for m := range validVerificationMethods {
		methods = append(methods, m)
	}
	return strings.Join(methods, ", ")
}

// GetVulnerabilities returns all reported vulnerabilities.
func GetVulnerabilities() []Vulnerability {
	vulnMu.RLock()
	defer vulnMu.RUnlock()
	// Return a copy to avoid data races on the caller's side
	result := make([]Vulnerability, len(vulnerabilities))
	copy(result, vulnerabilities)
	return result
}

// ResetVulnerabilities clears the vulnerability list (called at scan start).
func ResetVulnerabilities() {
	vulnMu.Lock()
	defer vulnMu.Unlock()
	vulnerabilities = nil
}

// GetVulnsJSON returns vulnerabilities as JSON.
func GetVulnsJSON() string {
	vulnMu.RLock()
	defer vulnMu.RUnlock()
	data, err := json.Marshal(vulnerabilities)
	if err != nil {
		return fmt.Sprintf(`{"error": "failed to marshal vulnerabilities: %s"}`, err.Error())
	}
	return string(data)
}

// severityRank maps severity strings to numeric levels for comparison.
var severityRank = map[string]int{
	"none": 0, "info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4,
}

// severityFromCVSS returns the HackerOne-standard severity label for a CVSS 3.1 score.
// Critical: 9.0-10.0, High: 7.0-8.9, Medium: 4.0-6.9, Low: 0.1-3.9, None/Info: 0.0
func severityFromCVSS(cvss float64) string {
	switch {
	case cvss >= 9.0:
		return "critical"
	case cvss >= 7.0:
		return "high"
	case cvss >= 4.0:
		return "medium"
	case cvss > 0:
		return "low"
	default:
		return "info"
	}
}

// classifySeverity enforces maximum severity caps based on vulnerability type.
// Returns the (possibly capped) severity and a reason if it was changed.
func classifySeverity(title, description, severity, proof string) (string, string) {
	rank, ok := severityRank[severity]
	if !ok || rank <= 1 {
		return severity, "" // info/low — no need to cap further
	}

	lower := strings.ToLower(title + " " + description)
	lowerProof := strings.ToLower(proof)

	// ── INFO-only findings (max severity: info) ──
	infoOnlyPatterns := []struct {
		keywords []string
		reason   string
	}{
		{[]string{"missing header", "security header", "x-frame-options missing", "csp missing", 
			"hsts missing", "x-content-type missing", "referrer-policy missing", 
			"permissions-policy missing", "x-xss-protection missing"},
			"Missing security headers are informational — not directly exploitable"},
		{[]string{"version disclosure", "server version", "software version", "banner grabbing",
			"x-powered-by", "server header disclosure", "technology detected"},
			"Version/technology disclosure is informational unless tied to a specific exploited CVE"},
		{[]string{"directory listing", "directory index", "index of /"},
			"Directory listing is informational unless sensitive files are exposed and accessed"},
		{[]string{"self-xss", "self xss"},
			"Self-XSS only affects the user's own session — not exploitable against others"},
		{[]string{"debug mode", "debug enabled", "stack trace exposed", "verbose error"},
			"Debug/error disclosure is informational unless it leaks credentials or enables further exploitation"},
		{[]string{"robots.txt", "sitemap.xml", "crossdomain.xml"},
			"Configuration file disclosure is informational"},
		{[]string{"ssl weak", "tls weak", "weak cipher", "tls 1.0", "tls 1.1", "ssl certificate"},
			"SSL/TLS configuration issues are informational — not directly exploitable in practice"},
		{[]string{"email disclosure", "email address found", "email harvesting"},
			"Email disclosure is informational"},
		{[]string{"dns zone transfer", "zone transfer"},
			"DNS zone transfer is informational in most contexts"},
		{[]string{"writekey", "write_key", "write key", "analytics key", "segment key", "analytics api key"},
			"Analytics writeKeys are public client-side tokens — not a security vulnerability"},
		{[]string{"rate limit", "rate-limit", "no rate limit", "brute force", "account lockout", "missing rate limit"},
			"Missing rate limiting is informational — most bug bounty programs exclude this"},
		{[]string{"sentry dsn", "ingest.sentry.io", "sentry.io/api"},
			"Sentry DSN is a public client-side key — not a vulnerability"},
		{[]string{"public_env", "next_public_", "react_app_", "window.__singletons"},
			"Client-side environment variables (PUBLIC_ENV, NEXT_PUBLIC_*) are public by design"},
	}

	for _, p := range infoOnlyPatterns {
		for _, kw := range p.keywords {
			if strings.Contains(lower, kw) {
				return "info", p.reason
			}
		}
	}

	// ── LOW-cap findings (max severity: low) — HackerOne standard ──
	lowCapPatterns := []struct {
		keywords  []string
		exception func() bool
		reason    string
	}{
		{[]string{"cors", "cross-origin resource sharing"},
			func() bool {
				// Exception: CORS + credential theft proof = allow higher severity
				theftKeywords := []string{"cookie", "token", "steal", "exfiltrate", "xmlhttprequest", "fetch(", "document.cookie"}
				for _, tk := range theftKeywords {
					if strings.Contains(lowerProof, tk) {
						return true
					}
				}
				return false
			},
			"CORS alone is low severity (CVSS 2.0-3.9) — needs proven cookie/token theft for higher"},
		{[]string{"clickjacking", "click jacking", "ui redressing"},
			nil,
			"Clickjacking is low severity (CVSS 2.0-3.9) per HackerOne — limited real-world impact"},
		{[]string{"cookie without httponly", "cookie missing httponly", "cookie flag", "cookie attribute", "missing secure flag"},
			nil,
			"Missing cookie flags alone are low severity (CVSS 2.0-3.9)"},
		{[]string{"path disclosure", "full path", "internal path"},
			nil,
			"Internal path disclosure is low severity (CVSS 2.0-3.9)"},
		// Open redirect: HackerOne treats standalone open redirects as LOW
		{[]string{"open redirect", "url redirect", "unvalidated redirect"},
			func() bool {
				// Exception: redirect chained with OAuth/token theft = allow higher
				chainKeywords := []string{"oauth", "token", "ssrf", "chain", "steal", "authorization_code", "code="}
				for _, ck := range chainKeywords {
					if strings.Contains(lowerProof, ck) || strings.Contains(lower, ck) {
						return true
					}
				}
				return false
			},
			"Open redirect is low severity (CVSS 2.0-3.9) per HackerOne — needs OAuth/token chain for higher"},
		// CRLF: HackerOne treats as low unless chained
		{[]string{"crlf injection", "http response splitting"},
			func() bool {
				chainKeywords := []string{"cache poison", "xss", "session fixation", "header injection"}
				for _, ck := range chainKeywords {
					if strings.Contains(lowerProof, ck) || strings.Contains(lower, ck) {
						return true
					}
				}
				return false
			},
			"CRLF injection is low severity (CVSS 2.0-3.9) per HackerOne — needs cache poisoning or XSS chain for higher"},
		// Host header injection: low unless chained
		{[]string{"host header injection", "host header"},
			func() bool {
				chainKeywords := []string{"cache poison", "password reset", "email", "inject", "redirect"}
				for _, ck := range chainKeywords {
					if strings.Contains(lowerProof, ck) {
						return true
					}
				}
				return false
			},
			"Host header injection is low severity (CVSS 2.0-3.9) per HackerOne — needs password reset poisoning or cache poisoning chain for higher"},
	}

	for _, p := range lowCapPatterns {
		for _, kw := range p.keywords {
			if strings.Contains(lower, kw) {
				if p.exception != nil && p.exception() {
					continue // exception met, allow higher severity
				}
				if rank > severityRank["low"] {
					return "low", p.reason
				}
			}
		}
	}

	// ── MEDIUM-cap findings (max severity: medium) — HackerOne standard ──
	medCapPatterns := []struct {
		keywords  []string
		exception func() bool
		reason    string
	}{
		{[]string{"reflected xss"},
			func() bool {
				// Exception: Reflected XSS → session hijack/ATO = allow high
				for _, kw := range []string{"account takeover", "session hijack", "cookie stolen", "admin access", "document.cookie"} {
					if strings.Contains(lowerProof, kw) {
						return true
					}
				}
				return false
			},
			"Reflected XSS is medium (CVSS 4.0-6.9) per HackerOne — needs proven session hijack for high"},
		{[]string{"dom xss", "dom-based xss"},
			func() bool {
				for _, kw := range []string{"account takeover", "session hijack", "cookie stolen", "admin access"} {
					if strings.Contains(lowerProof, kw) {
						return true
					}
				}
				return false
			},
			"DOM XSS is medium (CVSS 4.0-6.9) per HackerOne — needs proven session hijack for high"},
		{[]string{"csrf", "cross-site request forgery"},
			func() bool {
				// Exception: CSRF on critical action = allow high
				for _, kw := range []string{"password", "admin", "delete account", "transfer", "payment", "email change", "role change"} {
					if strings.Contains(lower, kw) || strings.Contains(lowerProof, kw) {
						return true
					}
				}
				return false
			},
			"CSRF is medium (CVSS 4.0-6.9) per HackerOne — needs critical action impact (password change, payment) for high"},
		{[]string{"information disclosure", "info disclosure", "sensitive data exposure"},
			func() bool {
				// Exception: PII/credentials leaked = allow high
				for _, kw := range []string{"password", "credential", "api key", "secret", "token", "pii", "ssn", "credit card"} {
					if strings.Contains(lowerProof, kw) {
						return true
					}
				}
				return false
			},
			"Information disclosure is medium (CVSS 4.0-6.9) per HackerOne — needs PII/credential exposure for high"},
	}

	for _, p := range medCapPatterns {
		for _, kw := range p.keywords {
			if strings.Contains(lower, kw) {
				if p.exception != nil && p.exception() {
					continue // exception met, allow higher severity
				}
				if rank > severityRank["medium"] {
					return "medium", p.reason
				}
			}
		}
	}

	// ── HIGH-cap findings (max severity: high) — HackerOne standard ──
	highCapPatterns := []struct {
		keywords  []string
		exception func() bool
		reason    string
	}{
		// Stored XSS: High on HackerOne unless it leads to mass ATO/RCE
		{[]string{"stored xss", "persistent xss"},
			func() bool {
				for _, kw := range []string{"admin", "rce", "mass", "worm", "all users", "account takeover"} {
					if strings.Contains(lowerProof, kw) {
						return true
					}
				}
				return false
			},
			"Stored XSS is high (CVSS 7.0-8.9) per HackerOne — needs admin access/mass ATO/RCE chain for critical"},
		// SSRF: High on HackerOne unless full internal access/cloud metadata
		{[]string{"ssrf", "server-side request forgery", "server side request forgery"},
			func() bool {
				for _, kw := range []string{"aws", "metadata", "169.254", "cloud", "credentials", "rce", "internal network", "full access"} {
					if strings.Contains(lowerProof, kw) {
						return true
					}
				}
				return false
			},
			"SSRF is high (CVSS 7.0-8.9) per HackerOne — needs cloud metadata/credential exposure or RCE for critical"},
		// IDOR: High on HackerOne unless mass data exposure
		{[]string{"idor", "insecure direct object"},
			func() bool {
				for _, kw := range []string{"all users", "mass", "database dump", "admin access", "full", "account takeover"} {
					if strings.Contains(lowerProof, kw) {
						return true
					}
				}
				return false
			},
			"IDOR is high (CVSS 7.0-8.9) per HackerOne — needs mass data dump or admin access for critical"},
		// File Inclusion: High unless RCE demonstrated
		{[]string{"file inclusion", "lfi", "local file inclusion", "path traversal", "directory traversal"},
			func() bool {
				for _, kw := range []string{"rce", "remote code", "shell", "/etc/shadow", "proc/self", "command execution"} {
					if strings.Contains(lowerProof, kw) {
						return true
					}
				}
				return false
			},
			"File inclusion is high (CVSS 7.0-8.9) per HackerOne — needs RCE or shadow file access for critical"},
		// Auth Bypass: High unless full admin access
		{[]string{"authentication bypass", "auth bypass", "login bypass"},
			func() bool {
				for _, kw := range []string{"admin", "root", "superuser", "full access", "all accounts"} {
					if strings.Contains(lowerProof, kw) {
						return true
					}
				}
				return false
			},
			"Auth bypass is high (CVSS 7.0-8.9) per HackerOne — needs admin/root access for critical"},
	}

	for _, p := range highCapPatterns {
		for _, kw := range p.keywords {
			if strings.Contains(lower, kw) {
				if p.exception != nil && p.exception() {
					continue // exception met, allow critical
				}
				if rank > severityRank["high"] {
					return "high", p.reason
				}
			}
		}
	}

	return severity, "" // no cap needed
}

// extractVulnType extracts a canonical vulnerability type from title/description
// for deduplication purposes. Returns empty string if type can't be determined.
func extractVulnType(title, description string) string {
	lower := strings.ToLower(title + " " + description)

	vulnTypes := []struct {
		typeName string
		keywords []string
	}{
		{"xss", []string{"xss", "cross-site scripting", "cross site scripting", "reflected xss", "stored xss", "dom xss", "script injection"}},
		{"sqli", []string{"sql injection", "sqli", "sql inject", "blind sql", "union select", "error-based sql"}},
		{"ssrf", []string{"ssrf", "server-side request forgery", "server side request forgery"}},
		{"idor", []string{"idor", "insecure direct object", "broken access control", "unauthorized access"}},
		{"lfi", []string{"local file inclusion", "lfi", "file inclusion", "path traversal", "directory traversal", "path disclosure", "physical path"}},
		{"rfi", []string{"remote file inclusion", "rfi"}},
		{"rce", []string{"remote code execution", "rce", "command injection", "os command", "code execution"}},
		{"csrf", []string{"csrf", "cross-site request forgery", "cross site request forgery"}},
		{"xxe", []string{"xxe", "xml external entity"}},
		{"open_redirect", []string{"open redirect", "url redirect", "unvalidated redirect"}},
		{"auth_bypass", []string{"authentication bypass", "auth bypass", "login bypass", "auth flow"}},
		{"info_disclosure", []string{"information disclosure", "info disclosure", "sensitive data exposure", "data leak", "api key", "credential leak", "password leak", "exposed secret", "token leak", "verbose error"}},
		{"missing_header", []string{"missing header", "security header", "x-frame-options", "content-security-policy", "hsts", "x-content-type"}},
		{"version_disclosure", []string{"version disclosure", "server header", "x-powered-by", "technology disclosure", "fingerprint"}},
		{"subdomain_takeover", []string{"subdomain takeover", "dangling dns", "unclaimed subdomain"}},
		{"clickjacking", []string{"clickjacking", "ui redressing"}},
		{"cors", []string{"cors", "cross-origin resource sharing", "cross origin"}},
		{"crlf", []string{"crlf injection", "http response splitting"}},
		{"ssti", []string{"ssti", "server-side template injection", "template injection"}},
		{"deserialization", []string{"deserialization", "insecure deserialization", "object injection"}},
	}

	for _, vt := range vulnTypes {
		for _, kw := range vt.keywords {
			if strings.Contains(lower, kw) {
				return vt.typeName
			}
		}
	}
	return ""
}

// normalizeEndpoint strips query params, fragments, and trailing slashes
// so "/api/search?q=test" and "/api/search?q=foo" match as the same endpoint.
func normalizeEndpoint(endpoint string) string {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return ""
	}

	// Strip query parameters
	if idx := strings.Index(endpoint, "?"); idx >= 0 {
		endpoint = endpoint[:idx]
	}
	// Strip fragment
	if idx := strings.Index(endpoint, "#"); idx >= 0 {
		endpoint = endpoint[:idx]
	}
	// Strip trailing slashes
	endpoint = strings.TrimRight(endpoint, "/")
	// Lowercase for consistent comparison
	return strings.ToLower(endpoint)
}
