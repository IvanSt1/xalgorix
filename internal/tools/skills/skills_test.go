package skills

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/tools"
)

// setupTestSkills creates a temporary skills directory with test files.
func setupTestSkills(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()

	// Create category directories
	categories := []string{"vulnerabilities", "protocols", "frameworks"}
	for _, cat := range categories {
		os.MkdirAll(filepath.Join(dir, cat), 0755)
	}

	// Create test skill files in new directory/SKILL.md format
	files := map[string]string{
		"vulnerabilities/sql_injection/SKILL.md": "# SQL Injection\nTest payloads...",
		"vulnerabilities/xss/SKILL.md":           "# XSS\nReflected payloads...",
		"protocols/graphql/SKILL.md":             "# GraphQL\nIntrospection...",
		"frameworks/django/SKILL.md":             "# Django\nDebug mode...",
	}
	for path, content := range files {
		os.MkdirAll(filepath.Join(dir, filepath.Dir(path)), 0755)
		os.WriteFile(filepath.Join(dir, path), []byte(content), 0644)
	}

	return dir
}

// makeFn returns a fully-wired read_skill executor for tests.
func makeFn(dir string) func(map[string]string) (tools.Result, error) {
	fsys := os.DirFS(dir)
	return makeReadSkill(fsys, makeListSkills(fsys))
}

func TestReadSkill_Basic(t *testing.T) {
	dir := setupTestSkills(t)
	reg := tools.NewRegistry()
	Register(reg, "")

	fn := makeFn(dir)

	// Read existing skill
	result, err := fn(map[string]string{"name": "sql_injection"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(result.Output, "SQL Injection") {
		t.Errorf("expected SQL Injection content, got: %s", result.Output)
	}
}

func TestReadSkill_WithExtension(t *testing.T) {
	dir := setupTestSkills(t)
	fn := makeFn(dir)

	// Should work with .md extension too
	result, err := fn(map[string]string{"name": "sql_injection.md"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(result.Output, "SQL Injection") {
		t.Errorf("expected SQL Injection content, got: %s", result.Output)
	}
}

func TestReadSkill_DifferentCategory(t *testing.T) {
	dir := setupTestSkills(t)
	fn := makeFn(dir)

	result, err := fn(map[string]string{"name": "graphql", "category": "protocols"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(result.Output, "GraphQL") {
		t.Errorf("expected GraphQL content, got: %s", result.Output)
	}
}

func TestReadSkill_NotFound(t *testing.T) {
	dir := setupTestSkills(t)
	fn := makeFn(dir)

	result, _ := fn(map[string]string{"name": "nonexistent_skill"})
	if result.Error == "" {
		t.Error("expected error for nonexistent skill")
	}
	if !strings.Contains(result.Error, "skill not found") {
		t.Errorf("expected 'skill not found' error, got: %s", result.Error)
	}
}

// TestReadSkill_EmptyName verifies the loop-breaking fallback: when the
// LLM emits read_skill with no name, the tool returns the catalogue plus
// a corrective hint instead of erroring (the old behaviour caused some
// models to issue dozens of identical empty calls in a row).
func TestReadSkill_EmptyName(t *testing.T) {
	dir := setupTestSkills(t)
	fn := makeFn(dir)

	result, err := fn(map[string]string{"name": ""})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Error != "" {
		t.Errorf("empty-name should not be a hard error any more, got: %s", result.Error)
	}
	if !strings.Contains(result.Output, "called without `name`") {
		t.Errorf("expected corrective hint in output, got: %s", result.Output)
	}
	if !strings.Contains(result.Output, "sql_injection") {
		t.Errorf("expected catalogue contents in output, got: %s", result.Output)
	}
}

func TestReadSkill_PathTraversal(t *testing.T) {
	dir := setupTestSkills(t)
	fn := makeFn(dir)

	// Attempt path traversal
	traversalInputs := []string{
		"../../etc/passwd",
		"../../../etc/shadow",
		"../secrets",
		"..%2F..%2Fetc%2Fpasswd",
	}
	for _, input := range traversalInputs {
		result, _ := fn(map[string]string{"name": input})
		if result.Output != "" && strings.Contains(result.Output, "root:") {
			t.Errorf("path traversal succeeded with input: %s", input)
		}
	}
}

func TestReadSkill_CrossCategorySearch(t *testing.T) {
	dir := setupTestSkills(t)
	fn := makeFn(dir)

	// Request skill from protocols category without specifying category
	// (defaults to vulnerabilities, then searches all categories)
	result, _ := fn(map[string]string{"name": "graphql"})
	if !strings.Contains(result.Output, "GraphQL") {
		t.Errorf("cross-category search should find graphql in protocols, got: %s", result.Output)
	}
}

func TestListSkills_All(t *testing.T) {
	dir := setupTestSkills(t)
	fn := makeListSkills(os.DirFS(dir))

	result, err := fn(map[string]string{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should list all skills across categories
	if !strings.Contains(result.Output, "sql_injection") {
		t.Error("expected sql_injection in output")
	}
	if !strings.Contains(result.Output, "graphql") {
		t.Error("expected graphql in output")
	}
	if !strings.Contains(result.Output, "django") {
		t.Error("expected django in output")
	}
	if !strings.Contains(result.Output, "Total: 4 skills") {
		t.Errorf("expected total of 4 skills, got: %s", result.Output)
	}
}

func TestListSkills_FilterCategory(t *testing.T) {
	dir := setupTestSkills(t)
	fn := makeListSkills(os.DirFS(dir))

	result, err := fn(map[string]string{"category": "protocols"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(result.Output, "graphql") {
		t.Error("expected graphql in protocols output")
	}
	if strings.Contains(result.Output, "sql_injection") {
		t.Error("should NOT contain sql_injection when filtering protocols")
	}
}

func TestListSkills_EmptyCategory(t *testing.T) {
	dir := setupTestSkills(t)
	fn := makeListSkills(os.DirFS(dir))

	result, _ := fn(map[string]string{"category": "nonexistent"})
	if !strings.Contains(result.Output, "Total: 0 skills") {
		t.Errorf("expected 0 skills for nonexistent category, got: %s", result.Output)
	}
}
