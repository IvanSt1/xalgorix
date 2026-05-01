package mcp

import (
	"encoding/json"
	"os"
	"reflect"
	"sort"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/tools"
)

func TestParamsFromSchema(t *testing.T) {
	schema := json.RawMessage(`{
      "type": "object",
      "properties": {
        "url": {"type": "string", "description": "target url"},
        "level": {"type": "integer", "description": "detection level"}
      },
      "required": ["url"]
    }`)
	got := paramsFromSchema(schema)
	sort.Slice(got, func(i, j int) bool { return got[i].Name < got[j].Name })
	want := []tools.Parameter{
		{Name: "level", Description: "detection level", Required: false},
		{Name: "url", Description: "target url", Required: true},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("paramsFromSchema mismatch\ngot:  %+v\nwant: %+v", got, want)
	}
}

func TestParamsFromSchemaHandlesEmpty(t *testing.T) {
	if got := paramsFromSchema(nil); got != nil {
		t.Fatalf("expected nil on empty schema, got %+v", got)
	}
	if got := paramsFromSchema(json.RawMessage(`{"type":"object"}`)); len(got) != 0 {
		t.Fatalf("expected empty on schema with no properties, got %+v", got)
	}
}

func TestSanitize(t *testing.T) {
	cases := map[string]string{
		"kali-mcp":   "kali_mcp",
		"a/b.c":      "a_b_c",
		"hex strike": "hex_strike",
		"ok_name1":   "ok_name1",
	}
	for in, want := range cases {
		if got := sanitize(in); got != want {
			t.Fatalf("sanitize(%q) = %q; want %q", in, got, want)
		}
	}
}

func TestSplitCommand(t *testing.T) {
	if got := splitCommand("  python3  -m  my_mcp  "); !reflect.DeepEqual(got, []string{"python3", "-m", "my_mcp"}) {
		t.Fatalf("splitCommand: %+v", got)
	}
	if got := splitCommand(""); len(got) != 0 {
		t.Fatalf("splitCommand empty: %+v", got)
	}
}

func TestRegisterNoopWhenEnvUnset(t *testing.T) {
	os.Unsetenv("XALGORIX_MCP_SERVERS")
	reg := tools.NewRegistry()
	if got := Register(reg); got != nil {
		t.Fatalf("expected nil client list when env unset, got %d", len(got))
	}
	if got := len(reg.List()); got != 0 {
		t.Fatalf("expected 0 tools, got %d", got)
	}
}

func TestRegisterSkipsMalformedEntries(t *testing.T) {
	t.Setenv("XALGORIX_MCP_SERVERS", "notanentry;;good=nonexistent-bin-xyz-12345")
	reg := tools.NewRegistry()
	// good= targets a nonexistent binary, so NewClient should fail; we just
	// want to confirm Register doesn't panic and returns nil clients.
	clients := Register(reg)
	if len(clients) != 0 {
		for _, c := range clients {
			_ = c.Close()
		}
		t.Fatalf("expected 0 clients (nonexistent bin), got %d", len(clients))
	}
}
