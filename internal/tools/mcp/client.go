// Package mcp is a minimal, opt-in Model Context Protocol adapter.
//
// Scope — point-MCP, not a rewrite. This file wraps external MCP stdio
// servers as regular `tools.Tool` entries so the existing llm.ParseToolCalls
// pipeline keeps working untouched. It intentionally skips the parts of
// the MCP spec that xalgorix does not need yet (resources, prompts,
// sampling, notifications other than responses).
//
// Opt-in. Nothing happens unless the operator exports
//
//	XALGORIX_MCP_SERVERS="name1=cmd1 arg1 arg2;name2=cmd2 ..."
//
// Each entry spawns a subprocess, negotiates an MCP session over stdio
// using JSON-RPC 2.0, lists the tools the server exposes, and registers
// each one as `mcp_<server>_<tool>`. The tool description is copied
// verbatim from the MCP server so the LLM sees the schema the server
// author wrote.
//
// Design choices:
//   - Synchronous request/response. The MCP spec allows async streaming,
//     but for pentesting tools (sqlmap-mcp, kali-mcp, hexstrike) the
//     whole point is to get stdout back and hand it to the LLM.
//   - One goroutine per server reading stdout; responses are matched by
//     JSON-RPC id via a small in-memory map.
//   - Per-server timeout on individual calls (default 5 minutes).
//   - Graceful shutdown on Close() — kills the subprocess and drains
//     pending callers with a context-cancelled error.
package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/tools"
)

const (
	protocolVersion = "2024-11-05"
	defaultTimeout  = 5 * time.Minute
)

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

// Client holds a single MCP stdio subprocess.
type Client struct {
	name    string
	cmd     *exec.Cmd
	stdin   io.WriteCloser
	timeout time.Duration

	mu       sync.Mutex
	pending  map[int64]chan rpcResponse
	nextID   atomic.Int64
	closed   atomic.Bool
	closeErr error
}

// rpcRequest / rpcResponse mirror the JSON-RPC 2.0 envelope MCP uses.
type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      int64           `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      int64           `json:"id"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (e *rpcError) Error() string { return fmt.Sprintf("mcp[%d]: %s", e.Code, e.Message) }

// NewClient spawns the configured command and performs the MCP handshake.
func NewClient(name, command string, timeout time.Duration) (*Client, error) {
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	parts := splitCommand(command)
	if len(parts) == 0 {
		return nil, fmt.Errorf("mcp: empty command for server %q", name)
	}

	cmd := exec.Command(parts[0], parts[1:]...)
	cmd.Stderr = os.Stderr
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("mcp[%s]: stdin pipe: %w", name, err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("mcp[%s]: stdout pipe: %w", name, err)
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("mcp[%s]: start: %w", name, err)
	}

	c := &Client{
		name:    name,
		cmd:     cmd,
		stdin:   stdin,
		timeout: timeout,
		pending: make(map[int64]chan rpcResponse),
	}
	go c.readLoop(stdout)
	if err := c.handshake(); err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("mcp[%s]: handshake: %w", name, err)
	}
	return c, nil
}

func (c *Client) readLoop(r io.Reader) {
	scanner := bufio.NewScanner(r)
	// MCP responses are newline-delimited JSON, and a single tool result
	// can legitimately be hundreds of KB of stdout. Raise the buffer.
	scanner.Buffer(make([]byte, 64*1024), 8*1024*1024)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var resp rpcResponse
		if err := json.Unmarshal(line, &resp); err != nil {
			log.Printf("[mcp %s] non-JSON frame ignored: %s", c.name, truncate(string(line), 200))
			continue
		}
		if resp.ID == 0 {
			// Server-originated notification — we don't handle these yet.
			continue
		}
		c.mu.Lock()
		ch, ok := c.pending[resp.ID]
		delete(c.pending, resp.ID)
		c.mu.Unlock()
		if ok {
			ch <- resp
		}
	}
	if err := scanner.Err(); err != nil && !c.closed.Load() {
		log.Printf("[mcp %s] read loop error: %v", c.name, err)
	}
	// Fail any remaining callers on stream close.
	c.mu.Lock()
	for id, ch := range c.pending {
		close(ch)
		delete(c.pending, id)
	}
	c.mu.Unlock()
}

func (c *Client) call(ctx context.Context, method string, params any) (json.RawMessage, error) {
	if c.closed.Load() {
		return nil, errors.New("mcp: client closed")
	}
	id := c.nextID.Add(1)
	var raw json.RawMessage
	if params != nil {
		b, err := json.Marshal(params)
		if err != nil {
			return nil, fmt.Errorf("marshal params: %w", err)
		}
		raw = b
	}
	req := rpcRequest{JSONRPC: "2.0", ID: id, Method: method, Params: raw}
	payload, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}
	ch := make(chan rpcResponse, 1)
	c.mu.Lock()
	c.pending[id] = ch
	c.mu.Unlock()

	if _, err := c.stdin.Write(append(payload, '\n')); err != nil {
		c.mu.Lock()
		delete(c.pending, id)
		c.mu.Unlock()
		return nil, fmt.Errorf("write stdin: %w", err)
	}

	select {
	case resp, ok := <-ch:
		if !ok {
			return nil, errors.New("mcp: server closed before responding")
		}
		if resp.Error != nil {
			return nil, resp.Error
		}
		return resp.Result, nil
	case <-ctx.Done():
		c.mu.Lock()
		delete(c.pending, id)
		c.mu.Unlock()
		return nil, ctx.Err()
	}
}

func (c *Client) handshake() error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_, err := c.call(ctx, "initialize", map[string]any{
		"protocolVersion": protocolVersion,
		"capabilities":    map[string]any{},
		"clientInfo": map[string]any{
			"name":    "xalgorix",
			"version": "4.x",
		},
	})
	if err != nil {
		return err
	}
	// `notifications/initialized` is a notification, not a request.
	nb, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"method":  "notifications/initialized",
	})
	if _, err := c.stdin.Write(append(nb, '\n')); err != nil {
		return err
	}
	return nil
}

// Close terminates the subprocess.
func (c *Client) Close() error {
	if !c.closed.CompareAndSwap(false, true) {
		return c.closeErr
	}
	if c.stdin != nil {
		_ = c.stdin.Close()
	}
	if c.cmd != nil && c.cmd.Process != nil {
		_ = c.cmd.Process.Kill()
		_, _ = c.cmd.Process.Wait()
	}
	return nil
}

// ---------------------------------------------------------------------------
// Schema / tool discovery
// ---------------------------------------------------------------------------

type toolDescriptor struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"inputSchema"`
}

// listTools returns the tool descriptors reported by the MCP server.
func (c *Client) listTools(ctx context.Context) ([]toolDescriptor, error) {
	raw, err := c.call(ctx, "tools/list", map[string]any{})
	if err != nil {
		return nil, err
	}
	var out struct {
		Tools []toolDescriptor `json:"tools"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("unmarshal tools/list: %w", err)
	}
	return out.Tools, nil
}

// callTool executes one tool. `args` is a map[string]string coming from
// the xalgorix registry; we re-encode to JSON for MCP.
func (c *Client) callTool(ctx context.Context, tool string, args map[string]string) (string, error) {
	jsonArgs := make(map[string]any, len(args))
	for k, v := range args {
		jsonArgs[k] = v
	}
	raw, err := c.call(ctx, "tools/call", map[string]any{
		"name":      tool,
		"arguments": jsonArgs,
	})
	if err != nil {
		return "", err
	}
	var out struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
		IsError bool `json:"isError"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return string(raw), nil // fall back to raw payload
	}
	var b strings.Builder
	for _, part := range out.Content {
		if part.Text != "" {
			b.WriteString(part.Text)
			b.WriteByte('\n')
		}
	}
	text := strings.TrimRight(b.String(), "\n")
	if out.IsError {
		return text, fmt.Errorf("mcp tool returned isError=true")
	}
	return text, nil
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

// Register consumes XALGORIX_MCP_SERVERS and registers every discovered
// MCP tool as an xalgorix Tool under the name `mcp_<server>_<tool>`.
// Returns the list of successfully connected clients so the caller can
// close them on agent shutdown.
func Register(reg *tools.Registry) []*Client {
	spec := os.Getenv("XALGORIX_MCP_SERVERS")
	if strings.TrimSpace(spec) == "" {
		return nil
	}
	var clients []*Client
	for _, server := range strings.Split(spec, ";") {
		server = strings.TrimSpace(server)
		if server == "" {
			continue
		}
		name, command, ok := strings.Cut(server, "=")
		name = strings.TrimSpace(name)
		command = strings.TrimSpace(command)
		if !ok || name == "" || command == "" {
			log.Printf("[mcp] skipping malformed entry %q (want name=command)", server)
			continue
		}
		client, err := NewClient(name, command, defaultTimeout)
		if err != nil {
			log.Printf("[mcp] %s: %v", name, err)
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		descs, err := client.listTools(ctx)
		cancel()
		if err != nil {
			log.Printf("[mcp %s] tools/list failed: %v", name, err)
			_ = client.Close()
			continue
		}
		for _, d := range descs {
			d := d // shadow for closure
			toolName := fmt.Sprintf("mcp_%s_%s", sanitize(name), sanitize(d.Name))
			reg.Register(&tools.Tool{
				Name:        toolName,
				Description: fmt.Sprintf("[MCP %s] %s", name, d.Description),
				Parameters:  paramsFromSchema(d.InputSchema),
				Execute: func(args map[string]string) (tools.Result, error) {
					ctx, cancel := context.WithTimeout(context.Background(), client.timeout)
					defer cancel()
					out, err := client.callTool(ctx, d.Name, args)
					res := tools.Result{Output: out}
					if err != nil {
						res.Error = err.Error()
					}
					res.Metadata = map[string]any{
						"mcp_server": name,
						"mcp_tool":   d.Name,
					}
					return res, nil
				},
			})
		}
		log.Printf("[mcp] %s: registered %d tools", name, len(descs))
		clients = append(clients, client)
	}
	return clients
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// paramsFromSchema turns a JSON Schema (subset MCP actually emits) into
// the flat `tools.Parameter` list xalgorix uses. We keep descriptions
// and `required` markers; typing is advisory for the LLM only.
func paramsFromSchema(schema json.RawMessage) []tools.Parameter {
	if len(schema) == 0 {
		return nil
	}
	var parsed struct {
		Properties map[string]struct {
			Type        any    `json:"type"`
			Description string `json:"description"`
		} `json:"properties"`
		Required []string `json:"required"`
	}
	if err := json.Unmarshal(schema, &parsed); err != nil {
		return nil
	}
	required := make(map[string]bool, len(parsed.Required))
	for _, r := range parsed.Required {
		required[r] = true
	}
	out := make([]tools.Parameter, 0, len(parsed.Properties))
	for name, p := range parsed.Properties {
		out = append(out, tools.Parameter{
			Name:        name,
			Description: p.Description,
			Required:    required[name],
		})
	}
	return out
}

// splitCommand tokenises "bash -c ..." without pulling in a shell.
// Very simple: whitespace-separated, no quoting. Sufficient for MCP
// server specs that look like `uvx kali-mcp-server` or
// `python3 -m my_mcp.server`; users who need quoting can wrap with
// `bash -lc 'foo "bar baz"'`.
func splitCommand(s string) []string {
	return strings.Fields(s)
}

func sanitize(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '_':
			b.WriteRune('_')
		default:
			b.WriteByte('_')
		}
	}
	return b.String()
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
