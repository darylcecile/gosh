package goshmcp

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/darylcecile/gosh"
	"github.com/darylcecile/gosh/std"
)

const (
	// ToolName is the MCP tool name exposed by this package.
	ToolName = "bash"

	toolDescription = "Execute a Bash script inside a secure in-memory sandbox (no host filesystem or process access; network deny-by-default)."
)

// Option configures a Server.
type Option func(*Server)

// WithShellOptions appends base gosh options used whenever the server builds a
// sandbox for a tool call. Use this for limits, seed files, environment,
// network policy, custom commands, or a custom filesystem.
func WithShellOptions(opts ...gosh.Option) Option {
	return func(s *Server) {
		s.shellOptions = append(s.shellOptions, opts...)
	}
}

// WithPersistentFS controls whether tool calls reuse one gosh Shell and its
// virtual filesystem. The default is false: each tool call gets a fresh Shell.
func WithPersistentFS(persistent bool) Option {
	return func(s *Server) {
		s.persistentFS = persistent
	}
}

// Server adapts gosh to MCP tools and JSON-RPC transports.
type Server struct {
	mu              sync.Mutex
	shellOptions    []gosh.Option
	persistentFS    bool
	persistentShell *gosh.Shell
}

// NewServer constructs a Server. By default every call receives a fresh gosh
// sandbox with the standard command set and deny-by-default network policy.
func NewServer(opts ...Option) *Server {
	s := &Server{}
	for _, opt := range opts {
		opt(s)
	}
	if s.persistentFS {
		s.persistentShell = s.newShell()
	}
	return s
}

// ToolContent is an MCP text content item.
type ToolContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// ToolCallResult is the MCP-compatible result returned by HandleToolCall and
// tools/call. IsError marks tool-level failures without turning them into
// JSON-RPC protocol errors.
type ToolCallResult struct {
	Content []ToolContent `json:"content"`
	IsError bool          `json:"isError,omitempty"`
}

type bashArgs struct {
	Script *string  `json:"script"`
	Stdin  string   `json:"stdin,omitempty"`
	Cwd    string   `json:"cwd,omitempty"`
	Args   []string `json:"args,omitempty"`
}

// HandleToolCall executes a supported MCP tool independent of any transport.
// Script exits, including non-zero statuses, are returned as tool results. Bad
// tool names or malformed arguments are returned as Go errors.
func (s *Server) HandleToolCall(ctx context.Context, name string, args json.RawMessage) (ToolCallResult, error) {
	if name != ToolName {
		return ToolCallResult{}, fmt.Errorf("unknown tool %q", name)
	}

	var in bashArgs
	if len(args) == 0 || string(args) == "null" {
		return ToolCallResult{}, errors.New("missing arguments")
	}
	if err := json.Unmarshal(args, &in); err != nil {
		return ToolCallResult{}, fmt.Errorf("invalid arguments: %w", err)
	}
	if in.Script == nil || *in.Script == "" {
		return ToolCallResult{}, errors.New("script is required")
	}

	runOpts := []gosh.RunOption{gosh.RunStdin(in.Stdin)}
	if in.Cwd != "" {
		runOpts = append(runOpts, gosh.RunCwd(in.Cwd))
	}
	if len(in.Args) > 0 {
		runOpts = append(runOpts, gosh.RunArgs(in.Args...))
	}

	sh := s.shellForCall()
	res, err := sh.Run(ctx, *in.Script, runOpts...)
	text := formatRunResult(res, err)
	return ToolCallResult{
		Content: []ToolContent{{Type: "text", Text: text}},
		IsError: err != nil,
	}, nil
}

func (s *Server) shellForCall() *gosh.Shell {
	if !s.persistentFS {
		return s.newShell()
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.persistentShell == nil {
		s.persistentShell = s.newShell()
	}
	return s.persistentShell
}

func (s *Server) newShell() *gosh.Shell {
	opts := append([]gosh.Option(nil), s.shellOptions...)
	return std.Shell(opts...)
}

func formatRunResult(res gosh.Result, hostErr error) string {
	var b strings.Builder
	fmt.Fprintf(&b, "exitCode: %d\n", res.ExitCode)
	if res.Stdout != "" {
		b.WriteString("stdout:\n")
		b.WriteString(res.Stdout)
		if !strings.HasSuffix(res.Stdout, "\n") {
			b.WriteByte('\n')
		}
	} else {
		b.WriteString("stdout: \n")
	}
	if res.Stderr != "" {
		b.WriteString("stderr:\n")
		b.WriteString(res.Stderr)
		if !strings.HasSuffix(res.Stderr, "\n") {
			b.WriteByte('\n')
		}
	} else {
		b.WriteString("stderr: \n")
	}
	if hostErr != nil {
		fmt.Fprintf(&b, "error: %v\n", hostErr)
	}
	return b.String()
}

// ServeStdio serves a minimal MCP JSON-RPC 2.0 endpoint over newline-delimited
// JSON. Each inbound request or notification must be a single JSON object ending
// in '\n'; each response is written as one JSON object ending in '\n'.
func (s *Server) ServeStdio(ctx context.Context, in io.Reader, out io.Writer) error {
	if ctx == nil {
		ctx = context.Background()
	}

	scanner := bufio.NewScanner(in)
	scanner.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	enc := json.NewEncoder(out)
	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		var req rpcRequest
		if err := json.Unmarshal([]byte(line), &req); err != nil {
			if err := enc.Encode(errorResponse(nil, -32700, "parse error")); err != nil {
				return err
			}
			continue
		}
		if req.ID == nil {
			continue
		}

		resp := s.handleRPC(ctx, req)
		if err := enc.Encode(resp); err != nil {
			return err
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	return nil
}

type rpcRequest struct {
	JSONRPC string           `json:"jsonrpc"`
	ID      *json.RawMessage `json:"id,omitempty"`
	Method  string           `json:"method"`
	Params  json.RawMessage  `json:"params,omitempty"`
}

type rpcResponse struct {
	JSONRPC string           `json:"jsonrpc"`
	ID      *json.RawMessage `json:"id"`
	Result  any              `json:"result,omitempty"`
	Error   *rpcError        `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (s *Server) handleRPC(ctx context.Context, req rpcRequest) rpcResponse {
	if req.JSONRPC != "2.0" || req.Method == "" {
		return errorResponse(req.ID, -32600, "invalid request")
	}

	switch req.Method {
	case "initialize":
		return successResponse(req.ID, map[string]any{
			"protocolVersion": "2024-11-05",
			"serverInfo": map[string]any{
				"name":    "goshmcp",
				"version": "0.1.0",
			},
			"capabilities": map[string]any{
				"tools": map[string]any{},
			},
		})
	case "ping":
		return successResponse(req.ID, map[string]any{})
	case "tools/list":
		return successResponse(req.ID, map[string]any{
			"tools": []any{bashTool()},
		})
	case "tools/call":
		var params struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		}
		if err := json.Unmarshal(req.Params, &params); err != nil {
			return errorResponse(req.ID, -32602, "invalid params")
		}
		result, err := s.HandleToolCall(ctx, params.Name, params.Arguments)
		if err != nil {
			return errorResponse(req.ID, -32602, err.Error())
		}
		return successResponse(req.ID, result)
	default:
		return errorResponse(req.ID, -32601, "method not found")
	}
}

func successResponse(id *json.RawMessage, result any) rpcResponse {
	return rpcResponse{JSONRPC: "2.0", ID: id, Result: result}
}

func errorResponse(id *json.RawMessage, code int, message string) rpcResponse {
	return rpcResponse{JSONRPC: "2.0", ID: id, Error: &rpcError{Code: code, Message: message}}
}

func bashTool() map[string]any {
	return map[string]any{
		"name":        ToolName,
		"description": toolDescription,
		"inputSchema": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"script": map[string]any{"type": "string", "description": "Bash script to execute inside the sandbox."},
				"stdin":  map[string]any{"type": "string", "description": "Optional standard input for the script."},
				"cwd":    map[string]any{"type": "string", "description": "Optional virtual working directory for this run."},
				"args":   map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "Optional positional arguments for the script."},
			},
			"required":             []string{"script"},
			"additionalProperties": false,
		},
	}
}
