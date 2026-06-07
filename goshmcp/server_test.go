package goshmcp

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"
)

func TestHandleToolCallEcho(t *testing.T) {
	srv := NewServer()
	res, err := srv.HandleToolCall(context.Background(), ToolName, json.RawMessage(`{"script":"echo hi"}`))
	if err != nil {
		t.Fatalf("HandleToolCall returned error: %v", err)
	}
	text := onlyText(t, res)
	if !strings.Contains(text, "hi\n") || !strings.Contains(text, "exitCode: 0") {
		t.Fatalf("result text = %q, want stdout hi and exitCode 0", text)
	}
}

func TestHandleToolCallFailingScript(t *testing.T) {
	srv := NewServer()
	res, err := srv.HandleToolCall(context.Background(), ToolName, json.RawMessage(`{"script":"false"}`))
	if err != nil {
		t.Fatalf("HandleToolCall returned error: %v", err)
	}
	text := onlyText(t, res)
	if !strings.Contains(text, "exitCode: 1") {
		t.Fatalf("result text = %q, want non-zero exitCode", text)
	}
}

func TestHandleToolCallStdin(t *testing.T) {
	srv := NewServer()
	res, err := srv.HandleToolCall(context.Background(), ToolName, json.RawMessage(`{"script":"cat","stdin":"from stdin\n"}`))
	if err != nil {
		t.Fatalf("HandleToolCall returned error: %v", err)
	}
	text := onlyText(t, res)
	if !strings.Contains(text, "from stdin\n") || !strings.Contains(text, "exitCode: 0") {
		t.Fatalf("result text = %q, want stdin echoed", text)
	}
}

func TestHandleToolCallNetworkDeniedByDefault(t *testing.T) {
	srv := NewServer()
	res, err := srv.HandleToolCall(context.Background(), ToolName, json.RawMessage(`{"script":"curl http://example.invalid"}`))
	if err != nil {
		t.Fatalf("HandleToolCall returned error: %v", err)
	}
	text := onlyText(t, res)
	if !strings.Contains(text, "exitCode: 127") || !strings.Contains(text, "curl: command not found") {
		t.Fatalf("result text = %q, want denied network failure", text)
	}
}

func TestServeStdioRoundTrip(t *testing.T) {
	srv := NewServer()
	requests := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"bash","arguments":{"script":"echo hello"}}}`,
		"",
	}, "\n")

	reader, writer := io.Pipe()
	done := make(chan error, 1)
	go func() {
		done <- srv.ServeStdio(context.Background(), strings.NewReader(requests), writer)
		_ = writer.Close()
	}()

	var responses []map[string]any
	scan := bufio.NewScanner(reader)
	for scan.Scan() {
		var resp map[string]any
		if err := json.Unmarshal(scan.Bytes(), &resp); err != nil {
			t.Fatalf("response is not JSON: %v", err)
		}
		responses = append(responses, resp)
	}
	if err := scan.Err(); err != nil {
		t.Fatalf("reading responses: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatalf("ServeStdio returned error: %v", err)
	}
	if len(responses) != 3 {
		t.Fatalf("got %d responses, want 3: %#v", len(responses), responses)
	}

	listResult := responses[1]["result"].(map[string]any)
	tools := listResult["tools"].([]any)
	if tools[0].(map[string]any)["name"] != ToolName {
		t.Fatalf("tools/list response = %#v, want bash tool", listResult)
	}

	callResult := responses[2]["result"].(map[string]any)
	content := callResult["content"].([]any)
	text := content[0].(map[string]any)["text"].(string)
	if !strings.Contains(text, "hello\n") || !strings.Contains(text, "exitCode: 0") {
		t.Fatalf("tools/call text = %q, want hello and exitCode 0", text)
	}
}

func onlyText(t *testing.T, res ToolCallResult) string {
	t.Helper()
	if len(res.Content) != 1 || res.Content[0].Type != "text" {
		t.Fatalf("content = %#v, want one text item", res.Content)
	}
	return res.Content[0].Text
}
