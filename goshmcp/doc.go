// Package goshmcp exposes gosh as a minimal MCP (Model Context Protocol) tool
// server.
//
// The package is intentionally transport-agnostic at its core: hosts can call
// Server.HandleToolCall directly, or wire Server.ServeStdio to a JSON-RPC 2.0
// stream. ServeStdio uses newline-delimited JSON frames: each request or
// notification is one complete JSON object followed by '\n'. It does not
// implement Content-Length framing.
//
// Example host wiring:
//
// func run(ctx context.Context) error {
// srv := goshmcp.NewServer()
// return srv.ServeStdio(ctx, os.Stdin, os.Stdout)
// }
//
// The exposed MCP tool is named "bash". It executes scripts through the gosh
// interpreter only; no host shell, host filesystem, or host process execution is
// exposed by this adapter. Network access remains denied unless the embedding
// host supplies an explicit gosh.WithNetwork policy through WithShellOptions.
package goshmcp
