# Safe MCP Server Example

This fixture demonstrates a safer local file-read pattern for MCP tools that need to read files from a narrow, known directory.

The example uses `Path.resolve()` and `Path.relative_to()` so sibling directories with the same prefix do not bypass the boundary check. It also rejects directories and missing files before reading.

Compare this with `examples/unsafe-mcp-server/`, which intentionally contains shell execution, dynamic evaluation, remote install, and secret-passing patterns for scanner demonstrations.
