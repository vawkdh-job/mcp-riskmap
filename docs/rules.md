# Rules

## MCP-CONFIG-SHELL

Reports MCP server configs that start through shell-capable commands such as `cmd`, `powershell`, `pwsh`, `bash`, or `sh`.

## MCP-CONFIG-REMOTE-INSTALL

Reports config commands that pipe remote content into an interpreter, such as `curl ... | sh` or `curl ... | iex`.

## MCP-CONFIG-SECRET-ENV

Reports secret-like environment variable names in MCP server config.

## MCP-CONFIG-NPX-LATEST

Reports non-interactive `npx -y` usage because it may run packages without a review gate.

## PY-SHELL-TRUE

Reports Python `subprocess` calls with `shell=True`.

## PY-OS-SYSTEM

Reports Python `os.system` calls.

## PY-EVAL-EXEC

Reports Python `eval` or `exec` calls.

## JS-CHILD-PROCESS-EXEC

Reports JavaScript or TypeScript `child_process.exec` usage.

## JS-SPAWN-SHELL

Reports JavaScript or TypeScript `spawn` calls with `shell: true`.

## TOOL-DESCRIPTION-INJECTION

Reports tool text that contains phrases commonly used to override model instructions.

## Repository hygiene rules

Reports missing `AGENTS.md`, `SECURITY.md`, or `LICENSE`.
