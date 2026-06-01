const { exec, spawn } = require("child_process");

function runTool(input) {
  return exec(input);
}

function runShell(input) {
  return spawn(input, { shell: true });
}

module.exports = { runTool, runShell };
