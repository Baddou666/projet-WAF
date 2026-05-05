const fs = require("fs");
const path = require("path");

function ensureDirectory(filePath) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
}

function writeBlockedRequest(logFile, record) {
  ensureDirectory(logFile);
  fs.appendFileSync(logFile, `${JSON.stringify(record)}\n`, "utf8");
}

module.exports = {
  writeBlockedRequest,
};
