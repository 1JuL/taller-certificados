const fs = require("fs");
const path = require("path");

function fromRoot(relPath) {
  return path.resolve(process.cwd(), relPath);
}

function readFile(relPath) {
  return fs.readFileSync(fromRoot(relPath));
}

function readText(relPath) {
  return fs.readFileSync(fromRoot(relPath), "utf8");
}

module.exports = {
  fromRoot,
  readFile,
  readText,
};
