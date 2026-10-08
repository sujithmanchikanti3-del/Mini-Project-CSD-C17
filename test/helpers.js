const fs = require('fs');
const os = require('os');
const path = require('path');

/** Create a temp directory containing the given { relativePath: content } files. */
function makeProject(files) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'sec-arch-test-'));
  for (const [rel, content] of Object.entries(files)) {
    const abs = path.join(root, ...rel.split('/'));
    fs.mkdirSync(path.dirname(abs), { recursive: true });
    fs.writeFileSync(abs, content);
  }
  return root;
}

module.exports = { makeProject, OUT: path.join(__dirname, '..', 'out') };
