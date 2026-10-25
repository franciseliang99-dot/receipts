// Demo target for Receipts: parses command-line flags with a patched minimist.
const parseArgs = require("minimist");

const argv = parseArgs(process.argv.slice(2));
console.log("ready", argv);
