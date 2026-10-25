// Demo target for Receipts: parses command-line flags and creates an output folder.
const argv = require("optimist").argv;
const mkdirp = require("mkdirp");

mkdirp.sync(argv.out || "out");
console.log("ready", argv);
