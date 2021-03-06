'use strict';

// disables Node error from self-signed server SSL certificate
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

const fs = require('fs');
const crypto = require('crypto');

require('dotenv').config();

const argv = require('yargs') // eslint-disable-line
  .usage('\nUsage: node $0 -e plain.file -o output.file')
  .usage('Usage: node $0 -d encrypted.file -o output.file')
  .example('node $0 -e plain.file -o output.file', 'Encrypt file\n\n')
  .example('node $0 -d encrypted.file -o output.file', 'Decrypt file\n\n')
  .help('h')
  .describe('e', 'Process to encrypt the input file')
  .describe('d', 'Process to decrypt the input file')
  .describe('o', 'Path to save the output file')
  .alias('e', 'encrypt')
  .alias('d', 'decrypt')
  .alias('o', 'output')
  .demandOption('o')
  .conflicts('e', 'd')
  .version(false)
  .argv;

/**
 * Entry function
 * @param {Object} argv
 * @param {string=} argv.e
 * @param {string=} argv.d
 * @param {string} argv.o
 */
function main(argv) {
  // crypto constants
  const HASH_ALGORITHM = 'sha256';
  const ENCRYPT_ALGORITHM = 'aes-256-ctr';
  const KEY_LEN = 32;
  const IV_LEN = 16;

  /**
   * Exit and clean up
   * @param {Object} err
   */
  const exit = (err) => {
    if (err) console.error(err); // eslint-disable-line no-console
    process.exit(err ? 1 : 0);
  };

  /**
   * Method to encrypt
   * @param {Buffer} buffer
   * @returns {Buffer}
   */
  const encrypt = (buffer) => {
    const key = crypto.createHash(HASH_ALGORITHM).update(String(process.env.MASTER_KEY)).digest('base64').substr(0, KEY_LEN);
    const iv = crypto.randomBytes(IV_LEN);
    const cipher = crypto.createCipheriv(ENCRYPT_ALGORITHM, key, iv);
    return Buffer.concat([iv, cipher.update(buffer), cipher.final()]);
  };

  /**
   * Method to decrypt
   * @param {Buffer} encrypted
   * @returns {Buffer}
   */
  const decrypt = (encrypted) => {
    const key = crypto.createHash(HASH_ALGORITHM).update(String(process.env.MASTER_KEY)).digest('base64').substr(0, KEY_LEN);
    const iv = encrypted.slice(0, IV_LEN);
    const decipher = crypto.createDecipheriv(ENCRYPT_ALGORITHM, key, iv);
    return Buffer.concat([decipher.update(encrypted.slice(IV_LEN)), decipher.final()]);
  };

  const method = argv.e ? encrypt : decrypt;
  const input = argv.e || argv.d;
  fs.readFile(input, (err, data) => {
    if (err) return exit(err);
    return fs.writeFile(argv.o, method(data), exit);
  });
}

if (require.main !== module) {
  module.exports = main;
} else {
  main(argv);
}

