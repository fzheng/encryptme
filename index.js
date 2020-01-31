'use strict';

// disables Node error from self-signed server SSL certificate
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

const fs = require('fs');
const crypto = require('crypto');
const zlib = require('zlib');
const { Transform } = require('stream');

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

class AppendIv extends Transform {
  constructor(iv, opts) {
    super(opts);
    this.iv = iv;
    this.appended = false;
  }

  _transform(chunk, encoding, cb) {
    if (!this.appended) {
      this.push(this.iv);
      this.appended = true;
    }
    this.push(chunk);
    cb();
  }
}

/**
 * Entry function
 * @param {Object} cmd
 * @param {string=} cmd.e
 * @param {string=} cmd.d
 * @param {string} cmd.o
 */
function main(cmd) {
  // crypto constants
  const HASH_ALGORITHM = 'sha256';
  const ENCRYPT_ALGORITHM = 'aes-256-ctr';
  const KEY_LEN = 32;
  const IV_LEN = 16;

  /**
   * Method to encrypt
   */
  const encrypt = (iv) => {
    const key = crypto.createHash(HASH_ALGORITHM).update(String(process.env.MASTER_KEY)).digest('base64').substr(0, KEY_LEN);
    return crypto.createCipheriv(ENCRYPT_ALGORITHM, key, iv);
  };

  /**
   * Method to decrypt
   */
  const decrypt = (iv) => {
    const key = crypto.createHash(HASH_ALGORITHM).update(String(process.env.MASTER_KEY)).digest('base64').substr(0, KEY_LEN);
    return crypto.createDecipheriv(ENCRYPT_ALGORITHM, key, iv);
  };

  const isEncrypt = !!cmd.e;
  if (isEncrypt) {
    const iv = crypto.randomBytes(IV_LEN);
    fs.createReadStream(cmd.e)
      .pipe(zlib.createGzip())
      .pipe(encrypt(iv))
      .pipe(new AppendIv(iv))
      .pipe(fs.createWriteStream(cmd.o));
  } else {
    let iv;
    const getIv = fs.createReadStream(cmd.d, { end: IV_LEN - 1 });
    getIv.on('data', (chunk) => {
      iv = chunk;
    });
    getIv.on('close', () => {
      fs.createReadStream(cmd.d, { start: IV_LEN })
        .pipe(decrypt(iv))
        .pipe(zlib.createUnzip())
        .pipe(fs.createWriteStream(cmd.o));
    });
  }
}

if (require.main !== module) {
  module.exports = main;
} else {
  main(argv);
}
