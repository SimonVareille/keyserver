/**
 * Mailvelope - secure email with OpenPGP encryption for Webmail
 * Copyright (C) 2016 Mailvelope GmbH
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

'use strict';

const crypto = require('crypto');
const config = require('config');

/**
 * Checks for a valid string
 * @param  {} data     The input to be checked
 * @return {boolean}   If data is a string
 */
exports.isString = function(data) {
  return typeof data === 'string' || String.prototype.isPrototypeOf(data); // eslint-disable-line no-prototype-builtins
};

/**
 * Cast string to a boolean value
 * @param  {}  data    The input to be checked
 * @return {boolean}   If data is true
 */
exports.isTrue = function(data) {
  if (this.isString(data)) {
    return data === 'true';
  } else {
    return Boolean(data);
  }
};

/**
 * Checks for a valid long key id which is 16 hex chars long.
 * @param  {string} data   The key id
 * @return {boolean}       If the key id is valid
 */
exports.isKeyId = function(data) {
  if (!this.isString(data)) {
    return false;
  }
  return /^[a-fA-F0-9]{16}$/.test(data);
};

/**
 * Checks for a valid version 4 fingerprint which is 40 hex chars long.
 * @param  {string} data   The key id
 * @return {boolean}       If the fingerprint is valid
 */
exports.isFingerPrint = function(data) {
  if (!this.isString(data)) {
    return false;
  }
  return /^[a-fA-F0-9]{40}$/.test(data);
};

/**
 * Checks for a valid email address.
 * @param  {string} data   The email address
 * @return {boolean}       If the email address if valid
 */
exports.isEmail = function(data) {
  if (!this.isString(data)) {
    return false;
  }
  const re = /^(([^<>()[\]\\.,;:\s@\"]+(\.[^<>()[\]\\.,;:\s@\"]+)*)|(\".+\"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
  return re.test(data);
};

/**
 * Checks for a valid specific organisation email address.
 * @param  {string} data   The email address
 * @return {boolean}       Wether the email address comes from organisation
 */
exports.isFromOrganisation = function(data) {
  if (!this.isString(data)) {
    return false;
  }
  const re = new RegExp(config.publicKey.restrictionRegEx, 'g');
  return re.test(data);
};

/**
 * Normalize email address to lowercase.
 * @param  {string} email   The email address
 * @return {string}       lowercase email address
 */
exports.normalizeEmail = function(email) {
  if (email) {
    email = email.toLowerCase();
  }
  return email;
};

/**
 * Check Uint8Array equality
 * @param {Uint8Array} first array
 * @param {Uint8Array} second array
 * @returns {Boolean} equality
 */
exports.equalsUint8Array = function (array1, array2) {
  try {
    if (array1.length !== array2.length) {
      return false;
    }
    
    for (let i = 0; i < array1.length; i++) {
      if (array1[i] !== array2[i]) {
        return false;
      }
    }
  } catch (e) {return false;}
  return true;
};

/**
 * Decode a base64 byte to uint6
 * @param {Integer} nChr base64 byte to decode
 * @returns {Integer} the uint6 integer
 * Comes from https://developer.mozilla.org/en-US/docs/Web/API/WindowBase64/Base64_encoding_and_decoding
 * All thanks to madmurphy
 */
function b64ToUint6 (nChr) {
  return nChr > 64 && nChr < 91 ?
      nChr - 65
    : nChr > 96 && nChr < 123 ?
      nChr - 71
    : nChr > 47 && nChr < 58 ?
      nChr + 4
    : nChr === 43 ?
      62
    : nChr === 47 ?
      63
    :
      0;
};

/**
 * Decode a base64 String to Uint8Array
 * @param {String} sBase64 base64 string to decode
 * @returns {Uint8Array} decoded data
 * Comes from https://developer.mozilla.org/en-US/docs/Web/API/WindowBase64/Base64_encoding_and_decoding
 * All thanks to madmurphy
 */
exports.base64DecToArr = function (sBase64) {
  var sB64Enc = sBase64.replace(/[^A-Za-z0-9\+\/]/g, ""), nInLen = sB64Enc.length,
    nOutLen = nInLen * 3 + 1 >> 2, taBytes = new Uint8Array(nOutLen);

  for (var nMod3, nMod4, nUint24 = 0, nOutIdx = 0, nInIdx = 0; nInIdx < nInLen; nInIdx++) {
    nMod4 = nInIdx & 3;
    nUint24 |= b64ToUint6(sB64Enc.charCodeAt(nInIdx)) << 18 - 6 * nMod4;
    if (nMod4 === 3 || nInLen - nInIdx === 1) {
      for (nMod3 = 0; nMod3 < 3 && nOutIdx < nOutLen; nMod3++, nOutIdx++) {
        taBytes[nOutIdx] = nUint24 >>> (16 >>> nMod3 & 24) & 255;
      }
      nUint24 = 0;
    }
  }
  return taBytes;
};

/**
 * Encode a uint6 to base64 byte
 * @param {Integer} nUint6 integer to encode
 * @returns {Integer} the base64 byte
 * Comes from https://developer.mozilla.org/en-US/docs/Web/API/WindowBase64/Base64_encoding_and_decoding
 * All thanks to madmurphy
 */
function uint6ToB64 (nUint6) {
  return nUint6 < 26 ?
      nUint6 + 65
    : nUint6 < 52 ?
      nUint6 + 71
    : nUint6 < 62 ?
      nUint6 - 4
    : nUint6 === 62 ?
      43
    : nUint6 === 63 ?
      47
    :
      65;
};


/**
 * Encode a Uint8Array to base64
 * @param {Uint8Array} aBytes array to encode
 * @returns {String} base64 String
 * Comes from https://developer.mozilla.org/en-US/docs/Web/API/WindowBase64/Base64_encoding_and_decoding
 * All thanks to madmurphy
 */
exports.base64EncArr = function (aBytes) {
  var eqLen = (3 - (aBytes.length % 3)) % 3, sB64Enc = "";
  for (var nMod3, nLen = aBytes.length, nUint24 = 0, nIdx = 0; nIdx < nLen; nIdx++) {
    nMod3 = nIdx % 3;
    /* Uncomment the following line in order to split the output in lines 76-character long: */
    /*
    if (nIdx > 0 && (nIdx * 4 / 3) % 76 === 0) { sB64Enc += "\r\n"; }
    */
    nUint24 |= aBytes[nIdx] << (16 >>> nMod3 & 24);
    if (nMod3 === 2 || aBytes.length - nIdx === 1) {
      sB64Enc += String.fromCharCode(uint6ToB64(nUint24 >>> 18 & 63), uint6ToB64(nUint24 >>> 12 & 63), uint6ToB64(nUint24 >>> 6 & 63), uint6ToB64(nUint24 & 63));
      nUint24 = 0;
    }
  }
  return  eqLen === 0 ? sB64Enc : sB64Enc.substring(0, sB64Enc.length - eqLen) + (eqLen === 1 ? "=" : "==");
};


/**
 * Create an error with a custom status attribute e.g. for http codes.
 * @param  {number} status    The error's http status code
 * @param  {string} message   The error message
 * @return {Error}            The resulting error object
 */
exports.throw = function(status, message) {
  const err = new Error(message);
  err.status = status;
  err.expose = true; // display message to the client
  throw err;
};

/**
 * Generate a cryptographically secure random hex string. If no length is
 * provided a 32 char hex string will be generated by default.
 * @param  {number} bytes   (optional) The number of random bytes
 * @return {string}         The random bytes in hex (twice as long as bytes)
 */
exports.random = function(bytes) {
  bytes = bytes || 16;
  return crypto.randomBytes(bytes).toString('hex');
};

/**
 * Check if the user is connecting over a plaintext http connection.
 * This can be used as an indicator to upgrade their connection to https.
 * @param  {Object} ctx   The koa request/repsonse context
 * @return {boolean}      If http is used
 */
exports.checkHTTP = function(ctx) {
  return !ctx.secure && ctx.get('X-Forwarded-Proto') === 'http';
};

/**
 * Check if the user is connecting over a https connection.
 * @param  {Object} ctx   The koa request/repsonse context
 * @return {boolean}      If https is used
 */
exports.checkHTTPS = function(ctx) {
  return ctx.secure || ctx.get('X-Forwarded-Proto') === 'https';
};

/**
 * Get the server's own origin host and protocol. Required for sending
 * verification links via email. If the PORT environmane variable
 * is set, we assume the protocol to be 'https', since the AWS loadbalancer
 * speaks 'https' externally but 'http' between the LB and the server.
 * @param  {Object} ctx   The koa request/repsonse context
 * @return {Object}       The server origin
 */
exports.origin = function(ctx) {
  return {
    protocol: this.checkHTTPS(ctx) ? 'https' : ctx.protocol,
    host: ctx.host
  };
};

/**
 * Helper to create urls pointing to this server
 * @param  {Object} origin     The server's origin
 * @param  {string} resource   (optional) The resource to point to
 * @return {string}            The complete url
 */
exports.url = function(origin, resource) {
  return `${origin.protocol}://${origin.host}${resource || ''}`;
};

/**
 * Helper to create a url for hkp clients to connect to this server via
 * the hkp protocol.
 * @param  {Object} ctx   The koa request/repsonse context
 * @return {string}       The complete url
 */
exports.hkpUrl = function(ctx) {
  return (this.checkHTTPS(ctx) ? 'hkps://' : 'hkp://') + ctx.host;
};
