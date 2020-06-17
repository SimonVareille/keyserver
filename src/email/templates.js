'use strict';

const util = require('../service/util');

function verifyKey(ctx, {name, email, nonce, origin, keyId}) {
  const link = `${util.url(origin)}/api/v1/key?op=verify&keyId=${keyId}&nonce=${nonce}`;
  return {
    subject: ctx.__('verify_key_subject'),
    text: ctx.__('verify_key_text', [name, email, link, origin.host])
  };
}

function verifyRemove(ctx, {name, email, nonce, origin, keyId}) {
  const link = `${util.url(origin)}/api/v1/key?op=verifyRemove&keyId=${keyId}&nonce=${nonce}`;
  return {
    subject: ctx.__('verify_removal_subject'),
    text: ctx.__('verify_removal_text', [name, email, origin.host, link])
  };
}

function checkNewSigs(ctx, {name, sigsNb, nonce, origin, keyId}) {
  const link = `${util.url(origin)}/api/v1/key?op=checkSignatures&keyId=${keyId}&nonce=${nonce}`;
  return {
    subject: ctx.__('check_signatures_subject'),
    text: ctx.__n('check_signatures_text', sigsNb, [name, sigsNb, link, origin.host])
  };
}

module.exports = {verifyKey, verifyRemove, checkNewSigs};
