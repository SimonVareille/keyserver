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

const parse = require('co-body');
const util = require('../service/util');

/**
 * The REST api to provide additional functionality on top of HKP
 */
class REST {
  /**
   * Create an instance of the REST server
   * @param  {Object} publicKey   An instance of the public key service
   * @param  {Object} userId      An instance of the user id service
   */
  constructor(publicKey) {
    this._publicKey = publicKey;
  }
  
  /**
   * http POST handler
   * @param  {Object} ctx   The koa request/response context
   */
  async postHandler(ctx) {
    const json = await parse.json(ctx, {limit: '1mb'});
    if(json.op === 'confirmSignatures')
      return this[json.op](ctx, json);//delegate operation
    
    await this.create(ctx, json);
  }
  
  /**
   * Public key / user ID upload via http POST
   * @param  {Object} ctx   The koa request/response context
   * @param  {Object} json  The json content of the request
   */
  async create(ctx, json) {
    const {emails, publicKeyArmored} = json || await parse.json(ctx, {limit: '1mb'});
    if (!publicKeyArmored) {
      ctx.throw(400, 'Invalid request!');
    }
    const origin = util.origin(ctx);
    await this._publicKey.put({emails, publicKeyArmored, origin}, ctx);
    ctx.body = 'Upload successful. Check your inbox to verify your email address.';
    ctx.status = 201;
  }

  /**
   * Public key query via http GET
   * @param  {Object} ctx   The koa request/response context
   */
  async query(ctx) {
    const op = ctx.query.op;
    if (op === 'verify' || op ===  'verifyRemove' || op === 'confirmSignatures' ||
        op === 'checkSignatures') {
      return this[op](ctx); // delegate operation
    }
    // do READ if no 'op' provided
    const q = {keyId: ctx.query.keyId, fingerprint: ctx.query.fingerprint, email: ctx.query.email};
    if (!util.isKeyId(q.keyId) && !util.isFingerPrint(q.fingerprint) && !util.isEmail(q.email)) {
      ctx.throw(400, 'Invalid request!');
    }
    ctx.body = await this._publicKey.get(q, ctx);
  }

  /**
   * Verify a public key's user id via http GET
   * @param  {Object} ctx   The koa request/response context
   */
  async verify(ctx) {
    const q = {keyId: ctx.query.keyId, nonce: ctx.query.nonce};
    if (!util.isKeyId(q.keyId) || !util.isString(q.nonce)) {
      ctx.throw(400, 'Invalid request!');
    }
    const {email} = await this._publicKey.verify(q, util.origin(ctx), ctx);
    // create link for sharing
    const link = util.url(util.origin(ctx), `/pks/lookup?op=get&search=${email}`);
    await ctx.render('verify-success', {email, link});
  }
  
  /**
   * Check public key's signatures via http GET
   * @param  {Object} ctx   The koa request/response context
   */
  async checkSignatures(ctx) {
    const q = {keyId: ctx.query.keyId, nonce: ctx.query.nonce};
    if (!util.isKeyId(q.keyId) || !util.isString(q.nonce)) {
      ctx.throw(400, 'Invalid request!');
    }
    
    const sigs = await this._publicKey.getPendingSignatures(q, ctx);
    // create link for confirmation
    const link = util.url(util.origin(ctx), `/api/v1/key`);
    await ctx.render('verify-certs', {keyId: q.keyId, link, nonce: q.nonce, sigs});
  }
  
  /**
   * Confirm public key's signatures via http POST
   * @param  {Object} ctx   The koa request/response context
   * @param  {Object} json  The json content of the request
   */
  async confirmSignatures(ctx, json) {
    const post = json || await parse.json(ctx, {limit: '1mb'});
    const q = {keyId: post.keyId, nonce: post.nonce, sigs: post.sig};
    const {email} = await this._publicKey.verifySignatures(q, util.origin(ctx), ctx);
    // create link for sharing
    const link = util.url(util.origin(ctx), `/pks/lookup?op=get&search=${email}`);
    ctx.body = `Update successful. You can find your key <a href="${link}" target="_blank">here</a>.`;
    ctx.status = 201;
  }
  
  /**
   * Request public key removal via http DELETE
   * @param  {Object} ctx   The koa request/response context
   */
  async remove(ctx) {
    const q = {keyId: ctx.query.keyId, email: ctx.query.email, origin: util.origin(ctx)};
    if (!util.isKeyId(q.keyId) && !util.isEmail(q.email)) {
      ctx.throw(400, 'Invalid request!');
    }
    await this._publicKey.requestRemove(q, ctx);
    ctx.body = 'Check your inbox to verify the removal of your email address.';
    ctx.status = 202;
  }

  /**
   * Verify public key removal via http GET
   * @param  {Object} ctx   The koa request/response context
   */
  async verifyRemove(ctx) {
    const q = {keyId: ctx.query.keyId, nonce: ctx.query.nonce};
    if (!util.isKeyId(q.keyId) || !util.isString(q.nonce)) {
      ctx.throw(400, 'Invalid request!');
    }
    const {email} = await this._publicKey.verifyRemove(q);
    await ctx.render('removal-success', {email});
  }
}

module.exports = REST;
