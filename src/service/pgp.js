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

const log = require('winston');
const util = require('./util');
const config = require('config');
const openpgp = require('openpgp');

const KEY_BEGIN = '-----BEGIN PGP PUBLIC KEY BLOCK-----';
const KEY_END = '-----END PGP PUBLIC KEY BLOCK-----';

/**
 * A simple wrapper around OpenPGP.js
 */
class PGP {
  constructor() {
    openpgp.config.show_version = false;
    openpgp.config.show_comment = false;
  }

  /**
   * Parse an ascii armored pgp key block and get its parameters.
   * @param  {String} publicKeyArmored   ascii armored pgp key block
   * @return {Object}                    public key document to persist
   */
  async parseKey(publicKeyArmored) {
    publicKeyArmored = this.trimKey(publicKeyArmored);

    const r = await openpgp.key.readArmored(publicKeyArmored);
    if (r.err) {
      const error = r.err[0];
      log.error('pgp', 'Failed to parse PGP key:\n%s', publicKeyArmored, error);
      util.throw(500, 'Failed to parse PGP key');
    } else if (!r.keys || r.keys.length !== 1 || !r.keys[0].primaryKey) {
      util.throw(400, 'Invalid PGP key: only one key can be uploaded');
    }

    // verify primary key
    const key = r.keys[0];
    const primaryKey = key.primaryKey;
    const now = new Date();
    const verifyDate = primaryKey.created > now ? primaryKey.created : now;
    if (await key.verifyPrimaryKey(verifyDate) !== openpgp.enums.keyStatus.valid) {
      util.throw(400, 'Invalid PGP key: primary key verification failed');
    }

    // accept version 4 keys only
    const keyId = primaryKey.getKeyId().toHex();
    const fingerprint = primaryKey.getFingerprint();
    if (!util.isKeyId(keyId) || !util.isFingerPrint(fingerprint)) {
      util.throw(400, 'Invalid PGP key: only v4 keys are accepted');
    }

    // check for at least one valid user id
    const {userIds, status} = await this.parseUserIds(key.users, primaryKey, verifyDate);
    if (!userIds.length) {
      if (status == 1) {
        util.throw(400, 'Invalid PGP key: no user ID comes from a valid organisation');
      }
      else {
        util.throw(400, 'Invalid PGP key: invalid user IDs');
      }
    }

    // get algorithm details from primary key
    const keyInfo = key.primaryKey.getAlgorithmInfo();

    // public key document that is stored in the database
    return {
      keyId,
      fingerprint,
      userIds,
      created: primaryKey.created,
      uploaded: new Date(),
      algorithm: keyInfo.algorithm,
      keySize: keyInfo.bits,
      publicKeyArmored
    };
  }

  /**
   * Remove all characters before and after the ascii armored key block
   * @param  {string} data   The ascii armored key
   * @return {string}        The trimmed key block
   */
  trimKey(data) {
    if (!this.validateKeyBlock(data)) {
      util.throw(400, 'Invalid PGP key: key block not found');
    }
    return KEY_BEGIN + data.split(KEY_BEGIN)[1].split(KEY_END)[0] + KEY_END;
  }

  /**
   * Validate an ascii armored public PGP key block.
   * @param  {string} data   The armored key block
   * @return {boolean}       If the key is valid
   */
  validateKeyBlock(data) {
    if (!util.isString(data)) {
      return false;
    }
    const begin = data.indexOf(KEY_BEGIN);
    const end =  data.indexOf(KEY_END);
    return begin >= 0 && end > begin;
  }

  /**
   * Parse an array of user ids and verify signatures
   * @param  {Array} users      A list of openpgp.js user objects
   * @param {Object} primaryKey The primary key packet of the key
   * @param {Date} verifyDate   Verify user IDs at this point in time
   * @return {Array, integer}   An array of user id objects and a satus indicator
   * Values of status : 0 if no error, 1 if no address comes from a specific organisation.
   */
  async parseUserIds(users, primaryKey, verifyDate = new Date()) {
    if (!users || !users.length) {
      util.throw(400, 'Invalid PGP key: no user ID found');
    }
    // at least one user id must be valid, revoked or expired
    const result = [];
    var isFromOrganisation = false;
    for (const user of users) {
      const userStatus = await user.verify(primaryKey, verifyDate);
      if (userStatus !== openpgp.enums.keyStatus.invalid && user.userId && user.userId.userid) {
        try {
          const uid = openpgp.util.parseUserId(user.userId.userid);
          if (util.isEmail(uid.email)) {
            // map to local user id object format
            result.push({
              status: userStatus,
              name: uid.name,
              email: util.normalizeEmail(uid.email),
              verified: false
            });
            if(util.isFromOrganisation(util.normalizeEmail(uid.email)))
            	isFromOrganisation = true;
          }
        } catch (e) {}
      }
    }
    var status = 0;
    if(config.publicKey.restrictUserOrigin && !isFromOrganisation ){
      result.length = 0;
      status = 1;
    }
    return {userIds: result, status: status};
  }

  /**
   * Remove user IDs from armored key block which are not in array of user IDs
   * @param  {Array} userIds  user IDs to be kept
   * @param  {String} armored armored key block to be filtered
   * @return {String}         filtered amored key block
   */
  async filterKeyByUserIds(userIds, armored) {
    const emails = userIds.map(({email}) => email);
    const {keys: [key]} = await openpgp.key.readArmored(armored);
    key.users = key.users.filter(({userId}) => !userId || emails.includes(util.normalizeEmail(userId.email)));
    return key.armor();
  }
  
  /**
   * Remove signatures from source armored key which are not in compared armored key
   * @param  {String} srcArmored armored key block to be filtered
   * @param  {String} cmpArmored armored key block to be compare with
   * @return {String, newSigs}   filterd armored key block, list of new signatures
   */
  async filterKeyBySignatures(srcArmored, cmpArmored) {
    const {keys: [srcKey], err: srcErr} = await openpgp.key.readArmored(srcArmored);
    if (srcErr) {
      log.error('pgp', 'Failed to parse source PGP key:\n%s', srcArmored, srcErr);
      util.throw(500, 'Failed to parse PGP key');
    }
    const {keys: [cmpKey], err: cmpErr} = await openpgp.key.readArmored(cmpArmored);
    if (cmpErr) {
      log.error('pgp', 'Failed to parse destination PGP key:\n%s', cmpArmored, cmpErr);
      util.throw(500, 'Failed to parse PGP key');
    }
    
    const newSigs=[];
    if(cmpKey.hasSameFingerprintAs(srcKey)) {
      await Promise.all(srcKey.users.map(async srcUser => {
        await Promise.all(cmpKey.users.map(async dstUser => {
          if ((srcUser.userId && dstUser.userId &&
             (srcUser.userId.userid === dstUser.userId.userid)) ||
             (srcUser.userAttribute && (srcUser.userAttribute.equals(dstUser.userAttribute)))) {
            const source = srcUser.otherCertifications;
            const dest = dstUser.otherCertifications;
            for(let i = source.length-1; i >= 0; i--) {
              const sourceSig = source[i];
              if (!sourceSig.isExpired() && !dest.some(function(destSig) {
                return util.equalsUint8Array(destSig.signature, sourceSig.signature);
              })) {
                // list new signatures
                let userId = (srcUser.userId) ? srcUser.userId.userid : null; 
                let userAttribute = (srcUser.userAttribute) ? srcUser.userAttribute : null;
                newSigs.push({user: {userId: userId, userAttribute: userAttribute}, signature: sourceSig});
                // do not add new signatures
                source.splice(i, 1);
              }
            }
          }
        }));
      }));
    }
    return {armored: srcKey.armor(), newSigs: newSigs};
  }

  /**
   * Merge (update) armored key blocks without adding new signatures
   * @param  {String} srcArmored source amored key block
   * @param  {String} dstArmored destination armored key block
   * @return {String}            merged amored key block
   */
  async updateKey(srcArmored, dstArmored) {
    const {keys: [srcKey], err: srcErr} = await openpgp.key.readArmored(srcArmored);
    if (srcErr) {
      log.error('pgp', 'Failed to parse source PGP key for update:\n%s', srcArmored, srcErr);
      util.throw(500, 'Failed to parse PGP key');
    }
    const {keys: [dstKey], err: dstErr} = await openpgp.key.readArmored(dstArmored);
    if (dstErr) {
      log.error('pgp', 'Failed to parse destination PGP key for update:\n%s', dstArmored, dstErr);
      util.throw(500, 'Failed to parse PGP key');
    }    
    await dstKey.update(srcKey);
    return dstKey.armor();
  }
  
  /**
   * Returns primary user and most significant (latest valid) self signature
   * - if multiple primary users exist, returns the one with the latest self signature
   * - otherwise, returns the user with the latest self signature
   * @return {Object}   The primary userId
   */
  async getPrimaryUser(publicKeyArmored) {
    const {keys: [key], err: srcErr} = await openpgp.key.readArmored(publicKeyArmored);
    if (srcErr) {
      log.error('pgp', 'Failed to parse PGP key for getPrimaryUser:\n%s', publicKeyArmored, srcErr);
      util.throw(500, 'Failed to parse PGP key');
    }
    const primaryUser = await key.getPrimaryUser();
    return primaryUser;
  }
  
  /**
   * Remove user ID from armored key block
   * @param  {String} email            email of user ID to be removed
   * @param  {String} publicKeyArmored amored key block to be filtered
   * @return {String}                  filtered armored key block
   */
  async removeUserId(email, publicKeyArmored) {
    const {keys: [key]} = await openpgp.key.readArmored(publicKeyArmored);
    key.users = key.users.filter(({userId}) => !userId || util.normalizeEmail(userId.email) !== email);
    return key.armor();
  }
}

module.exports = PGP;
