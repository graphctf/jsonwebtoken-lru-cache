const { promisify } = require('util');
const { decode, verify: verifySync } = require('jsonwebtoken');
const Lru = require('lru-cache');
const sizeOf = require('object-sizeof');

const verifyAsync = promisify(verifySync);

// For private methods
const getMaxAge = Symbol('getMaxAge');
const verify = Symbol('verify');

/**
 * An implementation of jsonwebtoken.verify which intelligently caches the results of past lookups to save the costly
 * crypto operations associated with verification.
 */
class JwtLruCache {
  /**
   * An implementation of jsonwebtoken.verify which intelligently caches the results of past lookups to save the costly
   * crypto operations associated with verification.
   *
   * @param {int} size The rough size in bytes
   * @param {string|Object} secretOrPrivateKey The secret key all JWT tokens in this cache will be verified with.
   * @param {Object?} options Additional properties for pass to verify for all JWT tokens in this cache.
   */
  constructor (sizeInBytes, secretOrPrivateKey, options) {
    this.secretOrPrivateKey = secretOrPrivateKey;
    this.options = options;
    this.cache = new Lru({
      max: sizeInBytes,
      length: (val, key) => 2 + sizeOf(val) + key.length,
    });
  }

  /**
   * Calculates the number of seconds until the token's validation may change. If the token has a future nbf or exp, the
   * result will be the number of seconds until that time. (If not, the validation never expires and the function
   * returns null.)
   *
   * @param {Object} payload The token's decoded payload.
   * @param {int?} timestamp Timestamp in seconds to use for the current time. Defaults to the time from Date.now.
   * @returns {int?} The time until the token's validity may change, or null.
   */
  [getMaxAge] (payload) {
    if (typeof(payload) !== 'object') return null;
    const { nbf, exp } = payload;
    const { clockTolerance = 0, ignoreNotBefore, ignoreExpiration } = this.options || {};
    const currentTime = Math.floor(Date.now() / 1000);

    if (!ignoreNotBefore && nbf && (currentTime + clockTolerance) < nbf)
      return ((nbf - clockTolerance) - currentTime) * 1000;

    else if (!ignoreExpiration && exp && (currentTime - clockTolerance) < exp)
      return ((exp + clockTolerance) - currentTime) * 1000;

    else return null;
  }

  /**
   * Verifies the token, saves the validation in the cache, and returns both the decoded value and an error.
   *
   * @param {string} token The token to validate (and cache).
   * @param {boolean} complete If true, the result will be an object {header, payload, signature}.
   * @returns {Object} Object containing the decoded JWT as result, and any error as error.
   */
  [verify] (token, complete, promise) {
    if (typeof(complete) === 'string')
      throw Error('You can only set secretOrPrivateKey in the constructor, not in the second param to verify().');

    let error = null, result = null;

    if (!this.cache.has(token)) {
      result = decode(token, { complete: true });
      const maxAge = this[getMaxAge](result.payload);

      if (promise) {
        return verifyAsync(token, this.secretOrPrivateKey, this.options)
          .catch((err) => error = err)
          .then(() => this.cache.set(token, [error, result], maxAge))
          .then(() => ({ error, result: complete ? result : result.payload }));
      } else {
        try {
          verifySync(token, this.secretOrPrivateKey, this.options);
        } catch (err) {
          error = err;
        }
        this.cache.set(token, [ error, result ], maxAge);
        return { error, result: complete ? result : result.payload };
      }
    } else {
      [ error, result ] = this.cache.get(token);
      const out = { error, result: complete ? result : result.payload };
      if (promise) {
        return new Promise((resolve, reject) => resolve(out));
      } else {
        return out;
      }
    }
  }

  /**
   * Checks if the token is in the cache (and unexpired).
   *
   * @param {string} token The token to check.
   * @returns {boolean} True if the token exists in the cache and is unexpired, false if not.
   */
  has (token) {
    return this.cache.has(token);
  }

  /**
   * Gets the remaining max-age of an item in the cache. This is slow because lru-cache does not expose this method
   * natively and we have to get a deep copy of the object, so this should mostly be used for testing.
   *
   * @param {string} token The token to search for in the cache.
   * @returns {int?} The remaining max-age, or null if not set.
   */
  getMaxAge (token) {
    const entry = this.cache.dump().filter(e => e.k === token)[0] || null;
    if (!entry) return null;
    return Math.floor((entry.e - Date.now())/1000);
  }

  /**
   * Verifies the token, saves the validation in the cache, and returns both the decoded value and an error.
   *
   * @param {string} token The token to validate (and cache).
   * @param {boolean} complete If true, the result will be an object {header, payload, signature}.
   * @returns {Object} The decoded token: either the payload, or the full object if options.complete is true.
   */
  async verifyAsync (token, complete) {
    const { result, error } = await this[verify](token, complete, true);
    if (error)
      throw error;
    return result;
  }

  /**
   * Verifies the token, saves the validation in the cache, and returns both the decoded value and an error.
   *
   * @param {string} token The token to validate (and cache).
   * @param {boolean} complete If true, the result will be an object {header, payload, signature}.
   * @param {function} callback Optional callback function, if not provided it will be called synchronously.
   * @returns {Object} The decoded token: either the payload, or the full object if options.complete is true.
   */
  verify (token, complete, callback) {
    if (callback) this[verify](token, complete, true).then(({ error, result }) => callback(error, result));
    else {
      const { error, result } = this[verify](token, complete, false);
      if (error) throw Error(error);
      return result;
    }
  }
}
module.exports = JwtLruCache;
