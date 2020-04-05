const jsonwebtoken = require('jsonwebtoken'),
    cache = require('cache')(),
    crypto = require('crypto');
var _appConfig = {};

/**
 * Decrypts an encrypted JWT using the secret and returns the decrypted payload object,
 * The parameter for this method can either be a JWT or the request object
 * @param jwt
 * @returns {*}
 */
function getJwtPayload(jwt) {
    if (typeof jwt === "object") {
        var req = jwt;
        jwt = this.getJwtCookie(req);
    }

    var payload;
    if (jwt !== undefined) {
        payload = jsonwebtoken.verify(jwt, _appConfig.settings.get('/JWT/SECRET'));
    }
    return payload;
};

/**
 * Decrypts an encrypted JWT using the secret and returns a Promise for the decrypted payload object,
 * The parameter for this method can either be a JWT or the request object
 * @param jwt
 * @returns {*}
 */
function getJwtPayloadAsync(jwt, options) {
    return new Promise(function (resolve, reject) {
        if (typeof jwt === "object") {
            const req = jwt;
            jwt = this.getJwtCookie(req);
        }

        let payload;
        if (jwt !== undefined) {
            switch (options["type"]) {
                case "cmt":
                    try {
                        payload = jsonwebtoken.verify(jwt, _appConfig.settings.get('/JWT/CMT/SECRET'));
                    } catch (err) {
                        return reject(err);
                    }
                    break;
                case "customer":
                    try {
                        payload = jsonwebtoken.verify(jwt, new Buffer(_appConfig.settings.get('/JWT/SECRET'), 'base64'));
                    } catch (err) {
                        return reject(err);
                    }
                    break;
                default:
                    try {
                        payload = jsonwebtoken.verify(jwt, new Buffer(_appConfig.settings.get('/JWT/SECRET')), 'base64');
                    } catch (err) {
                        return reject(err);
                    }
            }
        }
        return resolve(payload);
    });
};

/**
 * Creates a new JWT using a payload
 * @param payload
 * @returns {*}
 */
function createJwt(payload) {
    //Create the JWT using the secret
    return jsonwebtoken.sign(payload, new Buffer(_appConfig.settings.get('/JWT/SECRET'), 'base64'));
};

/**
 * Returns a Promise for a new JWT using a payload
 * @param payload
 * @returns {*}
 */
function createJwtPromise(payload) {
    //Create the JWT using the secret
    return new Promise(function (resolve, reject) {
        let token;
        try {
            token = jsonwebtoken.sign(payload, new Buffer(_appConfig.settings.get('/JWT/SECRET'), 'base64'));
        } catch (err) {
            return reject(err);
        }
        return resolve(token);
    });
};

/**
 * Returns the encrypted JWT stored in the cookie
 * @param req, options hash
 * @returns {*}
 */
function getJwtCookie(req, options) {
    let jwt;
    switch (options["type"]) {
        case "cmt":
            jwt = req.state[_appConfig.settings.get('/JWT/CMT/COOKIE/NAME')];
            break;
        case "customer":
            jwt = req.state[_appConfig.settings.get('/JWT/COOKIE/NAME')];
            break;
        default:
            jwt = undefined;
    }
    return jwt;
};

/**
 * Deletes a JWT cookie from provided response object
 * @param response
 */
function deleteJwtCookie(response) {
    response.unstate(_appConfig.settings.get('/JWT/COOKIE/NAME'), {
        ttl: 0, // In milliseconds
        path: _appConfig.settings.get('/JWT/COOKIE/PATH'),
        domain: _appConfig.settings.get('/JWT/COOKIE/DOMAIN')
    });
};

/**
 * Deletes JWT from Redis cache
 * @param jwt
 */
function deleteJwtCache(jwt) {
    cache.getRedisClient().exists(jwt, function (err, result) {
        if (err) {
            callback(cache.error(err));
        } else {
            if (result === 1) {
                cache.getRedisClient().del(jwt);
            }
        }

    });
};

/**
 * Caches a JWT cookie with a provided expiration
 * @param response
 */
function cacheNewJwtPromise(jwt, minutesTilExpire) {

    return new Promise(function (resolve, reject) {
        let createTime = new Date(),
            expireTime = new Date();

        expireTime.setMinutes(expireTime.getMinutes() + minutesTilExpire);

        // Save jwt into redis cache
        // "key" = jwt, "value" = { "expireTime": expireTime }
        // Other properties can be added to the "value" property later if we need to store other data for the user
        cache.getRedisClient().hset(jwt, _appConfig.settings.get('/REDIS_USER_KEYS/EXPIRE_TIME'), expireTime, function (err, result) {
            if (err) {
                return {
                    "ERROR_CODE": "USCNODE001",
                    "STATUS_CODE": 503,
                    "ERROR_DESCRIPTION": "Cannot connect to Redis cache server"
                };
            } else {
                cache.getRedisClient().expire(jwt, minutesTilExpire * 60, function (err, result) {
                    if (err) {
                        return {
                            "ERROR_CODE": "USCNODE001",
                            "STATUS_CODE": 503,
                            "ERROR_DESCRIPTION": "Cannot connect to Redis cache server"
                        };
                    } else {
                        return resolve(jwt);
                    }
                });
            }
        });
    });
};

/**
 * Sets the response cookie with a JWT
 * @param jwt
 * @param response
 * @param minutesTilExpire
 */
function setJwtCookie(jwt, response, minutesTilExpire) {
    response.state(_appConfig.settings.get('/JWT/COOKIE/NAME'), jwt, {
        ttl: minutesTilExpire * 60 * 1000, // In milliseconds
        path: _appConfig.settings.get('/JWT/COOKIE/PATH'),
        domain: _appConfig.settings.get('/JWT/COOKIE/DOMAIN')
    });
};

/**
 * Checks for JWT and whether it's valid using promises
 * @param jwt
 */
function isJwtValidAsync(jwt) {
    return new Promise(function (resolve, reject) {
        let jwtValid = false;

        cache.getRedisClient().existsAsync(jwt)
            .then(function (jwtExists) {
                if (jwtExists === 1) {
                    cache.getRedisClient().hgetAsync(jwt, _appConfig.get('/REDIS_USER_KEYS/EXPIRE_TIME'))
                        .then(function (res) {
                            const expireDate = new Date(res);
                            const hasExpired = ((Date.now() - expireDate) >= 0);
                            // Exists but has expired
                            if (!hasExpired) {
                                // JWT exists and hasn't expired yet so it is still valid
                                jwtValid = true;
                            }
                            return resolve(jwtValid);
                        })
                        .catch(function (err) {
                            return reject(err);
                        });
                } else {
                    // JWT did not exist
                    return resolve(jwtValid);
                }
            })
            .catch(function (err) {
                console.log('tried to redis exist failure', err);
                return reject(err);
            })
    });
}

/**
 * Checks for JWT and whether it's valid
 * @param jwt
 * @param callback
 */
function isJwtValid(jwt, callback) {

    // By default, let's say JWT is invalid
    var jwtValid = false;

    // A value for JWT was found so proceed
    if (jwt !== undefined) {
        cache.getRedisClient().exists(jwt, function (err, jwtExists) {
            if (err) {
                callback(cache.error(err));
            } else {
                // JWT exists in the cache
                if (jwtExists === 1) {

                    // Get from Redis asynchronously using the JWT as the key
                    cache.getRedisClient().hget(jwt, _appConfig.settings.get('/REDIS_USER_KEYS/EXPIRE_TIME'), function (err, obj) {
                        if (err) {
                            callback(cache.error(err));
                        } else {
                            var expireDate = new Date(obj);
                            var hasExpired = ((Date.now() - expireDate) >= 0);

                            // Exists but has expired
                            if (!hasExpired) {
                                // JWT exists and hasn't expired yet so it is still valid
                                jwtValid = true;
                            }

                            callback(err, jwtValid);
                        }
                    });
                } else {
                    callback(null, jwtValid);
                }
            }
        });
    } else {
        callback(null, jwtValid);
    }
};

/**
 * Checks for JWT and whether it's valid
 * @param text the text to encrypt
 * @param password the password to use for encryption
 */
function encrypt(text, password) {
    const algorithm = 'aes-256-ctr',
        cipher = crypto.createCipher(algorithm, password);
    let crypted = cipher.update(text, 'utf8', 'hex');
    crypted += cipher.final('hex');
    return crypted;
}

/**
 * Checks for JWT and whether it's valid
 * @param text the encrypted text to decrypt
 * @param password the password to use for decryption
 */
function decrypt(text, password) {
    const algorithm = 'aes-256-ctr',
        decipher = crypto.createDecipher(algorithm, password);
    let dec = decipher.update(text, 'hex', 'utf8');
    dec += decipher.final('utf8');
    return dec;
}

/**
 * Collect the security functions for export
 * @param appConfig the application_configuration
 * @returns {{getJwtPayload: getJwtPayload, createJwt: createJwt, getJwtCookie: getJwtCookie, createJwtPromise: createJwtPromise, deleteJwtCookie: deleteJwtCookie, deleteJwtCache: deleteJwtCache, setJwtCookie: setJwtCookie, isJwtValid: isJwtValid, isJwtValidAsync: isJwtValidAsync, getJwtPayloadAsync: getJwtPayloadAsync, cacheNewJwtPromise: cacheNewJwtPromise, encrypt: encrypt, decrypt: decrypt, appConfig: *}}
 */
module.exports = function (appConfig) {
    _appConfig = appConfig;

    return {
        getJwtPayload: getJwtPayload,
        createJwt: createJwt,
        getJwtCookie: getJwtCookie,
        createJwtPromise: createJwtPromise,
        deleteJwtCookie: deleteJwtCookie,
        deleteJwtCache: deleteJwtCache,
        setJwtCookie: setJwtCookie,
        isJwtValid: isJwtValid,
        isJwtValidAsync: isJwtValidAsync,
        getJwtPayloadAsync: getJwtPayloadAsync,
        cacheNewJwtPromise: cacheNewJwtPromise,
        encrypt: encrypt,
        decrypt: decrypt,
        appConfig: appConfig
    };
}
