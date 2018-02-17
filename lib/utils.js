'use strict'
var fs = require('fs')

function log (rawMSG, code) {
  // move date into function, otherwise it's not the current time
  var d = new Date()
  var timeStamp = '[' + d.getHours() + ':' + d.getMinutes() + '] '
  var msg = timeStamp + String(rawMSG)
  switch (String(code).toLowerCase()) {
    default:
    case '0':
      console.log('  | ' + msg)
      break
    case '1':
    case 'error':
    case 'e':
      console.log('E | ' + msg)
      break
    case '2':
    case 'update':
    case 'u':
      console.log('U | ' + msg)
      break
    case '3':
    case 'debug':
    case 'd':
      console.log('D | ' + msg)
      break
  }
}

function btoa (str) {
  var buffer

  if (str instanceof Buffer) {
    buffer = str
  } else {
    buffer = Buffer.from(str.toString(), 'binary')
  }

  return buffer.toString('base64')
}

String.prototype.hexToBase64 = function () { // eslint-disable-line no-extend-native
  var str = this
  return btoa(String.fromCharCode.apply(null,
    str.replace(/\r|\n/g, '').replace(/([\da-fA-F]{2}) ?/g, '0x$1 ').replace(/ +$/, '').split(' ')))
}

/**
 * generate random integer not greater than `max`
 */

function rand (max) {
  return Math.floor(Math.random() * max)
}

/**
 * generate random character of the given `set`
 */

function random (set) {
  return set[rand(set.length - 1)]
}

/**
 * generate an array with the given `length`
 * of characters of the given `set`
 */

function generate (length, set) {
  var result = []
  while (length--) result.push(random(set))
  return result
}

function shuffle (arr) {
  var result = []

  while (arr.length) {
    result = result.concat(arr.splice(rand[arr.length - 1]))
  }

  return result
}

// Settings

var config = require('../config.json')

var utils = module.exports = {

  unit_test: function (mainconxt) {
    var ut = require('./utils')
    var conf = require('../config.json')
    var assert = require('assert')
    assert.equal(ut.HashPass('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$*', conf.PassReq.SALTA, conf.PassReq.SALTB), '2qWaDLMka1s4EjsW9H9VEOsW8x0fMhFeoV64GztxkBo=',
      "Couln't pass hash test, do you have blakejs installed?")
  },

  log: function (msg, code) {
    log(msg, code)
  },

  // added this because fs.exists is deprecated
  fileExists: function (filePath, cb) {
    fs.stat(filePath, function fsStat (err, stats) {
      if (err) {
        if (err.code === 'ENOENT') {
          return cb(null, false)
        } else {
          return cb(err)
        }
      }
      return cb(null, stats.isFile())
    })
  },

  randtext: function (length, characters) {
    var result = [] // we need to ensure we have some characters
    result = result.concat(generate(length, characters)) // remaining - whatever

    return shuffle(result).join('') // shuffle and make a string
  },

  gettoast: function (text) {
    return 'Materialize.toast("' + text + '", 4000);'
  },

  /*
    Parses cookies en returns it as a list/dict
    */
  parseCookies: function (request) {
    var list = {}
    var rc = request.headers.cookie

    rc && rc.split(';').forEach(function (cookie) {
      var parts = cookie.split('=')
      list[parts.shift().trim()] = decodeURI(parts.join('='))
    })

    return list
  },

  /*
    Redirects user to said page
    */
  Redirect: function (response, topath = '/', Head = {}) {
    response.writeHead(302, Object.assign({
      'Location': topath,
      'Content-Type': 'text/html'
    }, Head))
    log('Redirecting to: ' + String(topath), 2)
    response.write("You're being redirected \n")
    response.end()
  },

  IllegalAddressesCheck: function (path) { // Checks if it a special website. So it doesn't double write or that you can still access it.
    switch (path.replace('.html', '').toLowerCase()) {
      // cases should be lower case
      case '/root/website/login':
      case '/root/website/dashboard':
        return false
    }
    return true
  },

  /*
    checks if request contains Post data
    */
  CheckIfIsPostReq: function (request) {
    return request.method === 'POST'
  },

  AddJS: function (str, Jstr) {
    for (var i = 2; i < arguments.length; i++) {
      str.replace('//EXTRAJS//', '//EXTRAJS//\n' + arguments[i])
    }
    return str.replace('//EXTRAJS//', '//EXTRAJS//\n' + Jstr)
  },

  // if not found will also reject(catch)
  GetUserVerified: function (db, username, password) {
    return new Promise(function (resolve, reject) {
      db.find().make(function (filter) {
        filter.first()
        filter.where('username', username.toLowerCase())
        filter.where('password', utils.HashPass(password, config.PassReq.SALTA, config.PassReq.SALTB))
        filter.callback((err, resp) => {
          if (err) {
            reject(err)
          }
          if (resp === undefined || resp === null) {
            reject(new Error('User/Password Not Found'))
          } else {
            resolve(resp)
          }
        })
      })
    })
  },

  // if not found will also reject(catch)
  GetUser: function (db, username) {
    return new Promise(function (resolve, reject) {
      db.find().make(function (filter) {
        filter.first()
        filter.where('username', username.toLowerCase())
        filter.callback((err, resp) => {
          if (err) {
            reject(err)
          }
          if (resp === undefined || resp === null) {
            reject(new Error('User Not Found'))
          } else {
            resolve(resp)
          }
        })
      })
    })
  },

  // S(B(Salt1) + B(Password) + S(Salt2))
  HashPass: function (PASSWORD, SALT1, SALT2) {
    try {
      var crypto = require('crypto')
      var blake = require('blakejs')
      var S1H = blake.blake2bHex(SALT1).hexToBase64()
      var S2H = crypto.createHash('sha256').update(SALT2).digest('base64')
      var P1H = blake.blake2bHex(PASSWORD).hexToBase64()
      var OL1 = blake.blake2bHex(S1H + P1H + S2H).hexToBase64()
      var OL2 = crypto.createHash('sha256').update(OL1).digest('base64')
      return OL2
    } catch (e) {
      log('Salty pass: ' + String(e), 1)
      return null
    }
  },

  AddAntiBruteCaptcha: function (str) {
    if (config.reCaptcha.enable && config.reCaptcha.SiteKey !== '' && config.reCaptcha.SecretKey !== '') {
      return str.replace('<!-- Extra Captcha -->', '<div class="g-recaptcha" data-sitekey="' + config.reCaptcha.SiteKey + '"></div>')
    } else {
      return str
    }
  },

  // Deprecated
  CreateCaptcha: function (callback) {
    var captcha = require('svg-captcha').create()
    callback(captcha)
    return captcha
  },

  GetCaptchaHTML: function () {
    if (config.reCaptcha.enable && config.reCaptcha.SiteKey !== '' && config.reCaptcha.SecretKey !== '') {
      return '<div class="g-recaptcha" data-sitekey="' + config.reCaptcha.SiteKey + '"></div>'
    } else {
      return ''
    }
  },

  ValidateCaptcha: function (request, SkipCondition = false) {
    return new Promise(function (resolve, reject) {
      if (!config.reCaptcha.enable || SkipCondition) { resolve() }
      if (request.post['g-recaptcha-response'] === undefined) {
        reject(new Error('Invalid Captcha'))
      }
      require('request')({
        method: 'POST',
        url: 'https://www.google.com/recaptcha/api/siteverify',
        form: {
          secret: config.reCaptcha.SecretKey,
          response: request.post['g-recaptcha-response']
        },
        json: true
      }, function (error, response, body) {
        if (error) {
          log('Captcha validatino: ' + error, 1)
          reject(new Error('Internal Server Error'))
          return
        }
        if (body['success']) {
          resolve()
          return
        }
        reject(new Error('Invalid Captcha'))
      })
    })
  },

  /*
    Processes Post request and puts it in request.post(if valid)
    */
  ProcessPostReq: function (request, response, callback) {
    var querystring = require('querystring')

    var queryData = ''
    if (typeof callback !== 'function') return null

    if (utils.CheckIfIsPostReq(request)) {
      request.on('data', function (data) {
        queryData += data
        if (queryData.length > 1e6) {
          queryData = ''
          response.writeHead(413, {
            'Content-Type': 'text/plain'
          }).end()
          request.connection.destroy()
        }
      })

      request.on('end', function () {
        request.post = querystring.parse(queryData)
        log('Request.end(): ', 3)
        callback()
      })
    } else {
      callback()
    }
  },

  getSession: function (sessiondb, sessionid) {
    return new Promise(function (resolve, reject) {
      sessiondb.find().make(function (filter) {
        filter.first()
        filter.where('session-id', sessionid)
        filter.callback((err, resp) => {
          if (err) {
            reject(err)
          } else if (resp === undefined || resp === null) {
            reject(new Error('Session-id Not Found: "' + String(sessionid) + '"'))
          } else {
            resolve(resp)
          }
        })
      })
    })
  },

  getAdminDashInfo: function (sessiondb) {
    return new Promise(function (resolve, reject) {
      sessiondb.find().make(function (filter) {
        filter.callback((err, resp) => {
          if (err) {
            reject(err)
          }

          var adminDeliver = {
            currentUsers: resp.length,
            currentSessions: {}
          }

          log('resp.Length: ' + String(resp.length), 3)
          log('resp[' + String(resp.length <= 0), 3)
          resp.forEach(entry => {
            adminDeliver.currentSessions[entry['session-id']] = entry
          })

          resolve(JSON.stringify(adminDeliver))
        })
      })
    })
  },

  addLoginFailsSession: function (sessiondb, sessionid) { // Modify and update sessions
    return new Promise(function (resolve, reject) {
      sessiondb.find().make(function (filter) {
        filter.first()
        filter.where('session-id', sessionid)
        filter.callback((err, resp) => {
          if (err) {
            reject(err)
          } else if (resp === undefined || resp === null) {
            reject(new Error('In addLoginFails(), session-id not found! ' + String(sessionid)))
          } else {
            var newValue = resp.loginFails + 1
            sessiondb.modify({
              'loginFails': newValue,
              'expiretime': Date.now() + config.Sessions.SessionTime * 60000
            }).make(function (builder) {
              builder.first()
              builder.where('session-id', sessionid)
              builder.callback((err, count) => {
                if (err) {
                  log('Modifying session: ' + String(err), 1)
                  reject(err)
                } else {
                  resolve(newValue)
                }
              })
            })
          }
        })
      })
    })
  },

  addBrutesIP: function (sessiondb, ip) {

  },

  // Not really needed imo // WY NOT!? :(
  addSessionUsr: function (sessiondb, sessionid, username) { // Yes it is different as that it REQUIRES an username instead of any
    return new Promise(function (resolve, reject) {
      // user lowercase version of username in database
      username = username.toLowerCase()
      var newSessionId

      if (sessionid === undefined || sessionid === '') {
        utils.insertSession(sessiondb, { username }).then(nsid => {
          resolve({
            'Set-Cookie': 'session=' + nsid
          })
        })
      } else {
        newSessionId = sessionid
        // Session expired/already exist, trying to update the timeout - totally original
        sessiondb.modify({
          'username': username,
          'expiretime': Date.now() + config.Sessions.SessionTime * 60000
        }).make(function (builder) {
          builder.first()
          builder.where('session-id', sessionid)
          builder.callback((err, count) => {
            if (err) {
              log('Session adduser modify: ' + String(err), 1)
              reject(err)
            }
            if (count === 0) {
              utils.insertSession(sessiondb, { username }).then(nsid => {
                resolve({
                  'Set-Cookie': 'session=' + nsid
                })
              })
            } else {
              resolve({
                'Set-Cookie': 'session=' + newSessionId
              })
            }
          })
        })
      }
    })
  },

  CheckSessionUser: function (sessionsDB, usersDB, sessionid) {
    var session
    return utils.getSession(sessionsDB, sessionid).then(x => {
      session = x
      if (x.username !== undefined && x.username !== '') {
        return utils.GetUser(usersDB, x.username)
      }
      // util.APIResponseReturn(response, "Couldn't find session", 400, false)
      throw new Error("Couldn't find session")
    })
      .then(u => {
        if (u !== undefined) {
          return [session, u]
        }

        throw new Error("Couldn't find session")
      })
      .catch(() => {
        // util.APIResponseReturn(response, "Couldn't find session", 400, false)
        throw new Error("Couldn't find session")
      })
  },

  CheckStrNumber: function (number, min = 0, max = 1e+8) {
    var amount = Number(number)
    if (amount === undefined || isNaN(amount)) {
      return false
    }
    if (amount <= min) {
      return false
    }
    if (amount >= max) {
      return false
    }
    return true
  },

  GetArgumentsFromURI: function (str) {
    return str.split('/').splice(3)
  },

  APIResponseReturn: function (response, stat, code) {
    response.writeHead(code, {
      'Content-Type': 'application/json; charset=utf-8',
      'vary': 'Origin, Accept-Encoding',
      'pragma': 'no-cache',
      'access-control-allow-credentials': true,
      'Access-Control-Allow-Origin': 'true'
    })
    response.write(JSON.stringify({'Content': stat, 'StatusCode': code}), 'utf8')
    response.end()
  },

  // Move this to a separate method since it's being used a various places
  insertSession: function (sessiondb, extraInfo) {
    return new Promise(function (resolve, reject) {
      try {
        var nses = utils.randtext(config.PassReq.Length, config.PassReq.Mask)
        if (typeof extraInfo.username === 'string') {
          extraInfo.username = extraInfo.username.toLowerCase()
        }
        sessiondb.insert(Object.assign({}, {
          'session-id': nses,
          'username': '',
          'expiretime': Date.now() + config.Sessions.SessionTime * 60000,
          'loginFails': 0
        }, extraInfo))

        resolve(nses)
      } catch (err) {
        reject(err)
      }
    })
  },

  UpdateSession: function (sessiondb, sessionid, extraInfo) {
    if (sessionid === undefined || sessionid === '') {
      return utils.insertSession(sessiondb, extraInfo).then(newSessionId => {
        log('New session: ' + String(newSessionId), 2)
        return {
          'Set-Cookie': 'session=' + newSessionId
        }
      })
    }

    return new Promise(function (resolve, reject) {
      // Session expired/already exist, trying to update the timeout
      sessiondb.modify(Object.assign({}, {
        'expiretime': Date.now() + config.Sessions.SessionTime * 60000
      }, extraInfo)).make(function (builder) {
        builder.first()
        builder.where('session-id', sessionid)
        builder.callback((err, count) => {
          if (err) {
            log('Session modify updateSession(): ' + String(err), 1)
            reject(err)
          }
          if (count === 0) {
            utils.insertSession(sessiondb, extraInfo).then(newSessionId => {
              log('New session: ' + String(newSessionId), 2)
              resolve({
                'Set-Cookie': 'session=' + newSessionId
              })
            })
          } else {
            log('updated session', 2)
            resolve({
              'Set-Cookie': 'session=' + sessionid
            })
          }
        })
      })
    })
  }
}
