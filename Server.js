var cache = require('./lib/cache.js')
var util = require('./lib/utils.js')
var nosql = require('nosql')
var url = require('url')
var http = require('http')
var https = require('https')
var config = require('./config')
var fs = require('fs')
var xsh = require('node-xsh')

const shield = xsh({
  host: '127.0.0.1',
  port: '20103',
  https: false
})
shield.auth(config.XSH.rpcuser, config.XSH.rpcpassword)
if (config.XSH.encrypted) {
  shield.exec('walletpassphrase', config.XSH.walletpassphrase, 10000000, function (err, data) {
    if (err) console.log(err)
    console.log(data)
  })
}
// xsh.auth('test', 'muffin')

var usersDB = nosql.load('./Databases/user.nosql')
var sessionsDB = nosql.load('./Databases/sessions.nosql')
// var brutesDB = nosql.load('./Databases/brutes.nosql') // TODO: change the ddos counter to db

var adminExpire = [] // TODO: change to db
var adminTokens = []

util.unit_test(this)

function getErrorPage (errorcode) {
  // TODO: Cache maybe? Yeah
  switch (errorcode) {
    case 404:
      return fs.readFileSync('./errorcodes/404.html', 'binary')
    default:
      return fs.readFileSync('./errorcodes/' + String(errorcode) + '.html', 'binary')
  }
}

function log (msg, code) {
  util.log(msg, code)
}

function endsWith (str, suffix) {
  return str.indexOf(suffix, str.length - suffix.length) !== -1
}

String.prototype.replaceAll = function (search, replacement) { // eslint-disable-line no-extend-native
  var target = this
  return target.replace(new RegExp(search, 'g'), replacement)
}

function ClearOldSessions () {
  for (var i = 0; i === adminTokens.length; i++) {
    if (Number(adminExpire[i]) < Date.now()) {
      delete adminExpire[i]
      delete adminTokens[i]
      log('Removed an adminToken', 2)
    }
  }

  sessionsDB.remove().make(function (builder) {
    builder.where('expiretime', '<', Date.now())
    builder.callback(function (err, count) {
      if (err) {
        log("Can't remove sessions: " + String(err), 1)
      }
      if (count !== 0) {
        log('Removed sessions: ' + String(count), 2)
      }
    })
  })
}

var brutes = {
  counter: 0,
  ip: {},
  ban: {},
  ban_length: 0,
  interval: 0,
  maximum: 1e3,
  minutes: 5
}

function CheckIP (ip) { // True: disallow, false: allow
  if (brutes.ban_length > 0 && brutes.ban[brutes.req.ip]) {
    return true
  }
  var count = (brutes.ip[ip] || 0) + 1
  brutes.ip[ip] = count
  if (count === 1) brutes.counter++
  if (count < brutes.maximum) return false
  brutes.ban[ip] = brutes.minutes + 1
  brutes.ban_length++
  return true
}

setInterval(function () {
  brutes.interval++
  var keys
  var length
  var count
  if (brutes.ban_length > 0 && brutes.interval % 60 === 0) {
    keys = Object.keys(brutes.ban)
    length = keys.length
    count = 0
    for (var i = 0; i < length; i++) {
      var key = keys[i]
      if (brutes.ban[key]-- > 0) continue
      brutes.ban_length--
      delete brutes.ban[key]
    }
    if (brutes.ban_length < 0) brutes.ban_length = 0
  }
  if (brutes.counter <= 0) return
  keys = Object.keys(brutes.ip)
  length = keys.length
  brutes.counter = length
  for (i = 0; i < length; i++) {
    key = keys[i]
    count = brutes.ip[key]--
    if (count) {
      brutes.counter--
      delete brutes.ip[key]
    }
  }
  if (brutes.counter < 0) brutes.counter = 0
}, 1e3)

var pages

function SyncFiles () {
  cache.SyncCache().then(() => {
    pages = cache.getCachedFiles() // TODO: find more memory efficient way
    Object.keys(pages).forEach(function (val, i) {
      pages[val].content = pages[val].content
        .replace('{CAPTCHA}', util.GetCaptchaHTML())
        .replace('{FQDN}', config.FQDN || 'localhost') // if no FQDN default to
    })
  }).catch(() => {
    log("Couldn't update files in cache!", 1)
  })
}

fs.watch('./cachedHTML', SyncFiles)

cache.AddFileToCache('Login', require('path').join(__dirname, './cachedHTML/Login.html')).then(() => {
  cache.AddFileToCache('Dashboard', require('path').join(__dirname, './cachedHTML/Dashboard.html')).then(() => {
    cache.AddFileToCache('AdminDash', require('path').join(__dirname, './cachedHTML/AdminDash.html'))
    .then(SyncFiles)// Important for fast boot
    .catch(err => {
      log('Couldn\'t Cache page /Dashboard: ' + String(err), 2)
    })
  }).catch(err => {
    log('Couldn\'t Cache page /Login: ' + String(err), 2)
  })
}).catch(err => {
  log('Couldn\'t Cache page /Login: ' + String(err), 2)
})

setInterval(ClearOldSessions, 30000) // 30s update rate

// FIXME: overlapping with  `switch (require('path').extname(uri)) {`
var contentTypesByExtension = {
  '.html': 'text/html',
  '.css': 'text/css',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.svg': 'image/svg+xml',
  '.pdf': 'application/pdf'
}

function SSLoptions () {
  return {
    key: fs.readFileSync(config.SSL.key),
    cert: fs.readFileSync(config.SSL.cert),
    ca: fs.readFileSync(config.SSL.ca)
  }
}

util.fileExists(config.SSL.key, sslkey => {
  if (sslkey && !config.Testing) {
    https.createServer(SSLoptions(), TESTsubDomainSeperator).listen(config.Sockets.SSLPort)
    http.createServer((request, response) => { // Redirect http requests
      response.writeHead(301, { Location: 'https://' + config.FQDN + String(url.parse(request.url).pathname) })
      response.end()
    }).listen(config.Sockets.HTTPredirectPort)
    log('Web server running at => https://127.0.0.1:443/', 2)
    log('Redirect server running at => http://127.0.0.1:80/', 2)
  } else {
    http.createServer(TESTsubDomainSeperator).listen(config.Sockets.TestingPort)
    // log('Replica web server running at => http://127.0.0.1:' + String(config.Sockets.HTTPredirectPort) + '/', 2)
    log('Test web server running at => http://127.0.0.1:' + String(config.Sockets.TestingPort) + '/', 2)
  }
})

function TESTsubDomainSeperator (request, response) {
  var uri = url.parse(request.url).pathname
  switch (uri.split('/')[1]) { // localhost vs 127.0.0.1 >.<
    case 'api': // Using localhost you get api
      apiServer(request, response)
      break
    default: // Using full IP you get site
      mainServer(request, response)
      break
  }
}

function mainServer (request, response) {
  // Default variable initialization
  var uri = url.parse(request.url).pathname
  var cookies = util.parseCookies(request)
  var ipadress = request.connection.remoteAddress ||
    request.socket.remoteAddress ||
    (request.connection.socket ? request.connection.socket.remoteAddress : null)
  var Head = {}
  var ConstructHeader = function (add) {
    var nHead = {}
    Object.assign(nHead, Head, add)
    return nHead
  }

  switch (require('path').extname(uri)) {
    case '.html':
    case '.png':
    case '.svg':
    case '.css':
    case '.jpg':
    case '.ico':
    case '.get':
    case '.gif':
    case '.txt':
    case '.js':
      DeliverFile()
      break
    default:
      if (uri.split('/')[1].indexOf('.get') !== -1) DeliverFile()
      else {
        log('Updated: uri: ' + String(uri), 3)
        util.UpdateSession(sessionsDB, cookies['session'], {
          'currentUrl': uri
        }).then(head => {
          Head = ConstructHeader(head)
          cookies['session'] = String(head['Set-Cookie']).split('=')[1]
          DeliverFile()
        }).catch(err => {
          log('(Server.js:138) Cookies > ' + String(err), 1)
          DeliverFile()
        })
      }
      break
  }

  function DeliverPage (page, httpcode) {
    response.writeHead(httpcode, ConstructHeader({
      'Content-Type': 'text/html'
    }))
    response.write(page)
    response.end()
  }

  function DeliverFile () {
    if (CheckIP(ipadress)) return
    if (uri === '/') {
      util.Redirect(response, '/Login', {})
      return
    }
    if (uri.replace('.html', '').toLowerCase() === '/login') {
      util.getSession(sessionsDB, cookies['session']).then(resp => {
        if (resp.username !== '') {
          log('User has already logged in, session: ' + String(cookies['session']), 1)
          util.Redirect(response, '/Dashboard', {})
        } else {
          if (util.CheckIfIsPostReq(request)) {
            util.ProcessPostReq(request, response, function () {
              if (request.post.type === 'login') { // TODO: if not found (maybe check required parameters beforehand)
                log('Login got!', 2)
                util.ValidateCaptcha(request, !(resp.loginFails > 3)).then(() => {
                  util.GetUserVerified(usersDB, request.post.username, request.post.password).then(user => {
                    log('Logged in succesfully, response: ' + String(user.username), 2)
                    util.addSessionUsr(sessionsDB, cookies['session'], request.post.username.toLowerCase()).then(head => {
                      Head = ConstructHeader(head)
                      cookies['session'] = String(head['Set-Cookie']).split('=')[1]
                    }).catch(err => {
                      log('Error Applying sessionUsr to cookie: ' + String(err), 1)
                    })
                    util.Redirect(response, '/Dashboard', {})
                  }).catch(err => {
                    log('Login failed || ERROR: ' + String(err), 1)
                    util.addLoginFailsSession(sessionsDB, cookies['session']).then(resp => {
                      log('Session: ' + String(cookies['session']) + ' failed the login ' + String(resp) + 'x', 2)
                      if (resp >= 10) {
                        // TODO: Log brutes' ip
                        DeliverPage(util.AddJS(util.AddAntiBruteCaptcha(pages['Login'].content), util.gettoast('Username or Password Incorrect')), 200) // Captcha page if above 10 tries (maybe logged?)
                      } else if (resp > 3) {
                        DeliverPage(util.AddJS(util.AddAntiBruteCaptcha(pages['Login'].content), util.gettoast('Username or Password Incorrect')), 200) // Captcha page if above 3 tries
                      } else {
                        DeliverPage(util.AddJS(pages['Login'].content, util.gettoast('Username or Password Incorrect')), 200) // Normal Login page if under 3 tries
                      }
                    })
                  })
                }).catch(err => {
                  DeliverPage(util.AddJS(util.AddAntiBruteCaptcha(pages['Login'].content), util.gettoast('Error, did your captcha fail?')), 200)
                  log('Captcha: ' + String(err), 1)
                })
              } else if (request.post.type === 'privkey') { // PRIVATE KEY CHECKING
                DeliverPage(pages['Login'].content, 200) // TODO: change to real page + session
              } else if (request.post.type === 'signup') {
                util.ValidateCaptcha(request).then(() => {
                  if (request.post.username.length >= 5 && request.post.username.length <= 60 && request.post.password.length >= 8 && request.post.password.length <= 60 && request.password === request.confirmPasswordSignUp) {
                    util.GetUser(usersDB, request.post.username.toLowerCase()).then(() => {
                      DeliverPage(util.AddJS(pages['Login'].content, util.gettoast('That username already exists')), 200)
                    }).catch(() => { // Couldn't find a existing user with that username
                      usersDB.insert({
                        username: request.post.username.toLowerCase(), // TODO: check replacing
                        displayname: request.post.displayname,
                        password: util.HashPass(request.post.password, config.PassReq.SALTA, config.PassReq.SALTB),
                        type: 1
                      }).callback(function (err) {
                        log('A user has been created.', 2)
                        if (!err) {
                          shield.exec('getNewAddress', request.post.username.toLowerCase(), function (err, addr) {
                            if (err) {
                              log(String(err), 3)
                            }
                            util.addSessionUsr(sessionsDB, cookies['session'], request.post.username.toLowerCase()).then(head => {
                              Head = ConstructHeader(head)
                              cookies['session'] = String(head['Set-Cookie']).split('=')[1]
                            }).catch(err => {
                              log('Inserting usersDB: ' + String(err), 3)
                            })
                            util.Redirect(response, '/Dashboard', {})
                          })
                        }
                      })
                    })
                  } else { // Smartass trying to get past the javascript in the file itself (Lower than 4 char)
                    DeliverPage(util.AddJS(pages['Login'].content, util.gettoast('Invalid Username')), 200)
                    log('Invalid signup request: ' + request.post.username + ' | ' + request.post.password, 1)
                  }
                }).catch(err => {
                  DeliverPage(util.AddJS(pages['Login'].content, util.gettoast('Error, did the captcha fail?')), 200)
                  log('Captcha: ' + String(err), 1)
                })
              } else {
                // Just '/Login'
                DeliverPage(pages['Login'].content, 200)
              } // If post request but not a certain method ... goto Just '/Login'
            })
          } else {
            // Just '/Login'
            DeliverPage(pages['Login'].content, 200)
          }
        }
      }).catch(err => {
        log('Getting cookie /Login: "' + String(err) + '" Creating a new session', 1)
        DeliverPage(util.AddJS(pages['Login'].content, util.gettoast(cookies['session'] === undefined || cookies['session'] === '' ? 'Welcome' : 'Your session has expired, please try again.')), 200)
      })
    } else if (uri.toLowerCase() === '/logout') {
      log('Logging out session: ' + String(cookies['session']), 2)
      util.addSessionUsr(sessionsDB, cookies['session'], '').then(head => {
        Head = ConstructHeader(head)
        cookies['session'] = String(head['Set-Cookie']).split('=')[1]
      }).catch(err => {
        log('Logging out: ' + String(err), 1)
      })
      util.Redirect(response, '/Login', {})
    } else if (uri.replace('.html', '').toLowerCase() === '/dashboard') { // Show basic dashboard
      var stringy = ''
      util.getSession(sessionsDB, cookies['session']).then(resp => {
        if (resp.username === undefined || resp.username === '') {
          log('User hasn\'t logged in yet, session: ' + String(cookies['session']), 1)
          util.Redirect(response, '/Login', {})
        } else {
          util.GetUser(usersDB, resp.username).then(resp => {
            stringy = stringy + '\ninfo["userName"] = "' + String(resp.username) + '"'
            stringy = stringy + '\ninfo["displayName"] = "' + String(resp.displayname) + '"'

            if (resp.type >= 9) DeliverPage(util.AddJS(pages['Dashboard'].content.replaceAll('<li><a href="/">Home</a></li>', '<li><a href="/">Home</a></li>\n<li><a href="/AdminDash">AdminDash</a></li>'), stringy), 200)
            else DeliverPage(util.AddJS(pages['Dashboard'].content, stringy), 200)
          }).catch(err => {
            log('Getting user: ' + String(err), 1)
          })
        }
      }).catch(err => {
        log('Getting cookie: ' + String(err), 1)
        util.Redirect(response, '/Login', {})
      })
    } else if (uri.replace('.html', '').toLowerCase() === '/admindash') { // Show AdminDash.
      util.getSession(sessionsDB, cookies['session']).then(resp => {
        if (resp.username === undefined || resp.username === '') {
          log('User hasn\'t logged in yet, session: ' + String(cookies['session']), 1)
          util.Redirect(response, '/Login', {})
        } else {
          util.GetUser(usersDB, resp.username).then(resp => {
            if (resp.type >= 9) {  // When they have the right privileges deliver the actual site:
              adminExpire[adminTokens.length] = Date.now() + config.Sessions.SessionTime * 60000
              adminTokens[adminTokens.length] = String(util.randtext(16, config.PassReq.Mask).replace('#', '!'))
              util.GetUser(usersDB, resp.username).then(resp => {
                DeliverPage(pages['AdminDash'].content.replace('//PrivateToken//', adminTokens[adminTokens.length - 1]), 200)
              }).catch(err => {
                log('Getting user: ' + String(err), 1)
              })
            } else {
              log('User doesn\'t have the right privileges, session: ' + String(cookies['session']) + ' Privilege: ' + String(resp.type), 1)
              util.Redirect(response, '/Dashboard', {})
            }
          })
        }
      }).catch(err => {
        log('Getting cookie: ' + String(err), 1)
        util.Redirect(response, '/Login', {})
      })
    } else if (uri.toLowerCase().split('/')[1] === 'js') {
      let filename = require('path').join(__dirname, '/allowedJS', uri.toLowerCase().split('/')[2])
      fs.readFile(filename, 'binary', function (err, file) { // TODO: organize
        if (err) return DeliverPage('Internal Server error 500' + '\n', 500)
        response.writeHead(200, 'application/javascript')
        response.write(file)
        response.end()
      })
    } else if (util.IllegalAddressesCheck(require('path').join(__dirname, uri))) {
      var filename = require('path').join(__dirname, uri)
      util.fileExists(filename, function (exists) { // Deliver files like a normal human being
        if (!exists) {
          DeliverPage(getErrorPage(404), 404)
          return
        }

        if (fs.statSync(filename).isDirectory()) filename += '/index.html'

        fs.readFile(filename, 'binary', function (err, file) { // TODO: organize
          if (err) {
            DeliverPage('Internal Server error 500' + '\n', 500)
            return
          }

          var headers = {}
          var contentType = contentTypesByExtension[require('path').extname(filename)]
          if (contentType) headers['Content-Type'] = contentType
          else { // Filter unsupported file formats
            DeliverPage(getErrorPage(404), 404)
            return
          }

          // Deliver a standard file (with headers if html)
          if (endsWith(uri, '/') || endsWith(uri, '.html') || contentType === 'text/html') { // If it's a normal page
            response.writeHead(200, ConstructHeader(headers))
          } else {
            response.writeHead(200, headers)
          }
          response.write(file, 'binary')
          response.end()
        })
      })
    }
  }
}

function apiServer (request, response) {
  var ipadress = request.connection.remoteAddress ||
  request.socket.remoteAddress ||
  (request.connection.socket ? request.connection.socket.remoteAddress : null)
  if (CheckIP(ipadress)) return
  var uri = url.parse(request.url).pathname
  var args = util.GetArgumentsFromURI(uri)
  // console.log(uri.toLowerCase().split('/'), args)
  if (uri.toLowerCase().split('/')[2] === 'send') { // /api/send/<session>/<address>/<amount>
    util.CheckSessionUser(sessionsDB, usersDB, args[0]).then(x => {
      if (util.CheckStrNumber(args[2], 1)) { // TODO: max as real balance
        shield.exec('getbalance', x[0].username, function (err, balance) {
          if (err) {
            log(String(err), 3)
            util.APIResponseReturn(response, "Couldn't get addresses", 400)
            return
          }
          if (balance <= Number(args[2]) + 0.05) {
            util.APIResponseReturn(response, 'Not enough balance', 400)
            return
          }
          shield.exec('sendfrom', x[0].username, args[1], Number(args[2]), function (err, txid) {
            if (err) {
              log(String(err), 3)
              util.APIResponseReturn(response, "Couldn't broadcast transaction, do you have enough balance?", 400)
              return
            }
            util.APIResponseReturn(response, txid, 200)
          })
        })
      }
    }).catch(e => {
      util.APIResponseReturn(response, e, 400, false)
    })
  } else if (uri.toLowerCase().split('/')[2] === 'gettransactions') { // /api/gettransactions/<session>
    util.CheckSessionUser(sessionsDB, usersDB, args[0]).then(x => {
      shield.exec('listtransactions', x[0].username, function (err, txjson) {
        if (err) {
          log(String(err), 3)
          util.APIResponseReturn(response, "Couldn't get transactions", 500)
          return
        }
        util.APIResponseReturn(response, txjson, 200)
      })
    }).catch(e => {
      util.APIResponseReturn(response, e, 400, false)
    })
  } else if (uri.toLowerCase().split('/')[2] === 'getbalance') { // /api/gettransactions/<session>
    util.CheckSessionUser(sessionsDB, usersDB, args[0]).then(x => {
      shield.exec('getbalance', x[0].username, function (err, json) {
        if (err) {
          log(String(err), 3)
          util.APIResponseReturn(response, "Couldn't get addresses", 400)
          return
        }
        util.APIResponseReturn(response, json, 200)
      })
    }).catch(e => {
      util.APIResponseReturn(response, e, 400, false)
    })
  } else if (uri.toLowerCase().split('/')[2] === 'getaddresses') { // /api/gettransactions/<session>
    util.CheckSessionUser(sessionsDB, usersDB, args[0]).then(x => {
      shield.exec('getaddressesbyaccount', x[0].username, function (err, json) {
        if (err) {
          log(String(err), 3)
          util.APIResponseReturn(response, "Couldn't get addresses", 400)
          return
        }
        // console.log(x[0].username)
        util.APIResponseReturn(response, json, 200)
      })
    }).catch(e => {
      util.APIResponseReturn(response, e, 400, false)
    })
  } else if (uri.toLowerCase().split('/')[2] === 'addaddress') { // /api/gettransactions/<session>
    util.CheckSessionUser(sessionsDB, usersDB, args[0]).then(x => { // TODO: add error detection for core
      shield.exec('getaddressesbyaccount', x[0].username, function (err, txjson) {
        if (err) {
          log(String(err), 3)
          util.APIResponseReturn(response, "Couldn't get addresses", 400)
          return
        }
        if (txjson.length < 10) {
          shield.exec('getnewaddress', x[0].username, function (err, txjson) {
            if (err) {
              log(String(err), 3)
              util.APIResponseReturn(response, "Couldn't get addresses", 400)
              return
            }
            util.APIResponseReturn(response, txjson, 200)
          })
        }
      })
    }).catch(e => {
      util.APIResponseReturn(response, e, 400, false)
    })
  } else if (adminTokens.indexOf(uri.split('/')[2]) !== -1) {
    if (uri.split('/')[3] === 'remove') {
      var adminDeliver = 'AdminToken "' + uri.split('/')[2] + '" removed.'
      response.writeHead(200, 'Content-Type: text/plain')
      response.write(adminDeliver, 'binary')
      response.end()
      log('AdminToken "' + uri.split('/')[2] + '" removed.', 2)
      delete adminExpire[adminTokens.indexOf(uri.split('/')[2])]
      delete adminTokens[adminTokens.indexOf(uri.split('/')[2])]
    } else {
      util.getAdminDashInfo(sessionsDB).then(resp => {
        response.writeHead(200, {
          'Content-Type': 'application/json; charset=utf-8',
          'vary': 'Origin, Accept-Encoding',
          'pragma': 'no-cache'
            // 'access-control-allow-credentials': true
        })
        response.write(resp, 'utf8')
        response.end()
      }).catch(err => {
        log('Getting AdminDashInfo: ' + String(err))
        var adminDeliver = 'Fuck'
        response.writeHead(200, 'Content-Type: text/plain')
        response.write(adminDeliver, 'binary')
        response.end()
      })
    }
  } else {
    response.writeHead(404, 'Content-Type: text/plain')
    response.write('API not found', 'binary')
    response.end()
  }
}

log('Static file server running at \n  => http://localhost:' + String(443) + '/')
