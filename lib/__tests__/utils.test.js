/* eslint-disable standard/no-callback-literal */
var utils = require('../utils')
var realNow = new Date()
var realDateNow = Date.now

var requestLib = require('request')
jest.mock('request')

describe('utils', () => {
  var originalConsoleLog = console.log

  beforeEach(() => {
    console.log = jest.fn()
  })

  afterEach(() => {
    console.log = originalConsoleLog
  })

  describe('log()', () => {
    it('logs code 0', () => {
      var d = new Date()
      utils.log('something', 0)
      expect(console.log).toHaveBeenLastCalledWith(`  | [${d.getHours()}:${d.getMinutes()}] something`)
    })

    it('logs code error', () => {
      var d = new Date()
      utils.log('something', 'error')
      expect(console.log).toHaveBeenLastCalledWith(`E | [${d.getHours()}:${d.getMinutes()}] something`)
    })

    it('logs code u', () => {
      var d = new Date()
      utils.log('something', 'u')
      expect(console.log).toHaveBeenLastCalledWith(`U | [${d.getHours()}:${d.getMinutes()}] something`)
    })

    it('logs code 3', () => {
      var d = new Date()
      utils.log('something', '3')
      expect(console.log).toHaveBeenLastCalledWith(`D | [${d.getHours()}:${d.getMinutes()}] something`)
    })
  })

  describe('random-ness functions', () => {
    var originalMathRandom = Math.random
    beforeEach(() => {
      Math.random = jest.fn(() => 0.5)
    })

    afterEach(() => {
      Math.random = originalMathRandom
    })

    test('randtext', () => {
      expect(utils.randtext(10, 'abcdef')).toBe('cccccccccc')
    })
  })

  it('adds hexToBase64 to String.prototype', () => {
    expect(String.prototype.hexToBase64).toBeInstanceOf(Function)
    expect('0x124a98224fd8d6d4d7b6d53459dc08a4142cc3ac'.hexToBase64()).toBe('AEqYIk/Y1tTXttU0WdwIpBQsw6w=')
  })

  it('parses cookie strings', () => {
    expect(utils.parseCookies({
      headers: { cookie: '' }
    })).toEqual({})

    expect(utils.parseCookies({
      headers: { cookie: 'some=thing; encoded=cookie%20with%20space' }
    })).toEqual({
      some: 'thing',
      encoded: 'cookie with space'
    })
  })

  test('AddJS', () => {
    expect(utils.AddJS('<div>//EXTRAJS//</div>', 'final', 'another', 'plusone')).toBe(`<div>//EXTRAJS//
final</div>`)
  })

  test('Redirect', () => {
    var response = {
      writeHead: jest.fn(),
      write: jest.fn(),
      end: jest.fn()
    }
    utils.Redirect(response, '/something', { 'X-Some-Header': 'val' })
    expect(response.writeHead).toHaveBeenCalledWith(302, {
      'X-Some-Header': 'val',
      'Location': '/something',
      'Content-Type': 'text/html'
    })
    expect(response.write).toHaveBeenCalledWith('You\'re being redirected \n')
    expect(response.end).toHaveBeenCalledTimes(1)
  })

  test('Redirect with defaults', () => {
    var response = {
      writeHead: jest.fn(),
      write: jest.fn(),
      end: jest.fn()
    }
    utils.Redirect(response)
    expect(response.writeHead).toHaveBeenCalledWith(302, {
      'Location': '/',
      'Content-Type': 'text/html'
    })
    expect(response.write).toHaveBeenCalledWith('You\'re being redirected \n')
    expect(response.end).toHaveBeenCalledTimes(1)
  })

  test('IllegalAddressesCheck', () => {
    var testCases = {
      '/root/Website/Login.html': false,
      '/root/Website/Dashboard': false,
      '/anything/Else': true
    }

    Object.keys(testCases).forEach(p => expect(utils.IllegalAddressesCheck(p)).toBe(testCases[p]))
  })

  test('CheckIfIsPostReq', () => {
    expect(utils.CheckIfIsPostReq({ method: 'POST' })).toBe(true)
    expect(utils.CheckIfIsPostReq({ method: 'GET' })).toBe(false)
  })

  test('HashPass', () => {
    expect(utils.HashPass('something', 'abc', '123')).toBe('MnuAWj2ca2YMEf2aB1E+FGHrgCSo5+kKXUS+dKcm2ts=')
  })

  test('APIResponseReturn', () => {
    var response = {
      writeHead: jest.fn(),
      write: jest.fn(),
      end: jest.fn()
    }
    utils.APIResponseReturn(response, 'content', 201)
    expect(response.writeHead).toHaveBeenCalledWith(201, {
      'Content-Type': 'application/json; charset=utf-8',
      'vary': 'Origin, Accept-Encoding',
      'pragma': 'no-cache',
      'access-control-allow-credentials': true,
      'Access-Control-Allow-Origin': 'true'
    })

    expect(response.write).toHaveBeenCalledWith(JSON.stringify({
      Content: 'content',
      StatusCode: 201
    }), 'utf8')

    expect(response.end).toHaveBeenCalledTimes(1)
  })

  test('ProcessPostReq with POST req', done => {
    var request = {
      method: 'POST',
      on: jest.fn((ev, cb) => {
        if (ev === 'data') {
          cb('some%20data=blah')
        } else if (ev === 'end') {
          cb()
        }
      })
    }

    var response = {
      writeHead: jest.fn(),
      write: jest.fn(),
      end: jest.fn()
    }

    utils.ProcessPostReq(request, response, () => {
      expect(request.on).toHaveBeenCalledTimes(2)
      expect(request.on).toHaveBeenCalledWith('data', expect.any(Function))
      expect(request.on).toHaveBeenCalledWith('end', expect.any(Function))
      expect(response.writeHead).not.toHaveBeenCalled()
      expect(request.post).toEqual({ 'some data': 'blah' })
      done()
    })
  })

  test('ProcessPostReq with non-POST req', done => {
    var request = {
      method: 'GET',
      on: jest.fn((ev, cb) => {
        if (ev === 'data') {
          cb('some%20data=blah')
        } else if (ev === 'end') {
          cb()
        }
      })
    }

    var response = {
      writeHead: jest.fn(),
      write: jest.fn(),
      end: jest.fn()
    }

    utils.ProcessPostReq(request, response, () => {
      expect(request.on).not.toHaveBeenCalled()
      expect(response.writeHead).not.toHaveBeenCalled()
      expect(request.post).toBeUndefined()
      done()
    })
  })

  test('gettoast', () => {
    expect(utils.gettoast('something')).toBe('Materialize.toast("something", 4000);')
  })

  test('GetCaptchaHTML', () => {
    expect(utils.GetCaptchaHTML()).toBe('<div class="g-recaptcha" data-sitekey="6Lc9EjwUAAAAANfjQw3Oe9DqscD3o_Axs2vN7c5a"></div>')
  })

  test('AddAntiBruteCaptcha', () => {
    var html = '<div><!-- Extra Captcha --></div>'
    expect(utils.AddAntiBruteCaptcha(html)).toBe('<div><div class="g-recaptcha" data-sitekey="6Lc9EjwUAAAAANfjQw3Oe9DqscD3o_Axs2vN7c5a"></div></div>')
  })

  test('file exists', done => {
    var thisFile = require('path').resolve(__dirname, __filename)
    utils.fileExists(thisFile, (err, doesExist) => {
      expect(err).toBe(null)
      expect(doesExist).toBe(true)
      done()
    })
  })

  test('GetArgumentsFromURI', () => {
    expect(utils.GetArgumentsFromURI('/blah/dah/arg')).toEqual(['arg'])
  })

  test('file does not exist', done => {
    var thisFile = '/some/file/that/probably/doesnot/exist.html'
    utils.fileExists(thisFile, (err, doesExist) => {
      expect(err).toBe(null)
      expect(doesExist).toBe(false)
      done()
    })
  })

  test('CheckStrNumber', () => {
    expect(utils.CheckStrNumber()).toBe(false)
    expect(utils.CheckStrNumber(10)).toBe(true)
    expect(utils.CheckStrNumber(20, 0, 10)).toBe(false)
    expect(utils.CheckStrNumber(10, 20, 10)).toBe(false)
  })

  describe('ValidateCaptcha', () => {
    it('resolves if SkipCondition is true', () => {
      return utils.ValidateCaptcha({}, true).then(res => {
        expect(res).toBeUndefined()
      })
    })

    it('resolves on success', () => {
      return utils.ValidateCaptcha({
        post: {
          'g-recaptcha-response': 'blah'
        }
      })
        .then(() => {
          expect(requestLib).toHaveBeenCalledWith({
            method: 'POST',
            url: 'https://www.google.com/recaptcha/api/siteverify',
            form: {
              secret: '6Lc9EjwUAAAAAK14Sbj3RO2bsWJ0ZEWRqeiognK_',
              response: 'blah'
            },
            json: true
          }, expect.any(Function))
        })
    })

    it('rejects on request error', () => {
      requestLib.__callbackArgs = ['some error']
      return utils.ValidateCaptcha({
        post: {
          'g-recaptcha-response': 'blah'
        }
      })
        .then(() => {
          expect(false).toBe(true)
        })
        .catch(err => {
          expect(err.message).toBe('Internal Server Error')
        })
    })

    it('rejects if body.success is not truthy', () => {
      requestLib.__callbackArgs = [null, {}, {}]
      return utils.ValidateCaptcha({
        post: {
          'g-recaptcha-response': 'blah'
        }
      })
        .then(() => {
          expect(false).toBe(true)
        })
        .catch(err => {
          expect(err.message).toBe('Invalid Captcha')
        })
    })

    it('rejects if g-recaptcha-response is undefined', () => {
      requestLib.__callbackArgs = [null, {}, {}]
      return utils.ValidateCaptcha({
        post: {}
      })
        .then(() => {
          expect(false).toBe(true)
        })
        .catch(err => {
          expect(err.message).toBe('Invalid Captcha')
        })
    })
  })

  describe('database functions', () => {
    var db
    var dbMake
    var dbFilter
    var dbBuilder
    var originalHashPass = utils.HashPass

    beforeEach(() => {
      Date.now = jest.fn(() => realNow.getTime())
      utils.HashPass = jest.fn(() => 'hashed_password')
      dbBuilder = {
        first: jest.fn(),
        where: jest.fn(),
        callback: jest.fn(cb => {
          cb(null, 1)
        })
      }

      dbFilter = {
        first: jest.fn(),
        where: jest.fn(),
        callback: jest.fn(cb => {
          cb(null, 'response')
        })
      }

      dbMake = jest.fn(cb => cb(dbFilter))

      db = {
        find: jest.fn(() => ({ make: dbMake })),
        modify: jest.fn(() => ({ make: jest.fn(cb => cb(dbBuilder)) })),
        insert: jest.fn()
      }
    })

    afterEach(() => {
      utils.HashPass = originalHashPass
      Date.now = realDateNow
    })

    describe('GetUserVerified', () => {
      it('resolves with a successful response', () => {
        return utils.GetUserVerified(db, 'Username', 'pass').then(res => {
          expect(db.find).toHaveBeenCalledTimes(1)
          expect(dbMake).toHaveBeenCalledTimes(1)
          expect(dbFilter.first).toHaveBeenCalledTimes(1)
          expect(dbFilter.where).toHaveBeenCalledTimes(2)
          expect(dbFilter.where).toHaveBeenCalledWith('username', 'username')
          expect(dbFilter.where).toHaveBeenCalledWith('password', 'hashed_password')
          expect(utils.HashPass).toHaveBeenCalledWith('pass', 'V@$98nyVRQWwn9y8', 'VW(B)v1b9A9wi74p')
          expect(res).toBe('response')
        })
      })

      it('rejects if not found', () => {
        dbFilter.callback.mockImplementation(cb => cb(null, null))
        return utils.GetUserVerified(db, 'blah', 'dah').then(res => {
          expect(res).not.toBeDefined()
        })
          .catch(err => {
            expect(err.message).toBe('User/Password Not Found')
          })
      })

      it('rejects on error', () => {
        dbFilter.callback.mockImplementation(cb => cb('some error', null)) // eslint-disable-line standard/no-callback-literal
        return utils.GetUserVerified(db, 'blah', 'dah').then(res => {
          expect(res).not.toBeDefined()
        })
          .catch(err => {
            expect(err).toBe('some error')
          })
      })
    })

    describe('GetUser', () => {
      it('gets user by username', () => {
        return utils.GetUser(db, 'Username').then(res => {
          expect(db.find).toHaveBeenCalledTimes(1)
          expect(dbMake).toHaveBeenCalledTimes(1)
          expect(dbFilter.first).toHaveBeenCalledTimes(1)
          expect(dbFilter.where).toHaveBeenCalledTimes(1)
          expect(dbFilter.where).toHaveBeenCalledWith('username', 'username')
          expect(res).toBe('response')
        })
      })

      it('rejects if not found', () => {
        dbFilter.callback.mockImplementation(cb => cb(null, null))
        return utils.GetUser(db, 'blah').then(res => {
          expect(res).not.toBeDefined()
        })
          .catch(err => {
            expect(err.message).toBe('User Not Found')
          })
      })

      it('rejects on error', () => {
        dbFilter.callback.mockImplementation(cb => cb('some error', null)) // eslint-disable-line standard/no-callback-literal
        return utils.GetUser(db, 'blah').then(res => {
          expect(res).not.toBeDefined()
        })
          .catch(err => {
            expect(err).toBe('some error')
          })
      })
    })

    describe('getSession', () => {
      it('gets session by session id', () => {
        return utils.getSession(db, 'session_id').then(res => {
          expect(db.find).toHaveBeenCalledTimes(1)
          expect(dbMake).toHaveBeenCalledTimes(1)
          expect(dbFilter.first).toHaveBeenCalledTimes(1)
          expect(dbFilter.where).toHaveBeenCalledTimes(1)
          expect(dbFilter.where).toHaveBeenCalledWith('session-id', 'session_id')
          expect(res).toBe('response')
        })
      })

      it('rejects if not found', () => {
        dbFilter.callback.mockImplementation(cb => cb(null, null))
        return utils.getSession(db, 'blah').then(res => {
          expect(res).not.toBeDefined()
        })
          .catch(err => {
            expect(err.message).toBe('Session-id Not Found: "blah"')
          })
      })

      it('rejects on error', () => {
        dbFilter.callback.mockImplementation(cb => cb('some error', null)) // eslint-disable-line standard/no-callback-literal
        return utils.getSession(db, 'blah').then(res => {
          expect(res).not.toBeDefined()
        })
          .catch(err => {
            expect(err).toBe('some error')
          })
      })
    })

    describe('getAdminDashInfo', () => {
      it('gets JSON of current info', () => {
        dbFilter.callback.mockImplementation(cb => {
          var info = [{
            'session-id': 'sesh_id',
            other: 'stuff'
          }]
          cb(null, info)
        })
        return utils.getAdminDashInfo(db).then(res => {
          expect(db.find).toHaveBeenCalledTimes(1)
          expect(dbMake).toHaveBeenCalledTimes(1)
          expect(JSON.parse(res)).toEqual({
            currentUsers: 1,
            currentSessions: {
              'sesh_id': {
                'session-id': 'sesh_id',
                other: 'stuff'
              }
            }
          })
        })
      })

      it('rejects on error', () => {
        dbFilter.callback.mockImplementation(cb => cb('some error', null)) // eslint-disable-line standard/no-callback-literal
        return utils.getAdminDashInfo(db).then(res => {
          expect(res).not.toBeDefined()
        })
          .catch(err => {
            expect(err).toBe('some error')
          })
      })
    })

    describe('addLoginFailsSession', () => {
      it('gets session by session id', () => {
        dbFilter.callback.mockImplementation(cb => cb(null, { loginFails: 1 }))
        return utils.addLoginFailsSession(db, 'session_id').then(res => {
          expect(db.find).toHaveBeenCalledTimes(1)
          expect(dbMake).toHaveBeenCalledTimes(1)
          expect(dbFilter.first).toHaveBeenCalledTimes(1)
          expect(dbFilter.where).toHaveBeenCalledTimes(1)
          expect(dbFilter.where).toHaveBeenCalledWith('session-id', 'session_id')
          expect(db.modify).toHaveBeenCalledTimes(1)
          expect(db.modify).toHaveBeenLastCalledWith({
            loginFails: 2,
            expiretime: Date.now() + 15 * 60000
          })
          expect(dbBuilder.first).toHaveBeenCalledTimes(1)
          expect(dbBuilder.where).toHaveBeenLastCalledWith('session-id', 'session_id')
          expect(dbBuilder.callback).toHaveBeenCalledTimes(1)
          expect(res).toBe(2)
        })
      })

      it('rejects if not found', () => {
        dbFilter.callback.mockImplementation(cb => cb(null, null))
        return utils.addLoginFailsSession(db, 'blah').then(res => {
          expect(res).not.toBeDefined()
        })
          .catch(err => {
            expect(err.message).toBe('In addLoginFails(), session-id not found! blah')
          })
      })

      it('rejects if builder has error', () => {
        dbBuilder.callback.mockImplementation(cb => cb('some error', null)) // eslint-disable-line standard/no-callback-literal
        return utils.addLoginFailsSession(db, 'blah').then(res => {
          expect(res).not.toBeDefined()
        })
          .catch(err => {
            expect(err).toBe('some error')
          })
      })

      it('rejects on error', () => {
        dbFilter.callback.mockImplementation(cb => cb('some error', null)) // eslint-disable-line standard/no-callback-literal
        return utils.addLoginFailsSession(db, 'blah').then(res => {
          expect(res).not.toBeDefined()
        })
          .catch(err => {
            expect(err).toBe('some error')
          })
      })
    })

    describe('addSessionUsr', () => {
      var originalInsertSession = utils.insertSession

      beforeEach(() => {
        utils.insertSession = jest.fn(() => Promise.resolve('new_sesh_id'))
      })

      afterEach(() => {
        utils.insertSession = originalInsertSession
      })

      it('adds new session', () => {
        return utils.addSessionUsr(db, '', 'Bob').then(res => {
          expect(res).toEqual({
            'Set-Cookie': 'session=new_sesh_id'
          })

          expect(utils.insertSession).toHaveBeenCalledWith(db, { username: 'bob' })
        })
      })

      it('updates existing session', () => {
        dbBuilder.callback.mockImplementation(cb => cb(null, 1))
        return utils.addSessionUsr(db, 'sesh_id', 'Bob').then(res => {
          expect(res).toEqual({
            'Set-Cookie': 'session=sesh_id'
          })

          expect(db.insert).not.toHaveBeenCalled()
          expect(db.modify).toHaveBeenLastCalledWith({
            username: 'bob',
            expiretime: Date.now() + 15 * 60000
          })
        })
      })

      it('adds new session if session-id is not found', () => {
        dbBuilder.callback.mockImplementation(cb => cb(null, 0))
        return utils.addSessionUsr(db, 'sesh_id', 'Bob').then(res => {
          expect(res).toEqual({
            'Set-Cookie': 'session=new_sesh_id'
          })

          expect(utils.insertSession).toHaveBeenCalledWith(db, { username: 'bob' })
        })
      })
    })

    describe('CheckSesssionUser', () => {
      var originalGetSession = utils.getSession
      var originalGetUser = utils.GetUser

      beforeEach(() => {
        utils.getSession = jest.fn(() => Promise.resolve({ username: 'bob' }))
        utils.GetUser = jest.fn(() => Promise.resolve({ user: 'obj' }))
      })

      afterEach(() => {
        utils.getSession = originalGetSession
        utils.GetUser = originalGetUser
      })

      it('resolves session and user', () => {
        return utils.CheckSessionUser(db, db, 'sesh_id').then(res => {
          expect(res).toEqual([{ username: 'bob' }, { user: 'obj' }])
          expect(utils.getSession).toHaveBeenLastCalledWith(db, 'sesh_id')
          expect(utils.GetUser).toHaveBeenLastCalledWith(db, 'bob')
        })
      })

      it('rejects if session not found', () => {
        utils.getSession.mockImplementation(() => Promise.reject(new Error('not found')))
        return utils.CheckSessionUser(db, db, 'sesh_id').then(() => {
          expect(true).toBe(false)
        })
          .catch(err => {
            expect(err.message).toBe("Couldn't find session")
            expect(utils.getSession).toHaveBeenLastCalledWith(db, 'sesh_id')
            expect(utils.GetUser).not.toHaveBeenCalled()
          })
      })

      it('rejects if user not found', () => {
        utils.GetUser.mockImplementation(() => Promise.reject(new Error('not found')))
        return utils.CheckSessionUser(db, db, 'sesh_id').then(() => {
          expect(true).toBe(false)
        })
          .catch(err => {
            expect(err.message).toBe("Couldn't find session")
            expect(utils.getSession).toHaveBeenLastCalledWith(db, 'sesh_id')
            expect(utils.GetUser).toHaveBeenLastCalledWith(db, 'bob')
          })
      })

      it('rejects if GetUser resolves to undefined', () => {
        utils.GetUser.mockImplementation(() => Promise.resolve())
        return utils.CheckSessionUser(db, db, 'sesh_id').then(() => {
          expect(true).toBe(false)
        })
          .catch(err => {
            expect(err.message).toBe("Couldn't find session")
            expect(utils.getSession).toHaveBeenLastCalledWith(db, 'sesh_id')
            expect(utils.GetUser).toHaveBeenLastCalledWith(db, 'bob')
          })
      })
    })

    describe('insertSession', () => {
      var originalRandText = utils.randtext

      beforeEach(() => {
        utils.randtext = jest.fn(() => 'random_text')
      })

      afterEach(() => {
        utils.randtext = originalRandText
      })

      it('resolves new session id', () => {
        return utils.insertSession(db, { username: 'Bob' }).then(res => {
          expect(res).toBe('random_text')
          expect(utils.randtext).toHaveBeenLastCalledWith(15, 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!$*')
          expect(db.insert).toHaveBeenLastCalledWith({
            'session-id': 'random_text',
            username: 'bob',
            expiretime: Date.now() + 15 * 60000,
            loginFails: 0
          })
        })
      })
    })

    describe('UpdateSession', () => {
      var originalInsertSession = utils.insertSession

      beforeEach(() => {
        utils.insertSession = jest.fn(() => Promise.resolve('new_sesh_id'))
      })

      afterEach(() => {
        utils.insertSession = originalInsertSession
      })

      it('adds new session', () => {
        return utils.UpdateSession(db, '', {}).then(res => {
          expect(res).toEqual({
            'Set-Cookie': 'session=new_sesh_id'
          })

          expect(utils.insertSession).toHaveBeenLastCalledWith(db, {})
        })
      })

      it('updates existing session', () => {
        dbBuilder.callback.mockImplementation(cb => cb(null, 1))
        return utils.UpdateSession(db, 'sesh_id', {}).then(res => {
          expect(res).toEqual({
            'Set-Cookie': 'session=sesh_id'
          })

          expect(db.insert).not.toHaveBeenCalled()
          expect(db.modify).toHaveBeenLastCalledWith({
            expiretime: Date.now() + 15 * 60000
          })
          expect(dbBuilder.first).toHaveBeenCalledTimes(1)
          expect(dbBuilder.where).toHaveBeenLastCalledWith('session-id', 'sesh_id')
          expect(dbBuilder.callback).toHaveBeenCalledTimes(1)
        })
      })

      it('adds new session if session-id is not found', () => {
        dbBuilder.callback.mockImplementation(cb => cb(null, 0))
        return utils.UpdateSession(db, 'sesh_id', { username: 'bob' }).then(res => {
          expect(res).toEqual({
            'Set-Cookie': 'session=new_sesh_id'
          })

          expect(db.modify).toHaveBeenLastCalledWith({
            expiretime: Date.now() + 15 * 60000,
            username: 'bob'
          })
          expect(dbBuilder.first).toHaveBeenCalledTimes(1)
          expect(dbBuilder.where).toHaveBeenLastCalledWith('session-id', 'sesh_id')
          expect(dbBuilder.callback).toHaveBeenCalledTimes(1)

          expect(utils.insertSession).toHaveBeenLastCalledWith(db, { username: 'bob' })
        })
      })
    })
  })
})
