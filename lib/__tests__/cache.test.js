/* eslint-disable standard/no-callback-literal */
var fs = require('fs')
var cache = require('../cache')
var originalGetCacheFile = cache.getCachedFiles
var realNow = new Date()
var realDateNow = Date.now

describe('cache', () => {
  var originalReadFile = fs.readFile
  beforeEach(() => {
    fs.readFile = jest.fn((filePath, ecnoding, cb) => {
      cb(null, filePath + ' content')
    })

    Date.now = jest.fn(() => realNow.getTime())
  })

  afterEach(() => {
    fs.readFile = originalReadFile
    Date.now = realDateNow
    cache.getCachedFiles = originalGetCacheFile
  })

  test('AddFileToCache', () => {
    return cache.AddFileToCache('afile', 'somepath').then(() => {
      expect(fs.readFile).toHaveBeenCalledWith('somepath', 'utf8', expect.any(Function))
      expect(cache.getCachedFiles()).toEqual({
        afile: {
          content: 'somepath content',
          path: 'somepath',
          timestamp: Date.now()
        }
      })
    })
  })

  test('AddFileToCache rejects', () => {
    fs.readFile.mockImplementation((f, e, cb) => cb('some error'))
    return cache.AddFileToCache('afile', 'somepath').then(() => {
      expect(false).toBe(true)
    })
      .catch(err => {
        expect(err).toBe('some error')
      })
  })

  test('SyncCache', () => {
    Date.now = jest.fn(() => 3333)
    cache.cachedFiles = {
      afile: {
        path: 'afilepath1',
        content: ''
      },
      bfile: {
        path: 'bfilepath1',
        content: ''
      }
    }
    return cache.SyncCache().then(() => {
      expect(fs.readFile).toHaveBeenCalledTimes(2)
      expect(fs.readFile).toHaveBeenCalledWith('afilepath1', 'utf8', expect.any(Function))
      expect(fs.readFile).toHaveBeenCalledWith('bfilepath1', 'utf8', expect.any(Function))
    })
  })

  test('SyncCache rejects', () => {
    fs.readFile.mockImplementation((f, e, cb) => cb('some error'))
    return cache.SyncCache().then(() => {
      expect(false).toBe(true)
    })
      .catch(err => {
        expect(err).toBe('some error')
      })
  })
})
