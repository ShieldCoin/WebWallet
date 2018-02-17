var fs = require('fs')
// Every key has (key: {filecontent: data, filepath: /x/amp.le, timestamp: date.then})

var cache = module.exports = {
  // Example FS.AddFileToCache('welcome', '/README.md');
  AddFileToCache: function (name, filerpath) {
    return new Promise(function (resolve, reject) {
      fs.readFile(filerpath, 'utf8', function (err, data) {
        if (err) {
          console.log(err)
          reject(err)
        }
        cache.cachedFiles[name] = {}
        cache.cachedFiles[name]['content'] = data
        cache.cachedFiles[name]['path'] = filerpath
        cache.cachedFiles[name]['timestamp'] = Date.now()
        resolve()
      })
    })
  },

  SyncCache: function () {
    var readPromises = []
    Object.keys(cache.cachedFiles).map(file => {
      readPromises.push(new Promise((resolve, reject) => {
        fs.readFile(cache.cachedFiles[file]['path'], 'utf8', function (err, data) {
          if (err) {
            console.log(err)
            return reject(err)
          }
          cache.cachedFiles[file]['content'] = data
          cache.cachedFiles[file]['timestamp'] = Date.now()
          resolve(cache.cachedFiles[file]['filepath'])
        })
      }))
    })
    return Promise.all(readPromises)
  },

  cachedFiles: {},

  getCachedFiles: () => cache.cachedFiles

}
