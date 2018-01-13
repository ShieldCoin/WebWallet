var fs = require('fs')
var cachedFiles = {}
// Every key has (key: {filecontent: data, filepath: /x/amp.le, timestamp: date.then})

module.exports = {
  // Example FS.AddFileToCache('welcome', '/README.md');
  AddFileToCache: function (name, filerpath) {
    return new Promise(function (resolve, reject) {
      fs.readFile(filerpath, 'utf8', function (err, data) {
        if (err) {
          console.log(err)
          reject(err)
        }
        cachedFiles[name] = {}
        cachedFiles[name]['content'] = data
        cachedFiles[name]['path'] = filerpath
        cachedFiles[name]['timestamp'] = Date.now()
        resolve()
      })
    })
  },

  SyncCache: function () {
    return Object.keys(cachedFiles).map(file => {
      return new Promise(function (resolve, reject) {
        fs.readFile(cachedFiles[file]['path'], 'utf8', function (err, data) {
          if (err) {
            console.log(err)
            return reject(err)
          }
          cachedFiles[file]['content'] = data
          cachedFiles[file]['timestamp'] = Date.now()
          resolve(cachedFiles[file]['filepath'])
        })
      })
    })
  },

  cachedFiles: cachedFiles

}
