var request = jest.fn((params, cb) => {
  request.__passedParams = params
  cb.apply(null, request.__callbackArgs)
})

request.__callbackArgs = [null, {}, { success: true }]

module.exports = request
