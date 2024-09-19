/* 产引入jsencrypt实现数据RSA加密 */
// import JSEncrypt from 'nodejs-jsencrypt' // 处理长文本数据时报错 jsencrypt.js Message too long for RSA
/* 产引入encryptlong实现数据RSA加密 */
// import Encrypt from 'encryptlong' // encryptlong是基于jsencrypt扩展的长文本分段加解密功能。

// 公钥key
const publicKey='MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCLW9UzjKEyztUcBD/GtLvzHNPCSpcjECjeeSfI5e42TSe1KZKRigkwObSTVueazodhiDD9lzQ+miv+/4tuX0jpY09oHrNebVUvjw1lfpnKZxZ0wwJPmC41Rjogn8kneF+m3EA3lC7YkmjDaBEU5OkQZPpm+JJ8eFFQ9SzmvcCGCQIDAQAB'
// 私钥key
const privateKey='MIIBUwIBADANBgkqhkiG9w0BAQEFAASCAT0wggE5AgEAAkEA0vfvyTdGJkdbHkB8\n'+
  'mp0f3FE0GYP3AYPaJF7jUd1M0XxFSE2ceK3k2kw20YvQ09NJKk+OMjWQl9WitG9p\n'+
  'B6tSCQIDAQABAkA2SimBrWC2/wvauBuYqjCFwLvYiRYqZKThUS3MZlebXJiLB+Ue\n'+
  '/gUifAAKIg1avttUZsHBHrop4qfJCwAI0+YRAiEA+W3NK/RaXtnRqmoUUkb59zsZ\n'+
  'UBLpvZgQPfj1MhyHDz0CIQDYhsAhPJ3mgS64NbUZmGWuuNKp5coY2GIj/zYDMJp6\n'+
  'vQIgUueLFXv/eZ1ekgz2Oi67MNCk5jeTF2BurZqNLR3MSmUCIFT3Q6uHMtsB9Eha\n'+
  '4u7hS31tj1UWE+D+ADzp59MGnoftAiBeHT7gDMuqeJHPL4b+kC+gzV4FGTfhR9q3\n'+
  'tTbklZkD2A=='
var RSA={
  /* JSEncrypt加密 */
  rsaPublicData(data) {
    // console.log(JSEncrypt)
    var jsencrypt=new JSEncrypt()
    jsencrypt.setPublicKey(publicKey)
    // 如果是对象/数组的话，需要先JSON.stringify转换成字符串
    var result=jsencrypt.encrypt(data)
    return result
  },
  /* JSEncrypt解密 */
  rsaPrivateData(data) {
    var jsencrypt=new JSEncrypt()
    jsencrypt.setPrivateKey(privateKey)
    // 如果是对象/数组的话，需要先JSON.stringify转换成字符串
    var result=jsencrypt.encrypt(data)
    return result
  }
}
window.Rsa = RSA;

// exports.default = RSA;