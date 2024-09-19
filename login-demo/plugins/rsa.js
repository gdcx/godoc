var RSA={
  /* JSEncrypt加密 */
  rsaPublicData(data,publicKey) {
    // console.log(JSEncrypt)
    var jsencrypt=new JSEncrypt()
    jsencrypt.setPublicKey(publicKey)
    // 如果是对象/数组的话，需要先JSON.stringify转换成字符串
    var result=jsencrypt.encrypt(data)
    return result
  }
}
window.Rsa = RSA;