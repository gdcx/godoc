var loginUrl='/sso/login'
function commonLogin(account, password, baseUrl,appid,sign_secret,publicKey) {
    let passwordSec = Rsa.rsaPublicData(password,publicKey);
    var xhr=new XMLHttpRequest();
    let timestamp=Math.round(new Date())
    xhr.open("POST", baseUrl+loginUrl, true);
    let sign = sha256(appid + timestamp + account + passwordSec + sign_secret)

    // 添加自定义的HTTP头部
    xhr.setRequestHeader('Content-Type', 'application/json;charset=utf-8');
    xhr.setRequestHeader('appid', appid);
    xhr.setRequestHeader('timestamp', timestamp);
    xhr.setRequestHeader('sign', sign);

    let params={
        accounts: account,
        passwd: passwordSec,
        verifyInput: '',
    }
    xhr.send(JSON.stringify(params))
    xhr.onreadystatechange=function () {
        if (xhr.readyState===4&&xhr.status===200) {
            // 请求成功
            var json=JSON.parse(xhr.responseText);
            console.log(json);
            alert('登录成功')
        }
    };
}