const APP_ID='gdcx1001';
const SIGN_SECRET='baa2847a57b5c45c79754442daeca425c56ffde81499ebe33de03ddefd19d46c';
var loginUrl='/sso/login'
function commonLogin(baseUrl,account, password, vertifyCode,appid=APP_ID,sign_secret=SIGN_SECRET) {
    let passwordSec = Rsa.rsaPublicData(password);
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
        verifyInput: vertifyCode,
    }
    xhr.send(JSON.stringify(params))
    xhr.onreadystatechange=function () {
        if (xhr.readyState===4&&xhr.status===200) {
            // 请求成功
            var json=JSON.parse(xhr.responseText);
            console.log(json);
        }
    };
}