# 高度无人机远程调度平台开放API

[TOC]

# 1.文档说明

## 1.1编写目的

------

高度无人机远程调度平台(以下简称平台)提供了：单点登录、设备授权、任务执行、机场复位、无人机悬停、无人机指点、无人机返航、视频接入，吊舱操控、实时数据获取、预警接入、飞行申报、AI识别、电子围栏、地图标会、电子围栏、飞行管控、地图资源、三维地图等开放功能。基于平台开放的能力，合作厂家和开发者可快速实现丰富的综合应用。 本文档详细描述了平台开放的API接口、调用方式、使用场景等内容。用于指导开发者基于平台做二次开发。



## 1.2阅读对象

------

希望基于本平台对外提供的能力做二次开发的客户、合作伙伴、第三方厂商或其他具有授权的开发者。

阅读群体需要具备以下技能，才能很好的理解本文档内容。

- 良好的计算机编程能力，开发者需要具备 Java、JavaScript、Go、Rust等常见的一种或者多种编程语言。

- 对无人机知识或低空飞行有一定的认知。理解机场、无人机、吊舱、视频监控、任务航线、无人机巡飞、Gis、AR融合等专有名词。

  

## 1.3阅读指南

------

为了能快速了解平台提供的API功能，和快速上手，建议按照以下顺序阅读本文档剩余内容。

- 查阅【相关术语】章节，对文档内会出现的专业术语进行初步认知。

- 查阅【协议概述】章节，掌握API的调用方式。

- 查阅【开发前准备】章节，了解开发对接流程。

- 按照API接口定义，编码开发及完成所需的应用。

  

## 1.4相关术语

------

| 术语       | 含义                                                         |
| ---------- | ------------------------------------------------------------ |
| OpenAPI    | 对外开放的接口                                               |
| Method     | http请求的方法，常用的方法有GET/POST/PUT/DELETE等            |
| headers    | http请求中的头信息,如：appId、timestamp、sign等              |
| path       | http请求地址，指域名/IP（端口号）之后的部分，如请求地址为"[http://drone.godouav.com/api/missionById/001"，则[path指"api/missionById/001"](api/missionById/001) |
| query      | 指请求地址参数，如请求"http://drone.godouav.com/api?userName=a,pwd=xxxx"，query为userName=a,pwd=xxxx |
| bodyJson   | 指POST请求中body以 JSON参数                                  |
| AppId      | 授权ID                                                       |
| AppSecret  | 授权签名密钥                                                 |
| timestamp  | 时间戳：如1725606482761，当前时间的毫秒数                    |
| PublicKey  | 授权加密公钥                                                 |
| 签名字符串 | 待签名计算的字符串                                           |
| sign       | 签名结果                                                     |
| webRtc     | 是一项实时通讯技术，允许网络应用或站点在不借助中间媒介的情况下，建立浏览器之间的点对点（Peer-to-Peer）连接，实现视频流和/或音频流以及其他任意数据的传输 |
| RTSP       | **实时串流协议**（Real Time Streaming Protocol，**RTSP**）是一种网络应用协议，专为娱乐和通信系统的使用，以控制流媒体 服务器。该协议用于建立和控制终端之间的媒体会话。媒体服务器的客户端发布VCR命令，例如播放，录制和暂停，以便于实时控制从服务器到客户端（视频点播）或从客户端到服务器（语音录音）的媒体流。 |
| RTMP       | 实时消息协议（英语：Real-Time Messaging Protocol，缩写RTMP）也称实时消息传输协议，是最初由Macromedia为通过互联网在Flash播放器与一个服务器之间传输流媒体音频、视频和数据而开发的一个专有协议 |
| MQTT       | MQTT（Message Queuing Telemetry Transport）是一种轻量级的消息协议，适用于物联网（IoT）设备之间的通信 |





# 2.协议概述

## 2.1接口规则

| 传输方式   | https                                          |
| ---------- | ---------------------------------------------- |
| URL格式    | {{base_url}}/backend/user/QueryUserRightDevice |
| 提交方式   | POST/GET                                       |
| 数据格式   | 请求及返回均为为JSON格式                       |
| 证书要求   | 暂不需要                                       |
| 返回值规则 | 见下表                                         |

## 2.2返回值规则

​      对于API接口调用返回的结果统一采用json格式，格式如下

​      

```
{
	"code": //返回码，0 成功; 非0 失败
	"msg": //返回信息
	"data"://返回详细数据
}
```

## 2.3成功示例

```
{
    "code": 0,
    "msg": "success",
    "data": {
              "pushStreamUrl": "http://gd.uavm.stream/drone"
    }   
}        
```

## 2.4失败示例

```
{
    "code": 300016,
    "msg": "The user name or login password is incorrect.",
    "data": {
        "needCheckCode": "NO"
    }
}
```





## 2.5公共返回码

| 返回码 | 描述                         |
| ------ | ---------------------------- |
| 0      | success                      |
| 300001 | failure                      |
| 300002 | AppId  can not be null       |
| 300003 | appId no auth                |
| 300004 | signature can not be null    |
| 300005 | signature check failure      |
| 300006 | signature has expired        |
| 300007 | account not be null          |
| 300008 | password not be null         |
| 300009 | check code not be null       |
| 300010 | check code check no pass     |
| 300011 | login on other device        |
| 300012 | request exception            |
| 300013 | parameter exception          |
| 300014 | file size more than max size |
| 300015 | timestamp  can not be null   |
| 300016 | request is expired           |
| 300017 | user no exist                |
| 300018 | pass word check no pass      |
| 300119 | account has expired.         |
| 300020 | fresh token is expire        |
| 300021 | access_token check failure   |
| 300022 | access_token is empty        |
| 300029 | sms send success             |
| 300030 | sms send failure             |
| 300033 | sms code is expire           |
| 300034 | sms code check failure       |
| 300101 | auth code expied             |
| 300035 | rsa decode failure           |
| 300036 | request wrong                |
| 300037 | app key is empty             |
| 400001 | micro service unavailable    |



# 3.开发前准备

## 3.1对接授权申请

对于需要深度对接高度无人机远程调度平台的单位或第三方，需要向高度申请账号授权，并获取以下对接信息:

- account：对接用户账号
- passwd：对接密钥
- AppId   ：对接AppID
- SignSecret：对接密钥
- PublicKey ：加密公钥

# 4.sso登录

需要通过客户自有大屏、OA、ERP或其他自有平台直接跳转到高度无人机远程调度平台的客户，可通过单点登录直接进入到无人机远程调度平台，实现类似于免登进入系统的功能，(前提条件，账号必须在高度平台中存在，且对账号赋予了相关操作权限)

## 4.1sso授权申请

```
AppKey     = xxxxx
AppSecret  = bbbbb
TenantId   = 17380105941094277122398xxxxx
```

## 4.2生成token

- 加密算法 Aes

- 加密示例 (Java)


```
public static void main(String[] args) {
    String account=Lisi     //双方平台必须一致
    long   send=300;        //单位秒(s)，token失效时间
    String originalString = account + "*" + System.currentTimeMillis() + "*" + send;// 原始加密串用；”*“隔开
    String token = AesUtil.encrypt(originalString,AppKey,AppSecret);
    token = URLEncodeUtil.encode(token, URLEncodeUtil.DEFAULT_CHARSET);
}
```

## 4.3sso跳转地址

```
https://drone.godouav.com/api/sso/auth/{TenantId}?token={token}
```

- AesUtil 工具类

```
import org.apache.commons.codec.binary.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;

public class AesUtil {
    private static final String key = "QWz7pR4eKb2G9yYt6";
    private static final String initVector = "Xa5n3jU8fL1MhZvT7";

    public static String encrypt(String value,String key,String initVector) {
        try {
            IvParameterSpec iv = new IvParameterSpec(initVector.getBytes(StandardCharsets.UTF_8));
            SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "AES");

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);

            byte[] encrypted = cipher.doFinal(value.getBytes());
            return Base64.encodeBase64String(encrypted);
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return null;
    }

    //加密
    public static String encrypt(String value) {
        try {
            IvParameterSpec iv = new IvParameterSpec(initVector.getBytes(StandardCharsets.UTF_8));
            SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "AES");

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);

            byte[] encrypted = cipher.doFinal(value.getBytes());
            return Base64.encodeBase64String(encrypted);
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return null;
    }
    public static String desEncrypt(String token, String mKey, String ivSpec) {
        try {
            IvParameterSpec iv = new IvParameterSpec(ivSpec.getBytes(StandardCharsets.UTF_8));
            SecretKeySpec skeySpec = new SecretKeySpec(mKey.getBytes(StandardCharsets.UTF_8), "AES");
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);
            byte[] original = cipher.doFinal(Base64.decodeBase64(token));
            return new String(original);
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return null;
    }
    //解密
    public static String decrypt(String encrypted) {
        try {
            IvParameterSpec iv = new IvParameterSpec(initVector.getBytes(StandardCharsets.UTF_8));
            SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "AES");
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);
            byte[] original = cipher.doFinal(Base64.decodeBase64(encrypted));
            return new String(original);
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return null;
    }
}
```

- URLEncodeUtil  工具类 


```
import java.net.URLDecoder;
import java.net.URLEncoder;

public class URLEncodeUtil {
    public static String DEFAULT_CHARSET="utf-8";
    public static String encode(final String str, final String charset) {
        try {
            return URLEncoder.encode(str, charset);
        } catch (Exception e) {
            e.printStackTrace();
            return str;
        }
    }

    public static String decode(final String str, final String charset) {
        try {
            return URLDecoder.decode(str, charset);
        } catch (Exception e) {
            e.printStackTrace();
            return str;
        }
    }
}
```





# 5.API列表

## 5.0接口接入地址

接口请求地址：BASE_URL = https://drone.godouav.com/api



## 5.1认证登录

- 接口说明

​       身份验证登录接口是平台相关接口的查询的授予凭证，通过该接口将返回租户组织、授权token、token过期时间信息，token过期单位毫秒

- 接口版本

  ```
  v2.0
  ```

- 接口地址

  ```
  {{base_url}}/sso/authLogin
  ```

- 请求方法

  ```
  POST
  ```

- 数据提交方式

  ```
  application/json
  ```

- 请求参数

  | 参数名称  | 参数位置 | 数据类型 | 是否必须 | 参数描述                                    |
  | --------- | -------- | -------- | -------- | ------------------------------------------- |
  | appId     | header   | string   | 是       | 授权appId                                   |
  | timestamp | header   | string   | 是       | 当前时间戳，单位毫秒                        |
  | sign      | header   | string   | 是       | 签名字符串，签名算法 sha256Hex 签名后的字符 |
  | accounts  | body     | string   | 是       | 授权账号                                    |
  | passwd    | body     | string   | 是       | 公钥加密后的密文(加密授权密码)                                   |

  

- 返回值

```
{
    "code": 0,
    "msg": "登陆成功",
    "data": {
        "accessTokenExpired": 886400000,
        "custId": "1831600756235825152125857700",
        "sign": "abt4556a5a07cdd15eb726fc7dfc678160c61fcfbb0e87b3db1ce19c2d5x56h",
        "accessToken": "xxxxxxxxxxxxgreate_eyJhbGcxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    }
}
```

### 5.1.1JAVA 签名示例

```
import org.apache.commons.codec.digest.DigestUtils;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Date;

public class testLogin {
    public static void main(String[] args) throws NoSuchAlgorithmException {
        long timestamp = System.currentTimeMillis();
        //测试对接账号
 
        String appid      = "AAAA";
        String Account    = "BBBB";
        String password   = "CCCC";
        String publicKey  = "MIGfMA0GCSqGSIb3DQEBAQUAXXXXXXX";
        String signSecret = "5b0105412aaaa276d69604fXXXXXXX";

        String passwordEn = RSAEncrypt.encrypt(password, publicKey);
        String strSign = appid + timestamp + Account + passwordEn + signSecret;
        String sign = DigestUtils.sha256Hex(strSign);

        System.out.println(" Account:[" + Account + "] login mock");
        System.out.println(" timestamp：" + timestamp);
        System.out.println(" sign：" + sign);
        System.out.println(" rsa encrypt password is :" + passwordEn);
    }
}
```



JAVA: RSAEncrypt 工具类

```
import org.apache.tomcat.util.codec.binary.Base64;
import javax.crypto.Cipher;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

public class RSAEncrypt {
    public static void main(String[] args) throws Exception {
        //生成公钥和私钥
        Map<Integer, String> keyMap =  genRsaKeyPair();
        //加密字符串
        String message = "installServerSecret";
        System.out.println("随机生成的公钥为:" + keyMap.get(0));
        System.out.println("随机生成的私钥为:" + keyMap.get(1));
        System.out.println("原始字符串为:" + message);
        String messageEn = encrypt(message, keyMap.get(0));
        System.out.println("加密后的字符串为:" + messageEn);
        String messageDe = decrypt(messageEn, keyMap.get(1));
        System.out.println("还原后的字符串为:" + messageDe);
    }
    /**
     * 随机生成密钥对
     *
     * @throws NoSuchAlgorithmException
     */
    public static Map<Integer, String> genRsaKeyPair() throws NoSuchAlgorithmException {
        Map<Integer, String> keyRsaMap = new HashMap<Integer, String>();

        // KeyPairGenerator类用于生成公钥和私钥对，基于RSA算法生成对象
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
        // 初始化密钥对生成器，密钥大小为96-1024位
        keyPairGen.initialize(1024, new SecureRandom());
        // 生成一个密钥对，保存在keyPair中
        KeyPair keyPair = keyPairGen.generateKeyPair();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();   // 得到私钥
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();  // 得到公钥
        String publicKeyString = new String(Base64.encodeBase64(publicKey.getEncoded()));
        // 得到私钥字符串
        String privateKeyString = new String(Base64.encodeBase64((privateKey.getEncoded())));
        // 将公钥和私钥保存到Map
        keyRsaMap.put(0, publicKeyString);  //0表示公钥
        keyRsaMap.put(1, privateKeyString);  //1表示私钥
        return keyRsaMap;
    }

    /**
     * RSA公钥加密
     *
     * @param str:       加密字符串
     * @param publicKey: 公钥
     * @return 密文
     * @throws Exception 加密过程中的异常信息
     */
    public static String encrypt(String str, String publicKey) {
        try {
            //base64编码的公钥
            byte[] decoded = Base64.decodeBase64(publicKey);
            RSAPublicKey pubKey = (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(decoded));
            //RSA加密
            Cipher cipher = Cipher.getInstance("RSA"); //密码
            cipher.init(Cipher.ENCRYPT_MODE, pubKey);
            String outStr = Base64.encodeBase64String(cipher.doFinal(str.getBytes("UTF-8")));
            return outStr;
        } catch (Exception e) {
            e.printStackTrace();
            return "";
        }
    }

    /**
     * RSA私钥解密
     *
     * @param str        加密字符串
     * @param privateKey 私钥
     * @return 铭文
     * @throws Exception 解密过程中的异常信息
     */
    public static String decrypt(String str, String privateKey) {
        try {
            //64位解码加密后的字符串
            byte[] inputByte = Base64.decodeBase64(str.getBytes("UTF-8"));
            //base64编码的私钥
            byte[] decoded = Base64.decodeBase64(privateKey);
            RSAPrivateKey priKey = (RSAPrivateKey) KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(decoded));
            //RSA解密
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, priKey);
            String outStr = new String(cipher.doFinal(inputByte));
            return outStr;
        } catch (Exception e) {
            return null;
        }
    }
}
```

### 5.1.2 JavaScript签名示例

- demo路径

https://gitee.com/romeo_zpl/gdoc/tree/master/login-demo

```
{{base_url}}/sso/authLogin
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
        passwd: passwordSec
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
```

- JavaScript涉及Rsa工具类

```
参考 demo 中 rsa加密
```



- JavaScript 涉及sha256工具类

```
参考 demo 中 签名
```





## 5.2获取机场及无人机

- 接口说明

​       获取权限内设备列表将返回机场列表数据及无人机列表数据

- 接口版本

  ```
  v2.0
  ```

- 接口地址

  ```
  {{base_url}}/backend/user/QueryUserRightDevice
  ```

- 请求方法

  ```
  POST
  ```

- 数据提交方式

  ```
  application/json
  ```

- 请求参数

  | 参数名称     | 参数位置 | 数据类型 | 是否必须 | 参数描述          |
  | ------------ | -------- | -------- | -------- | ----------------- |
  | access_token | header   | string   | 是       | 接口访问token凭证 |

- 返回值

```
{
    "code": 0,
    "msg": "操作成功",
    "data": {
        "listDrone": [
            {
                "fifthCom": "10.8.0.14",
                "PlatformLongitudeDeg": 114.24295786452763,
                "fifthComSwitch": 1,
                "visualIp": null,
                "droneId": "1725358456837378048289495838",
                "droneSn": "GDM002S2312178",
                "secondOnLandLatitudeDeg": 22.759178995556777,
                "latestParkDroneId": "1725358456837378048289495838",
                "longitudeDeg": 0.0,
                "systemId": 1,
                "peviceType": 0,
                "videoAgg": 0,
                "platformModel": "A170",
                "isMaintenance": 0,
                "platformId": "1725358456837378048289490001",
                "platformSn": "12",
                "latitudeDeg": 0.0,
                "secondOnLandLongitudeDeg": 114.24295786452763,
                "pushStreamType": 1,
                "PlatformName": "103测试机场",
                "latestParkPlatformName": "103测试机场",
                "PlatformLatitudeDeg": 22.759178995556777,
                "droneModel": "T2.5巡宇无人机",
                "mavlinkMode": 0,
                "latestParkPlatformId": "1725358456837378048289490001",
                "skipLineLocked": 0,
                "droneName": "103无人机",
                "nodeId": "98",
                "latestParkNodeId": "98"
            },
            {
                "fifthCom": "10.8.0.114",
                "PlatformLongitudeDeg": 114.24289236814671,
                "fifthComSwitch": 1,
                "visualIp": null,
                "droneId": "1726424641825804288449435505",
                "droneSn": "GDM001S2111103",
                "secondOnLandLatitudeDeg": 22.7592169752,
                "latestParkDroneId": "1726424641825804288449435505",
                "longitudeDeg": 0.0,
                "systemId": 1,
                "deviceType": 0,
                "videoAgg": 0,
                "platformModel": "A170",
                "isMaintenance": 0,
                "platformId": "1726423968849727488784920178",
                "platformSn": "AAA",
                "latitudeDeg": 0.0,
                "secondOnLandLongitudeDeg": 114.2429243939,
                "pushStreamType": 0,
                "PlatformName": "红花岭 119",
                "latestParkPlatformName": "红花岭 119",
                "PlatformLatitudeDeg": 22.75920015871399,
                "droneModel": "GD-T2.5",
                "mavlinkMode": 0,
                "latestParkPlatformId": "1726423968849727488784920178",
                "skipLineLocked": 0,
                "droneName": "红花岭 119",
                "nodeId": "119",
                "latestParkNodeId": "119"
            }
        ],
        "listPlateForms": [
            {
                "deviceType": 0,
                "longitudeDeg": 114.24295786452763,
                "platformModel": "A170",
                "isMaintenance": 0,
                "platformId": "1725358456837378048289490001",
                "platformSn": "12",
                "latitudeDeg": 22.759178995556777,
                "secondOnLandLongitudeDeg": 114.24295786452763,
                "visualIp": null,
                "name": "103测试机场",
                "secondOnLandLatitudeDeg": 22.759178995556777,
                "latestParkDroneId": "1725358456837378048289495838",
                "skipLineLocked": 0,
                "netWork": null,
                "nodeId": "98"
            },
            {
                "deviceType": 0,
                "longitudeDeg": 114.24289236814671,
                "platformModel": "A170",
                "isMaintenance": 0,
                "platformId": "1726423968849727488784920178",
                "platformSn": "AAA",
                "latitudeDeg": 22.75920015871399,
                "secondOnLandLongitudeDeg": 114.2429243939,
                "visualIp": null,
                "name": "红花岭 119",
                "secondOnLandLatitudeDeg": 22.7592169752,
                "latestParkDroneId": "1726424641825804288449435505",
                "skipLineLocked": 0,
                "netWork": null,
                "nodeId": "119"
            }
        ]
    }
}
```

- 返回字段说明

| 字段名                   | 说明                                                    |
| ------------------------ | ------------------------------------------------------- |
| platformId               | 机场ID                                                  |
| name                     | 机场名称                                                |
| deviceType               | 设备类型；0：机场；1充电装置；3中继器,4. 单兵（无机场） |
| nodeId                   | nodeId                                                  |
| platformModel            | 产品型号                                                |
| platformSn               | 序列号                                                  |
| longitudeDeg             | 机场部署-经度                                           |
| latitudeDeg              | 机场部署-纬度                                           |
| secondOnLandLongitudeDeg | 备降点-精度                                             |
| secondOnLandLatitudeDeg  | 备降点-维度                                             |
| isMaintenance            | 当前状态；0：就绪；1:设备维护                           |
| skipLineLocked           | 航线占用；0：未占用；1:占用                             |
| netWork                  | 网段信息                                                |
| visualIp                 | 虚拟ip                                                  |
| latestParkDroneId        | 当前停靠无人机ID                                        |

- 无人机信息 返回字段说明

| 字段名                   | 说明                                                    |
| ------------------------ | ------------------------------------------------------- |
| droneId                  | 无人机ID                                                |
| droneName                | 无人机名称                                              |
| droneSn                  | 无人机序列号                                            |
| droneModel               | 无人机产品型号                                          |
| videoAgg                 | 视频聚合支持 0:支持; 1不支持                            |
| pushStreamType           | 视频推流方式 0:p2p直推; 1服务器分发                     |
| latestParkPlatformId     | 当前停靠机场ID                                          |
| latestParkPlatformName   | 当前停靠机场                                            |
| latestParkNodeId         | 当前停靠机场nodeId                                      |
| nodeId                   | 原始机场nodeId                                          |
| skipLineLocked           | 航线占用；0：未占用；1:占用                             |
| fifthCom                 | 无人机通信连接ID                                        |
| fifthComSwitch           | 0 关闭5G， 1 打开                                       |
| PlatformLongitudeDeg     | 原始机场精度                                            |
| PlatformLatitudeDeg      | 原始机场维度                                            |
| visualIp                 | 虚拟IP                                                  |
| platformId               | 原始机场id                                              |
| PlatformName             | 原始机场                                                |
| secondOnLandLatitudeDeg  | 原始机场第二降落点                                      |
| secondOnLandLongitudeDeg | 原始机场第二降落点                                      |
| latestParkDroneId        | 原始机场最后停靠无人机                                  |
| longitudeDeg             | 无人机最后点精度                                        |
| latitudeDeg              | 无人机最后点维度                                        |
| systemId                 | 无人机通信连接ID                                        |
| deviceType               | 设备类型；0：机场；1充电装置；3中继器,4. 单兵（无机场） |
| isMaintenance            | 当前状态；0：就绪；1:设备维护                           |
| platformModel            | 原始机场产品型号                                        |
| platformSn               | 原始机场序列号                                          |
| mavlinkMode              | MavlinkMode连接模式,0:客户端；1服务端                   |

## 5.3获取吊舱信息

- 接口说明

​       获取权限内所有吊舱信息

- 接口版本

  ```
  v2.0
  ```

- 接口地址

  ```
  {{base_url}}/backend/user/QueryUserRightGimbal
  ```

- 请求方法

  ```
  POST
  ```

- 数据提交方式

  ```
  application/json
  ```

- 请求参数

  | 参数名称     | 参数位置 | 数据类型 | 是否必须 | 参数描述          |
  | ------------ | -------- | -------- | -------- | ----------------- |
  | access_token | header   | string   | 是       | 接口访问token凭证 |

- 返回值

```
{
    "code": 0,
    "msg": "操作成功",
    "data": [
        {
            "gimbalId": "1725359469224923136146623831",
            "gimbalType": "0",
            "gimbalTypeName": "视频吊舱",
            "droneId": "1725358456837378048289495838",
            "subUrl": "rtsp://admin:gdcx888666@192.168.109.140:554/h264/ch1/sub/av_stream",
            "sipPassWord": null,
            "updateBy": "1725684357466820608438748095",
            "cameraTypeName": "高清摄像机(主)",
            "model": "DC_03",
            "sn": "",
            "platformName": "103测试机场",
            "createDate": "2023-11-17 11:45:27",
            "systemId": 1,
            "openSub": 0,
            "sipConfigId": null,
            "comProtocol": null,
            "platformId": "1725358456837378048289490001",
            "cameraType": 0,
            "url": "rtsp://192.168.0.18:8554/live.stream",
            "sipUserName": null,
            "createBy": "10000100000000000000000001",
            "iPv4": "192.168.0.1",
            "port": 80,
            "iPv6": null,
            "supportGB": 0,
            "droneName": "103无人机",
            "nodeId": "98",
            "sipAuthUserName": null,
            "status": 0
        },
        {
            "updateDate": "2024-09-19 16:22:43",
            "gimbalTypeName": "喊话器",
            "gimbalId": "1836224039216422912873620886",
            "droneId": "1725358456837378048289495838",
            "subUrl": null,
            "sipPassWord": null,
            "updateBy": "1725684357466820608438748095",
            "cameraTypeName": "高清摄像机(主)",
            "model": "ZY-01",
            "sn": null,
            "platformName": "103测试机场",
            "createDate": "2024-09-18 10:01:41",
            "systemId": 1,
            "openSub": 0,
            "sipConfigId": null,
            "comProtocol": "TCP",
            "platformId": "1725358456837378048289490001",
            "cameraType": 0,
            "url": null,
            "sipUserName": null,
            "createBy": "1725684357466820608438748095",
            "iPv4": "192.168.0.103",
            "port": 80,
            "iPv6": null,
            "supportGB": 0,
            "gimbalType": "1",
            "droneName": "103无人机",
            "nodeId": "98",
            "sipAuthUserName": null,
            "status": 0
        }
    ]
}
```



- 返回字段说明

| 字段名          | 说明                                                         |
| --------------- | ------------------------------------------------------------ |
| gimbalId        | 吊舱ID                                                       |
| droneId         | 无人机ID                                                     |
| droneName       | 无人机名                                                     |
| systemId        | 无人机通信连接ID                                             |
| platformId      | 机场ID                                                       |
| platformName    | 机场名                                                       |
| nodeId          | nodeId                                                       |
| gimbalType      | 0:视频吊舱；1：喊话器;2气体监测(只需要配置型号及序列号)      |
| gimbalTypeName  | 吊舱名                                                       |
| cameraType      | 摄像机类型 0 高清摄像机(主)； 1红外摄像机(副)；2AI摄像机(副) |
| cameraTypeName  | 摄像机名                                                     |
| sn              | 吊舱序列号                                                   |
| model           | 吊舱产品型号                                                 |
| comProtocol     | 通讯协议TCP,UDP                                              |
| iPv4            | iPv4                                                         |
| iPv6            | iPv6                                                         |
| port            | port                                                         |
| url             | 拉流地址                                                     |
| openSub         | 开启辅码流 0 关闭； 1 开启                                   |
| subUrl          | 辅码流地址                                                   |
| supportGB       | 视频国标：0 不支持；1支持                                    |
| sipConfigId     | SipServer配置ID                                              |
| sipUserName     | Sip用户                                                      |
| sipAuthUserName | Sip认证用户                                                  |
| sipPassWord     | Sip密码                                                      |

## 5.4获取机场摄像机信息

- 接口说明

​       获取机场的内外摄像机信息

- 接口版本

  ```
  v2.0
  ```

- 接口地址

  ```
  {{base_url}}/backend/platform/queryPlatformInfoByPlatformId/{platformId}
  ```

- 请求方法

  ```
  GET
  ```

- 数据提交方式

  ```
  application/json
  ```

- 请求参数

  | 参数名称     | 参数位置 | 数据类型 | 是否必须 | 参数描述          |
  | ------------ | -------- | -------- | -------- | ----------------- |
  | access_token | header   | string   | 是       | 接口访问token凭证 |

- 返回值

```
{
    "code": 0,
    "msg": "操作成功",
    "data": {
        "lastUseTime": "2024-09-02 12:06:26",
        "listCamera": [
            {
                "name": "机场外摄像头",
                "port": 554,
                "url": "rtsp://admin:gdcx888666@192.168.119.140:554/h264/ch1/main/av_stream",
                "status": 0,
                "createBy": "1725362106884296704265405637",
                "updateBy": "1787745197812224000553585656",
                "createDate": "2023-11-20 10:15:24.000",
                "updateDate": "2024-06-27 16:07:37.000",
                "videoServerUrl": null,
                "platformId": "1726423968849727488784920178",
                "cameraId": "1726423970087047168554214027",
                "cameraType": 0,
                "sn": "BBB",
                "model": "AAA",
                "ipv4": "192.168.119.140",
                "sipConfigId": "",
                "ipv6": null,
                "supportGB": 0,
                "sipPassWord": "",
                "openSub": 1,
                "subUrl": "rtsp://admin:gdcx888666@192.168.119.140:554/stream2",
                "sipUserName": "",
                "sipAuthUserName": ""
            },
            {
                "name": "舱内摄像头",
                "port": 554,
                "url": "rtsp://admin:gdcx888666@192.168.119.139:554/stream1",
                "status": 0,
                "createBy": "1725684357466820608438748095",
                "updateBy": "1787745197812224000553585656",
                "createDate": "2024-06-18 17:05:33.000",
                "updateDate": "2024-06-27 16:07:37.000",
                "videoServerUrl": null,
                "platformId": "1726423968849727488784920178",
                "cameraId": "1802991025162162176158371169",
                "cameraType": 1,
                "sn": "BBB",
                "model": "AAA",
                "ipv4": "192.168.119.139",
                "sipConfigId": "",
                "ipv6": null,
                "supportGB": 0,
                "sipPassWord": "",
                "openSub": 0,
                "subUrl": "rtsp://admin:gdcx888666@192.168.119.139:554/stream2",
                "sipUserName": "",
                "sipAuthUserName": ""
            }
        ],
        
        "name": "红花岭 119",
        "platformId": "1726423968849727488784920178"
    }
}
```

- 返回字段说明

| 字段名     | 说明                             |
| ---------- | -------------------------------- |
| cameraId   | 摄像机ID                         |
| cameraType | 状态 0 外部摄像机； 1 内部摄像机 |
| name       | 摄像机名称                       |
| sn         | 序列号                           |
| model      | 产品型号                         |
| ipv4       | ipv4                             |
| ipv6       | ipv6                             |
| port       | 端口                             |
| url        | 视频流地址                       |
| subUrl     | 视频流辅码流地址                 |

## 5.5航线接口

### 5.5.1获取航线列表

- 接口说明

​       获取权限内航线列表

- 接口版本

  ```
  v2.0
  ```

- 接口地址

  ```
  {{base_url}}/backend/user/QueryUserRightMission
  ```

- 请求方法

  ```
  POST
  ```

- 数据提交方式

  ```
  application/json
  ```

- 请求参数

  | 参数名称     | 参数位置 | 数据类型 | 是否必须 | 参数描述          |
  | ------------ | -------- | -------- | -------- | ----------------- |
  | access_token | header   | string   | 是       | 接口访问token凭证 |

- 返回值

```
{
    "code": 0,
    "msg": "操作成功",
    "data": {
        "listMission": [
            {
                "missionId": "1820382209627467776203092248",
                "custId": "999001",
                "missionName": "XXX河道巡检",
                "missionLineType": 0,
                "missionType": "1725435460400058368624656727",
                "isExecute": 0,
                "flyKilometer": "47m",
                "flyArea": "0",
                "flyAreaShape": null,
                "lineShape": null,
                "signalLostDeal": 0,
                "hightType": 0,
                "executeTime": "5s"
                "platformId": "1725358456837378048289490001",
                "platformName": "103测试机场",
                "droneId": "1725358456837378048289495838",
                "droneName": "103无人机",
                "aiSwitch": 0,
                "aiTypeId": null,
                "photoMode": 0,
                "collectPhotos": 0,
                "collectTakeOffHight": 0.0,
                "collectMargins": 0.0,
                "collectPhotoHight": 0.0,
                "chooseShot": null,
                "collectFlightOverlapRate": 0.0,
                "collectGimbalModel": null,
                "collectFlightAngle": 0.0,
                "collectType": null,
                "collectSideOverlapRate": 0.0,
                "collectSpeed": 0.0,
                "operateMode": 0
            }
        ]
    }
}
```

- 返回字段说明

  | 字段名                   | 说明                                        |
  | ------------------------ | ------------------------------------------- |
  | missionId                | 航线ID                                      |
  | custId                   | 租户ID                                      |
  | missionName              | 航线名                                      |
  | missionLineType          | 航线类型；0：航点航线；1跳点航线;2 建图航线 |
  | missionType              | 航线类型                                    |
  | isExecute                | 航线当前状态：0,未执行或执行结束，1执行中   |
  | flyKilometer             | 预计飞行公里数                              |
  | flyArea                  | 预计巡飞面积                                |
  | flyAreaShape             | 预计采集区域形状                            |
  | lineShape                | 采集线条形状                                |
  | signalLostDeal           | 信号丢失 0:继续执行; 1:断联系返航           |
  | hightType                | 0：相对起飞点；1：相对海拔                  |
  | executeTime              | 预计飞行时长                                |
  | platformId               | 关联机场ID                                  |
  | platformName             | 关联机场名                                  |
  | droneId                  | 最近一次执飞该航线的无人机ID                |
  | droneName                | 最近一次执飞该航线的无人机                  |
  | aiSwitch                 | AI识别开关                                  |
  | aiTypeId                 | AI模型能力                                  |
  | photoMode                | 拍照模式 0:等距间隔拍照; 1:等时间隔拍照     |
  | collectPhotos            | 预计建图照片数                              |
  | collectTakeOffHight      | 起飞高度                                    |
  | collectMargins           | 边距                                        |
  | collectPhotoHight        | 建图高度                                    |
  | chooseShot               | 选择镜头(0:广角、1.红外、2.可见光等镜头)    |
  | collectFlightOverlapRate | 旁向重叠率                                  |
  | collectGimbalModel       | 挂载型号(DC-03)                             |
  | collectFlightAngle       | 航线角度                                    |
  | collectType              | 采集方式                                    |
  | collectSideOverlapRate   | 航向重叠率                                  |
  | collectSpeed             | 采集速度                                    |
  | operateMode              | 0手动，1自动(监控点自动触发）,3定时自动巡航 |

  

### 5.5.2查询机场相关任务列表

- 接口说明

​       获取机场相关任务列表

- 接口版本

  ```
  v2.0
  ```

- 接口地址

  ```
  {{base_url}}/backend/mission/QueryMissionListByPlatformId/{platformId}
  ```

- 请求方法

  ```
  GET
  ```

- 数据提交方式

  ```
  application/json
  ```

- 请求参数

  | 参数名称     | 参数位置     | 数据类型 | 是否必须 | 参数描述                             |
  | ------------ | ------------ | -------- | -------- | ------------------------------------ |
  | access_token | header       | string   | 是       | 接口访问token凭证                    |
  | platformId   | PathVariable | string   | 是       | 机场ID, 既获取机场列表中的platformId |

- 返回值

  ```
  {
      "code": 0,
      "msg": "操作成功",
      "data": [{
              "belong": 0,
              "photoMode": 0,
              "signalLostDeal": 0,
              "flyKilometer": "667m",
              "aiTypeId": null,
              "collectPhotos": 0,
              "remark": null,
              "collectTakeOffHight": 0.0,
              "dicId": null,
              "collectMargins": 0.0,
              "lineShape": null,
              "missionType": "1725435460400058368624656727",
              "collectPhotoHight": 0.0,
              "updateBy": "1725362637463752704299374952",
              "custId": "999001",
              "missionName": "fff",
              "platformName": "103测试机场",
              "flyAreaShape": null,
              "aiSwitch": 0,
              "createDate": "2024-08-30 16:59:43",
              "hightType": 0,
              "missionId": "1829443875471118336655836034",
              "platformId": "1725358456837378048289490001",
              "custName": "高度创新",
              "chooseShot": null,
              "collectFlightOverlapRate": 0.0,
              "collectGimbalModel": null,
              "flyArea": null,
              "collectFlightAngle": 0.0,
              "collectType": null,
              "collectSideOverlapRate": 0.0,
              "collectSpeed": 0.0,
              "missionLineType": 0,
              "operateMode": 0,
              "gsd": 0.0,
              "nodeId": "98",
              "executeTime": "1min7s"
          },
          {
              "belong": 0,
              "photoMode": 1,
              "signalLostDeal": 0,
              "flyKilometer": "906.38m",
              "aiTypeId": null,
              "collectPhotos": 31,
              "remark": null,
              "collectTakeOffHight": 120.0,
              "dicId": null,
              "collectMargins": 20.0,
              "lineShape": "LINESTRING(114.2429578645 22.7591789956 178.63,114.2430963127 22.7599685035 190.63)",
              "missionType": "1725435460400058368624656727",
              "collectPhotoHight": 132.0,
              "custId": "999001",
              "missionName": "103建图测试",
              "platformName": "103测试机场",
              "flyAreaShape": "POLYGON((114.2430917917 22.7606976606,114.2454723077 22.7618265097))",
              "aiSwitch": 0,
              "createDate": "2024-08-26 16:05:45",
              "hightType": 0,
              "missionId": "1827980742963765248334870439",
              "platformId": "1725358456837378048289490001",
              "custName": "高度创新",
              "chooseShot": 0,
              "collectFlightOverlapRate": 80.0,
              "collectGimbalModel": "DC_03",
              "flyArea": "7801.51㎡",
              "collectFlightAngle": 60.0,
              "collectType": 0,
              "collectSideOverlapRate": 70.0,
              "createBy": "1725361181457256448485625223",
              "collectSpeed": 10.0,
              "missionLineType": 2,
              "operateMode": 0,
              "gsd": 5.03,
              "nodeId": "98",
              "executeTime": "1min31s"
          }
      ]
  }
  ```

- 返回字段说明

  | 字段名                   | 说明                                        |
  | ------------------------ | ------------------------------------------- |
  | missionId                | 航线ID                                      |
  | custId                   | 租户ID                                      |
  | missionName              | 航线名                                      |
  | missionLineType          | 航线类型；0：航点航线；1跳点航线;2 建图航线 |
  | missionType              | 航线类型                                    |
  | isExecute                | 航线当前状态：0,未执行或执行结束，1执行中   |
  | flyKilometer             | 预计飞行公里数                              |
  | flyArea                  | 预计巡飞面积                                |
  | flyAreaShape             | 预计采集区域形状                            |
  | lineShape                | 采集线条形状                                |
  | signalLostDeal           | 信号丢失 0:继续执行; 1:断联系返航           |
  | hightType                | 0：相对起飞点；1：相对海拔                  |
  | executeTime              | 预计飞行时长                                |
  | platformId               | 关联机场ID                                  |
  | platformName             | 关联机场名                                  |
  | droneId                  | 最近一次执飞该航线的无人机ID                |
  | droneName                | 最近一次执飞该航线的无人机                  |
  | aiSwitch                 | AI识别开关                                  |
  | aiTypeId                 | AI模型能力                                  |
  | photoMode                | 拍照模式 0:等距间隔拍照; 1:等时间隔拍照     |
  | collectPhotos            | 预计建图照片数                              |
  | collectTakeOffHight      | 起飞高度                                    |
  | collectMargins           | 边距                                        |
  | collectPhotoHight        | 建图高度                                    |
  | chooseShot               | 选择镜头(0:广角、1.红外、2.可见光等镜头)    |
  | collectFlightOverlapRate | 旁向重叠率                                  |
  | collectGimbalModel       | 挂载型号(DC-03)                             |
  | collectFlightAngle       | 航线角度                                    |
  | collectType              | 采集方式                                    |
  | collectSideOverlapRate   | 航向重叠率                                  |
  | collectSpeed             | 采集速度                                    |
  | operateMode              | 0手动，1自动(监控点自动触发）,3定时自动巡航 |

### 5.5.3查询航线航点按航线ID

- 接口说明

​       查询航线航点列表

- 接口版本

  ```
  v2.0
  ```

- 接口地址

  ```
  {{base_url}}/backend/mission/QueryMissionByMissionId/{missionId}
  ```

- 请求方法

  ```
  GET
  ```

- 数据提交方式

  ```
  application/json
  ```

- 请求参数

  | 参数名称     | 参数位置     | 数据类型 | 是否必须 | 参数描述          |
  | ------------ | ------------ | -------- | -------- | ----------------- |
  | access_token | header       | string   | 是       | 接口访问token凭证 |
  | missionId    | PathVariable | string   | 是       | 航线ID            |

- 返回值

```
{
    "code": 0,
    "msg": "操作成功",
    "data": {
        "missionId": "1827980742963765248334870439",
        "missionName": "103建图测试",
        "listMissionLinePoint": [
            {
                "longitudeDeg": 114.24295786,
                "pointIndex": 0,
                "missionId": "1827980742963765248334870439",
                "platformHeight": null,
                "platformAltitude": null,
                "speedMS": 10.0,
                "platformLongitudeDeg": null,
                "pointType": 0,
                "platformId": null,
                "latitudeDeg": 22.759179,
                "params": null,
                "cameraAction": 0,
                "command": 16,
                "loiterTimeS": 0.0,
                "platformLatitudeDeg": null,
                "platformName": null,
                "relativeAltitudeM": 120.0,
                "nodeId": null,
                "direction": null
            },
            {
                "longitudeDeg": 114.24309631,
                "pointIndex": 1,
                "missionId": "1827980742963765248334870439",
                "platformHeight": null,
                "platformAltitude": null,
                "speedMS": 10.0,
                "platformLongitudeDeg": null,
                "pointType": 0,
                "platformId": null,
                "latitudeDeg": 22.7599685,
                "params": "[{\"label\":\"云台定向拍照
                \",\"actionType\":\"directionPhoto\",\"yaw\":58.788,\"ytYaw\":0,\"ytPitch\":-90,\"zoom\":1,\"params\":
                [{\"command\":115,\"params\":[58.788,null,null,null,null,null,null]},{\"command\":205,\"params\":
                [null,-90,0,null,null,3,8]},{\"command\":205,\"params\":[1,null,null,null,null,0,9]},
                {\"command\":205,\"params\":[null,null,null,null,0,1,9]}]}]",
                "cameraAction": 0,
                "command": 16,
                "loiterTimeS": 0.0,
                "platformLatitudeDeg": null,
                "platformName": null,
                "relativeAltitudeM": 132.0,
                "nodeId": null,
                "direction": null
            },
            {
                "longitudeDeg": 114.24334797,
                "pointIndex": 2,
                "missionId": "1827980742963765248334870439",
                "platformHeight": null,
                "platformAltitude": null,
                "speedMS": 10.0,
                "platformLongitudeDeg": null,
                "pointType": 0,
                "platformId": null,
                "latitudeDeg": 22.76010911,
                "params": "[{\"label\":\"云台定向拍照
                \",\"actionType\":\"directionPhoto\",\"yaw\":58.788,\"ytYaw\":0,\"ytPitch\":-90,\"zoom\":1,\"params\":
                [{\"command\":115,\"params\":[58.788,null,null,null,null,null,null]},{\"command\":205,\"params\":
                [null,-90,0,null,null,3,8]},{\"command\":205,\"params\":[1,null,null,null,null,0,9]},
                {\"command\":205,\"params\":[null,null,null,null,0,1,9]}]}]",
                "cameraAction": 0,
                "command": 16,
                "loiterTimeS": 0.0,
                "platformLatitudeDeg": null,
                "platformName": null,
                "relativeAltitudeM": 132.0,
                "nodeId": null,
                "direction": null
            }
        ]
    }
}
```

- 返回字段说明

| 字段名            | 说明                            |
| ----------------- | ------------------------------- |
| missionId         | 航线ID                          |
| PointIndex        | 航点顺序                        |
| PointType         | 航点类型；0：普通航点；换电航点 |
| PlatformId        | 换电装置Id                      |
| LongitudeDeg      | 经度(度)                        |
| LatitudeDeg       | 纬度(度)                        |
| RelativeAltitudeM | 相对高度(米)                    |
| Command           | 指令码                          |
| SpeedMS           | CameraAction                    |
| CameraAction      | 相机模式                        |
| LoiterTimeS       | 悬停时间                        |
| Params            | 该航点上复杂指令的相关参数集    |

## 5.6 机场操作相关

### 5.6.1获取执行ID

- 接口说明

​       获取飞行的执行executionId

- 接口版本

  ```
  v2.0
  ```

- 接口地址

  ```
  {{base_url}}/backend/executionmission/getExecutionsIdNew
  ```

- 请求方法

  ```
  POST
  ```

- 数据提交方式

  ```
  application/json
  ```

- 请求参数

  | 参数名称     | 参数位置 | 数据类型 | 是否必须 | 参数描述          |
  | ------------ | -------- | -------- | -------- | ----------------- |
  | access_token | header   | string   | 是       | 接口访问token凭证 |
  | droneId      | body     | string   | 是       | 无人机id          |

- 返回值

```
{
    "code": 0,
    "msg": "操作成功",
    "data": "GDM001S2111103-20240824-20982456"
}
```



### 5.6.2执行任务

- 接口说明

​       执行任务航线

- 接口版本

  ```
  v2.0
  ```

- 接口地址

  ```
  {{base_url}}/portal/{nodeId}/airport/startMission
  ```

- 请求方法

  ```
  POST
  ```

- 数据提交方式

  ```
  application/json
  ```

- 请求参数

  | 参数名称        | 参数位置 | 数据类型 | 是否必须 | 参数描述                             |
  | --------------- | -------- | -------- | -------- | ------------------------------------ |
  | access_token    | header   | string   | 是       | 接口访问token凭证                    |
  | airportId       | body     | string   | 是       | 机场ID, 既获取机场列表中的platformId |
  | missionId       | body     | string   | 是       | 航线ID                               |
  | executionId     | body     | string   | 是       | 执行id                               |
  | skipFlightCheck | body     | string   | 是       | 是否校验跳点飞行                     |

- 返回值

  ```
  {
  	"code": 0,
  	"msg": ""
  }
  ```

  

### 5.6.3取消任务

- 接口说明

​       取消任务操作

- 接口版本

  ```
  v2.0
  ```

- 接口地址

  ```
  {{base_url}}/portal/{nodeId}/airport/cancelMission/{missionId}
  ```

- 请求方法

  ```
  GET
  ```

- 数据提交方式

  ```
  application/json
  ```

- 请求参数

  | 参数名称     | 参数位置     | 数据类型 | 是否必须 | 参数描述          |
  | ------------ | ------------ | -------- | -------- | ----------------- |
  | access_token | Header       | string   | 是       | 接口访问token凭证 |
  | missionId    | PathVariable | string   | 是       | 航线ID            |

- 返回值

```
{
	"code": 0,
	"msg": ""
}
```

### 5.6.4机场开门

- 接口说明

​       机场开门操作

- 接口版本

  ```
  v2.0
  ```

- 接口地址

  ```
  {{base_url}}/portal/{nodeId}/airport/openDoor?id={airportId}
  ```

- 请求方法

  ```
  GET
  ```

- 数据提交方式

  ```
  application/json
  ```

- 请求参数

  | 参数名称     | 参数位置 | 数据类型 | 是否必须 | 参数描述                             |
  | ------------ | -------- | -------- | -------- | ------------------------------------ |
  | access_token | Header   | string   | 是       | 接口访问token凭证                    |
  | airportId    | Query    | string   | 是       | 机场ID, 既获取机场列表中的platformId |

- 返回值

  ```
  {
  	"code": 0,
  	"msg": ""
  }
  ```

### 5.6.5机场重启

- 接口说明

​       机场重启操作

- 接口版本

  ```
  v2.0
  ```

- 接口地址

  ```
  {{base_url}}/portal/{nodeId}/airport/reboot?id={airportId}
  ```

- 请求方法

  ```
  GET
  ```

- 数据提交方式

  ```
  application/json
  ```

- 请求参数

  | 参数名称     | 参数位置 | 数据类型 | 是否必须 | 参数描述                             |
  | ------------ | -------- | -------- | -------- | ------------------------------------ |
  | access_token | Header   | string   | 是       | 接口访问token凭证                    |
  | airportId    | Query    | string   | 是       | 机场ID, 既获取机场列表中的platformId |

- 返回值

  ```
  {
  	"code": 0,
  	"msg": ""
  }
  ```

  

### 5.6.6机场紧急停止

- 接口说明

​       机场紧急停止操作

- 接口版本

  ```
  v2.0
  ```

- 接口地址

  ```
  {{base_url}}/portal/{nodeId}/airport/emergencyStop?id={airportId}
  ```

- 请求方法

  ```
  GET
  ```

- 数据提交方式

  ```
  application/json
  ```

- 请求参数

  | 参数名称     | 参数位置 | 数据类型 | 是否必须 | 参数描述                             |
  | ------------ | -------- | -------- | -------- | ------------------------------------ |
  | access_token | Header   | string   | 是       | 接口访问token凭证                    |
  | airportId    | Query    | string   | 是       | 机场ID, 既获取机场列表中的platformId |

- 返回值

  ```
  {
  	"code": 0,
  	"msg": ""
  }
  ```

  

### 5.6.7机场取消紧急停止

- 接口说明

​       取消机场紧急停止操作

- 接口版本

  ```
  v2.0
  ```

- 接口地址

  ```
  {{base_url}}/portal/{nodeId}/airport/cancelEmergencyStop?id={airportId}
  ```

- 请求方法

  ```
  GET
  ```

- 数据提交方式

  ```
  application/json
  ```

- 请求参数

  | 参数名称     | 参数位置 | 数据类型 | 是否必须 | 参数描述                             |
  | ------------ | -------- | -------- | -------- | ------------------------------------ |
  | access_token | Header   | string   | 是       | 接口访问token凭证                    |
  | airportId    | Query    | string   | 是       | 机场ID, 既获取机场列表中的platformId |

- 返回值

  ```
  {
  	"code": 0,
  	"msg": ""
  }
  ```

  

## 5.7吊舱操作相关

### 5.7.1吊舱回中

- 接口说明

​       吊舱回中操作

- 接口版本

  ```
  v2.0
  ```

- 接口地址

  ```
  {{base_url}}/portal/{nodeId}/gimbal/center?id={gimbalId}
  ```

- 请求方法

  ```
  GET
  ```

- 数据提交方式

  ```
  application/json
  ```

- 请求参数

  | 参数名称     | 参数位置 | 数据类型 | 是否必须 | 参数描述                           |
  | ------------ | -------- | -------- | -------- | ---------------------------------- |
  | access_token | Header   | string   | 是       | 接口访问token凭证                  |
  | gimbalId     | Query    | string   | 是       | 吊舱ID, 既获取吊舱列表中的gimbalId |

- 返回值

  ```
  {
  	"code": 0,
  	"msg": ""
  }
  ```

  

### 5.7.2吊舱跟随机头

- 接口说明

​       吊舱跟随机头操作

- 接口版本

  ```
  v2.0
  ```

- 接口地址

  ```
  {{base_url}}/portal/{nodeId}/gimbal/followHead?id={gimbalId}
  ```

- 请求方法

  ```
  GET
  ```

- 数据提交方式

  ```
  application/json
  ```

- 请求参数

  | 参数名称     | 参数位置 | 数据类型 | 是否必须 | 参数描述                           |
  | ------------ | -------- | -------- | -------- | ---------------------------------- |
  | access_token | Header   | string   | 是       | 接口访问token凭证                  |
  | gimbalId     | Query    | string   | 是       | 吊舱ID, 既获取吊舱列表中的gimbalId |

- 返回值

  ```
  {
  	"code": 0,
  	"msg": ""
  }
  ```

  

### 5.7.3吊舱连续动作停止

- 接口说明

​       吊舱连续动作停止操作

- 接口版本

  ```
  v2.0
  ```

- 接口地址

  ```
  {{base_url}}/portal/{nodeId}/gimbal/stop?id={gimbalId}
  ```

- 请求方法

  ```
  GET
  ```

- 数据提交方式

  ```
  application/json
  ```

- 请求参数

  | 参数名称     | 参数位置 | 数据类型 | 是否必须 | 参数描述                           |
  | ------------ | -------- | -------- | -------- | ---------------------------------- |
  | access_token | Header   | string   | 是       | 接口访问token凭证                  |
  | gimbalId     | Query    | string   | 是       | 吊舱ID, 既获取吊舱列表中的gimbalId |

- 返回值

  ```
  {
  	"code": 0,
  	"msg": ""
  }
  ```

  

### 5.7.4吊舱左转

- 接口说明

​       吊舱左转操作

- 接口版本

  ```
  v2.0
  ```

- 接口地址

  ```
  {{base_url}}/portal/{nodeId}/gimbal/left?id={gimbalId}
  ```

- 请求方法

  ```
  GET
  ```

- 数据提交方式

  ```
  application/json
  ```

- 请求参数

  | 参数名称     | 参数位置 | 数据类型 | 是否必须 | 参数描述                           |
  | ------------ | -------- | -------- | -------- | ---------------------------------- |
  | access_token | Header   | string   | 是       | 接口访问token凭证                  |
  | gimbalId     | Query    | string   | 是       | 吊舱ID, 既获取吊舱列表中的gimbalId |

- 返回值

  ```
  {
  	"code": 0,
  	"msg": ""
  }
  ```

  

### 5.7.5吊舱右转

- 接口说明

​       吊舱右转操作

- 接口版本

  ```
  v2.0
  ```

- 接口地址

  ```
  {{base_url}}/portal/{nodeId}/gimbal/right?id={gimbalId}
  ```

- 请求方法

  ```
  GET
  ```

- 数据提交方式

  ```
  application/json
  ```

- 请求参数

  | 参数名称     | 参数位置 | 数据类型 | 是否必须 | 参数描述                           |
  | ------------ | -------- | -------- | -------- | ---------------------------------- |
  | access_token | Header   | string   | 是       | 接口访问token凭证                  |
  | gimbalId     | Query    | string   | 是       | 吊舱ID, 既获取吊舱列表中的gimbalId |

- 返回值

  ```
  {
  	"code": 0,
  	"msg": ""
  }
  ```

  

### 5.7.6吊舱上移

- 接口说明

​       吊舱上移操作

- 接口版本

  ```
  v2.0
  ```

- 接口地址

  ```
  {{base_url}}/portal/{nodeId}/gimbal/up?id={gimbalId}
  ```

- 请求方法

  ```
  GET
  ```

- 数据提交方式

  ```
  application/json
  ```

- 请求参数

  | 参数名称     | 参数位置 | 数据类型 | 是否必须 | 参数描述                           |
  | ------------ | -------- | -------- | -------- | ---------------------------------- |
  | access_token | Header   | string   | 是       | 接口访问token凭证                  |
  | gimbalId     | Query    | string   | 是       | 吊舱ID, 既获取吊舱列表中的gimbalId |

- 返回值

  ```
  {
  	"code": 0,
  	"msg": ""
  }
  ```

  

### 5.7.7吊舱下移

- 接口说明

​       吊舱下移操作

- 接口版本

  ```
  v2.0
  ```

- 接口地址

  ```
  {{base_url}}/portal/{nodeId}/gimbal/down?id={gimbalId}
  ```

- 请求方法

  ```
  GET
  ```

- 数据提交方式

  ```
  application/json
  ```

- 请求参数

  | 参数名称     | 参数位置 | 数据类型 | 是否必须 | 参数描述                           |
  | ------------ | -------- | -------- | -------- | ---------------------------------- |
  | access_token | Header   | string   | 是       | 接口访问token凭证                  |
  | gimbalId     | Query    | string   | 是       | 吊舱ID, 既获取吊舱列表中的gimbalId |

- 返回值

  ```
  {
  	"code": 0,
  	"msg": ""
  }
  ```

  

### 5.7.8吊舱左上移动

- 接口说明

​      吊舱左上移动操作

- 接口版本

  ```
  v2.0
  ```

- 接口地址

  ```
  {{base_url}}/portal/{nodeId}/gimbal/leftUp?id={gimbalId}
  ```

- 请求方法

  ```
  GET
  ```

- 数据提交方式

  ```
  application/json
  ```

- 请求参数

  | 参数名称     | 参数位置 | 数据类型 | 是否必须 | 参数描述                           |
  | ------------ | -------- | -------- | -------- | ---------------------------------- |
  | access_token | Header   | string   | 是       | 接口访问token凭证                  |
  | gimbalId     | Query    | string   | 是       | 吊舱ID, 既获取吊舱列表中的gimbalId |

- 返回值

  ```
  {
  	"code": 0,
  	"msg": ""
  }
  ```

  

### 5.7.9吊舱左下移动

- 接口说明

​       吊舱左下移动操作

- 接口版本

  ```
  v2.0
  ```

- 接口地址

  ```
  {{base_url}}/portal/{nodeId}/gimbal/leftDown?id={gimbalId}
  ```

- 请求方法

  ```
  GET
  ```

- 数据提交方式

  ```
  application/json
  ```

- 请求参数

  | 参数名称     | 参数位置 | 数据类型 | 是否必须 | 参数描述                           |
  | ------------ | -------- | -------- | -------- | ---------------------------------- |
  | access_token | Header   | string   | 是       | 接口访问token凭证                  |
  | gimbalId     | Query    | string   | 是       | 吊舱ID, 既获取吊舱列表中的gimbalId |

- 返回值

  ```
  {
  	"code": 0,
  	"msg": ""
  }
  ```

  

### 5.7.10吊舱右上移动

- 接口说明

​      吊舱右上移动操作

- 接口版本

  ```
  v2.0
  ```

- 接口地址

  ```
  {{base_url}}/portal/{nodeId}/gimbal/rightUp?id={gimbalId}
  ```

- 请求方法

  ```
  GET
  ```

- 数据提交方式

  ```
  application/json
  ```

- 请求参数

  | 参数名称     | 参数位置 | 数据类型 | 是否必须 | 参数描述                           |
  | ------------ | -------- | -------- | -------- | ---------------------------------- |
  | access_token | Header   | string   | 是       | 接口访问token凭证                  |
  | gimbalId     | Query    | string   | 是       | 吊舱ID, 既获取吊舱列表中的gimbalId |

- 返回值

  ```
  {
  	"code": 0,
  	"msg": ""
  }
  ```

  

### 5.7.11吊舱右下移动

- 接口说明

​       吊舱右下移动操作

- 接口版本

  ```
  v2.0
  ```

- 接口地址

  ```
  {{base_url}}/portal/{nodeId}/gimbal/rightDown?id={gimbalId}
  ```

- 请求方法

  ```
  GET
  ```

- 数据提交方式

  ```
  application/json
  ```

- 请求参数

  | 参数名称     | 参数位置 | 数据类型 | 是否必须 | 参数描述                           |
  | ------------ | -------- | -------- | -------- | ---------------------------------- |
  | access_token | Header   | string   | 是       | 接口访问token凭证                  |
  | gimbalId     | Query    | string   | 是       | 吊舱ID, 既获取吊舱列表中的gimbalId |

- 返回值

  ```
  {
  	"code": 0,
  	"msg": ""
  }
  ```

  

### 5.7.12吊舱变焦放大

- 接口说明

​      吊舱变焦放大操作

- 接口版本

  ```
  v2.0
  ```

- 接口地址

  ```
  {{base_url}}/portal/{nodeId}/gimbal/zoomIn?id={gimbalId}
  ```

- 请求方法

  ```
  GET
  ```

- 数据提交方式

  ```
  application/json
  ```

- 请求参数

  | 参数名称     | 参数位置 | 数据类型 | 是否必须 | 参数描述                           |
  | ------------ | -------- | -------- | -------- | ---------------------------------- |
  | access_token | Header   | string   | 是       | 接口访问token凭证                  |
  | gimbalId     | Query    | string   | 是       | 吊舱ID, 既获取吊舱列表中的gimbalId |

- 返回值

  ```
  {
  	"code": 0,
  	"msg": ""
  }
  ```

  

### 5.7.13吊舱变焦缩小

- 接口说明

​      吊舱变焦缩小操作

- 接口版本

  ```
  v2.0
  ```

- 接口地址

  ```
  {{base_url}}/portal/{nodeId}/gimbal/zoomOut?id={gimbalId}
  ```

- 请求方法

  ```
  GET
  ```

- 数据提交方式

  ```
  application/json
  ```

- 请求参数

  | 参数名称     | 参数位置 | 数据类型 | 是否必须 | 参数描述                           |
  | ------------ | -------- | -------- | -------- | ---------------------------------- |
  | access_token | Header   | string   | 是       | 接口访问token凭证                  |
  | gimbalId     | Query    | string   | 是       | 吊舱ID, 既获取吊舱列表中的gimbalId |

- 返回值

  ```
  {
  	"code": 0,
  	"msg": ""
  }
  ```

  

### 5.7.14吊舱变焦停止

- 接口说明

​       吊舱变焦停止操作

- 接口版本

  ```
  v2.0
  ```

- 接口地址

  ```
  {{base_url}}/portal/{nodeId}/gimbal/zoomStop?id={gimbalId}
  ```

- 请求方法

  ```
  GET
  ```

- 数据提交方式

  ```
  application/json
  ```

- 请求参数

  | 参数名称     | 参数位置 | 数据类型 | 是否必须 | 参数描述                           |
  | ------------ | -------- | -------- | -------- | ---------------------------------- |
  | access_token | Header   | string   | 是       | 接口访问token凭证                  |
  | gimbalId     | Query    | string   | 是       | 吊舱ID, 既获取吊舱列表中的gimbalId |

- 返回值

  ```
  {
  	"code": 0,
  	"msg": ""
  }
  ```

  

### 5.7.15吊舱一键向下

- 接口说明

​      吊舱一键向下操作

- 接口版本

  ```
  v2.0
  ```

- 接口地址

  ```
  {{base_url}}/portal/{nodeId}/gimbal/oneKeyDown?id={gimbalId}
  ```

- 请求方法

  ```
  GET
  ```

- 数据提交方式

  ```
  application/json
  ```

- 请求参数

  | 参数名称     | 参数位置 | 数据类型 | 是否必须 | 参数描述                           |
  | ------------ | -------- | -------- | -------- | ---------------------------------- |
  | access_token | Header   | string   | 是       | 接口访问token凭证                  |
  | gimbalId     | Query    | string   | 是       | 吊舱ID, 既获取吊舱列表中的gimbalId |

- 返回值

  ```
  {
  	"code": 0,
  	"msg": ""
  }
  ```

  

### 5.7.16吊舱切换视频源

- 接口说明

​       吊舱切换视频源操作

- 接口版本

  ```
  v2.0
  ```

- 接口地址

  ```
  {{base_url}}/portal/{nodeId}/gimbal/switchCam?id={gimbalId}
  ```

- 请求方法

  ```
  GET
  ```

- 数据提交方式

  ```
  application/json
  ```

- 请求参数

  | 参数名称     | 参数位置 | 数据类型 | 是否必须 | 参数描述                           |
  | ------------ | -------- | -------- | -------- | ---------------------------------- |
  | access_token | Header   | string   | 是       | 接口访问token凭证                  |
  | gimbalId     | Query    | string   | 是       | 吊舱ID, 既获取吊舱列表中的gimbalId |

- 返回值

  ```
  {
  	"code": 0,
  	"msg": ""
  }
  ```

  

### 5.7.17吊舱切换红外伪彩模式

- 接口说明

​       吊舱切换红外伪彩模式操作，循环切换 白热 黑热 黑红 墨绿红 模式

- 接口版本

  ```
  v2.0
  ```

- 接口地址

  ```
  {{base_url}}/portal/{nodeId}/gimbal/pseudoColor?id={gimbalId}
  ```

- 请求方法

  ```
  GET
  ```

- 数据提交方式

  ```
  application/json
  ```

- 请求参数

  | 参数名称     | 参数位置 | 数据类型 | 是否必须 | 参数描述                           |
  | ------------ | -------- | -------- | -------- | ---------------------------------- |
  | access_token | Header   | string   | 是       | 接口访问token凭证                  |
  | gimbalId     | Query    | string   | 是       | 吊舱ID, 既获取吊舱列表中的gimbalId |

- 返回值

  ```
  {
  	"code": 0,
  	"msg": ""
  }
  ```

  

### 5.7.18吊舱追踪

- 接口说明

​      吊舱追踪操作

- 接口版本

  ```
  v2.0
  ```

- 接口地址

  ```
  {{base_url}}/portal/{nodeId}/gimbal/track
  ```

- 请求方法

  ```
  GET
  ```

- 数据提交方式

  ```
  application/json
  ```

- 请求参数

  | 参数名称     | 参数位置 | 数据类型 | 是否必须 | 参数描述                           |
  | ------------ | -------- | -------- | -------- | ---------------------------------- |
  | access_token | Header   | string   | 是       | 接口访问token凭证                  |
  | id           | body     | string   | 是       | 吊舱ID, 既获取吊舱列表中的gimbalId |
  | x            | body     | double   | 是       | 画面中心点为 (0, 0), x轴距离       |
  | y            | body     | double   | 是       | 画面中心点为 (0, 0), y轴距离       |

- 返回值

  ```
  {
  	"code": 0,
  	"msg": ""
  }
  ```

  

### 5.7.19停止吊舱追踪

- 接口说明

​       停止吊舱追踪操作

- 接口版本

  ```
  v2.0
  ```

- 接口地址

  ```
  {{base_url}}/portal/{nodeId}/gimbal/stopTrack?id={gimbalId}
  ```

- 请求方法

  ```
  GET
  ```

- 数据提交方式

  ```
  application/json
  ```

- 请求参数

  | 参数名称     | 参数位置 | 数据类型 | 是否必须 | 参数描述                           |
  | ------------ | -------- | -------- | -------- | ---------------------------------- |
  | access_token | Header   | string   | 是       | 接口访问token凭证                  |
  | gimbalId     | Query    | string   | 是       | 吊舱ID, 既获取吊舱列表中的gimbalId |

- 返回值

  ```
  {
  	"code": 0,
  	"msg": ""
  }
  ```

  

### 5.7.20切换红外数字放大

- 接口说明

​       切换红外数字放大操作

- 接口版本

  ```
  v2.0
  ```

- 接口地址

  ```
  {{base_url}}/portal/{nodeId}/gimbal/irZoom?id={gimbalId}
  ```

- 请求方法

  ```
  GET
  ```

- 数据提交方式

  ```
  application/json
  ```

- 请求参数

  | 参数名称     | 参数位置 | 数据类型 | 是否必须 | 参数描述                           |
  | ------------ | -------- | -------- | -------- | ---------------------------------- |
  | access_token | Header   | string   | 是       | 接口访问token凭证                  |
  | gimbalId     | Query    | string   | 是       | 吊舱ID, 既获取吊舱列表中的gimbalId |

- 返回值

  ```
  {
  	"code": 0,
  	"msg": ""
  }
  ```

  

### 5.7.21打开红点指示器

- 接口说明

​       打开红点指示器操作

- 接口版本

  ```
  v2.0
  ```

- 接口地址

  ```
  {{base_url}}/portal/{nodeId}/gimbal/irZoom?id={gimbalId}
  ```

- 请求方法

  ```
  GET
  ```

- 数据提交方式

  ```
  application/json
  ```

- 请求参数

  | 参数名称     | 参数位置 | 数据类型 | 是否必须 | 参数描述                           |
  | ------------ | -------- | -------- | -------- | ---------------------------------- |
  | access_token | Header   | string   | 是       | 接口访问token凭证                  |
  | gimbalId     | Query    | string   | 是       | 吊舱ID, 既获取吊舱列表中的gimbalId |

- 返回值

  ```
  {
  	"code": 0,
  	"msg": ""
  }
  ```

  

### 5.7.22关闭红点指示器

- 接口说明

​       关闭红点指示器操作

- 接口版本

  ```
  v2.0
  ```

- 接口地址

  ```
  {{base_url}}/portal/{nodeId}/gimbal/redDotIndicatorOff?id={gimbalId}
  ```

- 请求方法

  ```
  GET
  ```

- 数据提交方式

  ```
  application/json
  ```

- 请求参数

  | 参数名称     | 参数位置 | 数据类型 | 是否必须 | 参数描述                           |
  | ------------ | -------- | -------- | -------- | ---------------------------------- |
  | access_token | Header   | string   | 是       | 接口访问token凭证                  |
  | gimbalId     | Query    | string   | 是       | 吊舱ID, 既获取吊舱列表中的gimbalId |

- 返回值

  ```
  {
  	"code": 0,
  	"msg": ""
  }
  ```

  

## 5.8.无人机操作相关

### 5.8.1设置吊舱航向角俯仰角

- 接口说明

​       设置吊舱航向角俯仰角指令

- 接口版本

  ```
  v2.0
  ```

- 接口地址

  ```
  {{base_url}}/portal/{nodeId}/drone/setYawPitch
  ```

- 请求方法

  ```
  POST
  ```

- 数据提交方式

  ```
  application/json
  ```

- 请求参数

  | 参数名称     | 参数位置 | 数据类型 | 是否必须 | 参数描述                           |
  | ------------ | -------- | -------- | -------- | ---------------------------------- |
  | access_token | Header   | string   | 是       | 接口访问token凭证                  |
  | id           | Body     | string   | 是       | 吊舱ID, 既获取吊舱列表中的gimbalId |
  | yaw          | Body     | string   | 是       | 航向角, [-180, 180]                |
  | pitch        | Body     | string   | 是       | 俯仰角度, [-120, 90]               |

- 返回值

  ```
  {
  	"code": 0,
  	"msg": ""
  }
  ```

  

### 5.8.2起飞并悬停

- 接口说明

​       用于飞机已通电情况下直接arm起飞后并悬停操作

- 接口版本

  ```
  v2.0
  ```

- 接口地址

  ```
  {{base_url}}/portal/{nodeId}/drone/takeOff?id={droneId}
  ```

- 请求方法

  ```
  GET
  ```

- 数据提交方式

  ```
  application/json
  ```

- 请求参数

  | 参数名称     | 参数位置 | 数据类型 | 是否必须 | 参数描述                             |
  | ------------ | -------- | -------- | -------- | ------------------------------------ |
  | access_token | Header   | string   | 是       | 接口访问token凭证                    |
  | id           | Query    | string   | 是       | droneId, 既获取无人机列表中的droneId |

- 返回值

  ```
  {
  	"code": 0,
  	"msg": ""
  }
  ```

  

### 5.8.3一键起飞

- 接口说明

​       无任务模式直接上电起飞，起飞后悬停，一般配合指点功能使用

- 接口版本

  ```
  v2.0
  ```

- 接口地址

  ```
  {{base_url}}/portal/{nodeId}/airport/oneKeyTakeoffInAirport
  ```

- 请求方法

  ```
  POST
  ```

- 数据提交方式

  ```
  application/json
  ```

- 请求参数

  | 参数名称     | 参数位置 | 数据类型 | 是否必须 | 参数描述                                   |
  | ------------ | -------- | -------- | -------- | ------------------------------------------ |
  | access_token | Header   | string   | 是       | 接口访问token凭证                          |
  | airportID    | Body     | string   | 是       | platformId, 既获取无人机列表中的platformId |
  | droneID      | Body     | string   | 是       | droneId, 既获取无人机列表中的droneId       |

- 返回值

  ```
  {
  	"code": 0,
  	"msg": ""
  }
  ```

  

### 5.8.4指点飞行

- 接口说明

​       继续执行任务指令

- 接口版本

  ```
  v2.0
  ```

- 接口地址

  ```
  {{base_url}}/portal/{nodeId}/drone/goTo
  ```

- 请求方法

  ```
  POST
  ```

- 数据提交方式

  ```
  application/json
  ```

- 请求参数

  | 参数名称     | 参数位置 | 数据类型 | 是否必须 | 参数描述                                   |
  | ------------ | -------- | -------- | -------- | ------------------------------------------ |
  | access_token | Header   | string   | 是       | 接口访问token凭证                          |
  | id           | Body     | string   | 是       | droneId, 既获取无人机列表中的droneId       |
  | longitude    | Body     | double   | 是       | 精度                                       |
  | latitude     | Body     | double   | 是       | 维度                                       |
  | altitudeMsl  | Body     | double   | 是       | 绝对高度,米                                |
  | altitude     | Body     | double   | 是       | 相对高度,米, 仅在 altitudeMsl 不存在时有效 |
  | obstacle     | Body     | double   | 是       | 障碍物高度，米                             |
  | velocity     | Body     | double   | 是       | 速度                                       |

- 返回值

### 5.8.5仿地飞行

- 接口说明

​      仿地飞行操作

- 接口版本

  ```
  v2.0
  ```

- 接口地址

  ```
  {{base_url}}/portal/{nodeId}/drone/preciseGoTo
  ```

- 请求方法

  ```
  POST
  ```

- 数据提交方式

  ```
  application/json
  ```

- 请求参数

  | 参数名称     | 参数位置 | 数据类型 | 是否必须 | 参数描述                             |
  | ------------ | -------- | -------- | -------- | ------------------------------------ |
  | access_token | Header   | string   | 是       | 接口访问token凭证                    |
  | id           | Body     | string   | 是       | droneId, 既获取无人机列表中的droneId |
  | longitude    | Body     | double   | 是       | 精度                                 |
  | latitude     | Body     | double   | 是       | 维度                                 |
  | heights      | Body     | double   | 是       | 高度：[ 10.0, 15.0 ]    相对高度米   |
  | interval     | Body     | double   | 是       | 间隔距离,米                          |

- 返回值

  ```
  {
  	"code": 0,
  	"msg": ""
  }
  ```

  

### 5.8.6继续执行任务

- 接口说明

​       继续执行任务指令

- 接口版本

  ```
  v2.0
  ```

- 接口地址

  ```
  {{base_url}}/portal/{nodeId}/drone/continueMission?id={droneId}
  ```

- 请求方法

  ```
  GET
  ```

- 数据提交方式

  ```
  application/json
  ```

- 请求参数

  | 参数名称     | 参数位置 | 数据类型 | 是否必须 | 参数描述                             |
  | ------------ | -------- | -------- | -------- | ------------------------------------ |
  | access_token | Header   | string   | 是       | 接口访问token凭证                    |
  | id           | Query    | string   | 是       | droneId, 既获取无人机列表中的droneId |

- 返回值

  {
  	"code": 0,
  	"msg": ""
  }

### 5.8.7无人机悬停

- 接口说明

​      无人机悬停指令

- 接口版本

  ```
  v2.0
  ```

- 接口地址

  ```
  {{base_url}}/portal/{nodeId}/drone/hold?id={droneId}
  ```

- 请求方法

  ```
  GET
  ```

- 数据提交方式

  ```
  application/json
  ```

- 请求参数

  | 参数名称     | 参数位置 | 数据类型 | 是否必须 | 参数描述                             |
  | ------------ | -------- | -------- | -------- | ------------------------------------ |
  | access_token | Header   | string   | 是       | 接口访问token凭证                    |
  | id           | Query    | string   | 是       | droneId, 既获取无人机列表中的droneId |

- 返回值

  ```
  {
  	"code": 0,
  	"msg": ""
  }
  ```

  

### 5.8.8无人机返航

- 接口说明

​      无人机返航指令

- 接口版本

  ```
  v2.0
  ```

- 接口地址

  ```
  {{base_url}}/portal/{nodeId}/drone/return?id={droneId}
  ```

- 请求方法

  ```
  GET
  ```

- 数据提交方式

  ```
  application/json
  ```

- 请求参数

  | 参数名称     | 参数位置 | 数据类型 | 是否必须 | 参数描述                             |
  | ------------ | -------- | -------- | -------- | ------------------------------------ |
  | access_token | Header   | string   | 是       | 接口访问token凭证                    |
  | id           | Query    | string   | 是       | droneId, 既获取无人机列表中的droneId |

- 返回值

  ```
  {
  	"code": 0,
  	"msg": ""
  }
  ```

  

### 5.8.9虚拟摇杆操作

- 接口说明

​      虚拟摇杆操作

- 接口版本

  ```
  v2.0
  ```

- 接口地址

  ```
  {{base_url}}/portal/{nodeId}/drone/continuousOP
  ```

- 请求方法

  ```
  POST
  ```

- 数据提交方式

  ```
  application/json
  ```

- 请求参数

  | 参数名称     | 参数位置 | 数据类型 | 是否必须 | 参数描述                             |
  | ------------ | -------- | -------- | -------- | ------------------------------------ |
  | access_token | Header   | string   | 是       | 接口访问token凭证                    |
  | id           | Body     | string   | 是       | droneId, 既获取无人机列表中的droneId |
  | op           | Body     | int      | 是       | ContinuousOP 码                      |
  | speed        | Body     | double   | 是       | 速度                                 |

- 返回值

  ```
  {
  	"code": 0,
  	"msg": ""
  }
  ```

  ### ContinuousOP 码说明

  | ContinuousOP | 描述       |
  | ------------ | ---------- |
  | 0            | 停止       |
  | 1            | 升高       |
  | 2            | 降高       |
  | 3            | 左移       |
  | 4            | 右移       |
  | 5            | 前进       |
  | 6            | 后退       |
  | 7            | 顺时钟旋转 |
  | 8            | 逆时钟旋转 |

  

### 5.8.10航向锁定

- 接口说明

​       航向锁定操作

- 接口版本

  ```
  v2.0
  ```

- 接口地址

  ```
  {{base_url}}/portal/{nodeId}/drone/lockYaw
  ```

- 请求方法

  ```
  POST
  ```

- 数据提交方式

  ```
  application/json
  ```

- 请求参数

  | 参数名称     | 参数位置 | 数据类型 | 是否必须 | 参数描述                             |
  | ------------ | -------- | -------- | -------- | ------------------------------------ |
  | access_token | Header   | string   | 是       | 接口访问token凭证                    |
  | id           | Body     | string   | 是       | droneId, 既获取无人机列表中的droneId |
  | yaw          | Body     | double   | 是       | 航向角                               |

- 返回值

  ```
  {
  	"code": 0,
  	"msg": ""
  }
  ```


### 5.8.11查询航向锁定

- 接口说明

​      查询航向锁定操作

- 接口版本

  ```
  v2.0
  ```

- 接口地址

  ```
  {{base_url}}/portal/{nodeId}/drone/queryLockYaw?id={droneId}
  ```

- 请求方法

  ```
  GET
  ```

- 数据提交方式

  ```
  application/json
  ```

- 请求参数

  | 参数名称     | 参数位置 | 数据类型 | 是否必须 | 参数描述                             |
  | ------------ | -------- | -------- | -------- | ------------------------------------ |
  | access_token | Header   | string   | 是       | 接口访问token凭证                    |
  | id           | Query    | string   | 是       | droneId, 既获取无人机列表中的droneId |

- 返回值

  ```
  {
  	"code": 0,
  	"msg": ""
  	"data": "220"
  }
  ```


### 5.8.12设置返航高度

- 接口说明

​      设置返航高度

- 接口版本

  ```
  v2.0
  ```

- 接口地址

  ```
  {{base_url}}/portal/{nodeId}/drone/setReturnAltitude
  ```

- 请求方法

  ```
  POST
  ```

- 数据提交方式

  ```
  application/json
  ```

- 请求参数

  | 参数名称     | 参数位置 | 数据类型 | 是否必须 | 参数描述                             |
  | ------------ | -------- | -------- | -------- | ------------------------------------ |
  | access_token | Header   | string   | 是       | 接口访问token凭证                    |
  | id           | Body     | string   | 是       | droneId, 既获取无人机列表中的droneId |
  | altitude     | Body     | double   | 是       | 返航高度                             |

- 返回值

  ```
  {
  	"code": 0,
  	"msg": ""
  }
  ```


### 5.8.13查询返航高度

- 接口说明

​       查询返航高度

- 接口版本

  ```
  v2.0
  ```

- 接口地址

  ```
  {{base_url}}/portal/{nodeId}/drone/queryReturnAltitude?id={droneId}
  ```

- 请求方法

  ```
  GET
  ```

- 数据提交方式

  ```
  application/json
  ```

- 请求参数

  | 参数名称     | 参数位置 | 数据类型 | 是否必须 | 参数描述                             |
  | ------------ | -------- | -------- | -------- | ------------------------------------ |
  | access_token | Header   | string   | 是       | 接口访问token凭证                    |
  | id           | Query    | string   | 是       | droneId, 既获取无人机列表中的droneId |

- 返回值

  ```
  {
  	"code": 0,
  	"msg": ""
  	"data": "150.0"
  }
  ```


### 5.8.14环绕飞行

- 接口说明

​       环绕飞行操作

- 接口版本

  ```
  v2.0
  ```

- 接口地址

  ```
  {{base_url}}/portal/{nodeId}/drone/orbit
  ```

- 请求方法

  ```
  POST
  ```

- 数据提交方式

  ```
  application/json
  ```

- 请求参数

  | 参数名称         | 参数位置 | 数据类型 | 是否必须 | 参数描述                             |
  | ---------------- | -------- | -------- | -------- | ------------------------------------ |
  | access_token     | Header   | string   | 是       | 接口访问token凭证                    |
  | id               | Body     | string   | 是       | droneId, 既获取无人机列表中的droneId |
  | radius           | Body     | double   | 是       | 半径,米                              |
  | velocity         | Body     | double   | 是       | 速度, 正数：顺时钟， 负数：逆时钟    |
  | longitude        | Body     | double   | 是       | 经度                                 |
  | latitude         | Body     | double   | 是       | 纬度                                 |
  | altitude         | Body     | double   | 是       | 海拔                                 |
  | counterClockwise | Body     | double   | 是       | 是否逆时钟                           |

- 返回值

  ```
  {
  	"code": 0,
  	"msg": ""
  }
  ```


### 5.8.15指点朝向

- 接口说明

​      指点朝向操作

- 接口版本

  ```
  v2.0
  ```

- 接口地址

  ```
  {{base_url}}/portal/{nodeId}/drone/conditionYaw
  ```

- 请求方法

  ```
  POST
  ```

- 数据提交方式

  ```
  application/json
  ```

- 请求参数

  | 参数名称     | 参数位置 | 数据类型 | 是否必须 | 参数描述                                 |
  | ------------ | -------- | -------- | -------- | ---------------------------------------- |
  | access_token | Header   | string   | 是       | 接口访问token凭证                        |
  | id           | Body     | string   | 是       | droneId, 既获取无人机列表中的droneId     |
  | longitude    | Body     | double   | 是       | 经度                                     |
  | latitude     | Body     | double   | 是       | 纬度                                     |
  | pitch        | Body     | double   | 是       | 俯仰角度, [-120, 90]   => "pitch": -30.0 |

- 返回值

  ```
  {
  	"code": 0,
  	"msg": ""
  }
  ```


### 5.8.16设置跟踪模式

- 接口说明

​       设置跟踪模式操作，取消跟踪模式可调用 drone/hold 切换到悬停模式

- 接口版本

  ```
  v2.0
  ```

- 接口地址

  ```
  {{base_url}}/portal/{nodeId}/drone/follow?id={droneId}
  ```

- 请求方法

  ```
  GET
  ```

- 数据提交方式

  ```
  application/json
  ```

- 请求参数

  | 参数名称     | 参数位置 | 数据类型 | 是否必须 | 参数描述                             |
  | ------------ | -------- | -------- | -------- | ------------------------------------ |
  | access_token | Header   | string   | 是       | 接口访问token凭证                    |
  | id           | Query    | string   | 是       | droneId, 既获取无人机列表中的droneId |

- 返回值

  ```
  {
  	"code": 0,
  	"msg": ""
  }
  ```


### 5.8.17设置跟踪目标

- 接口说明

​       设置跟踪目标操作

- 接口版本

  ```
  v2.0
  ```

- 接口地址

  ```
  {{base_url}}/portal/{nodeId}/drone/followTarget
  ```

- 请求方法

  ```
  POST
  ```

- 数据提交方式

  ```
  application/json
  ```

- 请求参数

  | 参数名称     | 参数位置 | 数据类型 | 是否必须 | 参数描述                             |
  | ------------ | -------- | -------- | -------- | ------------------------------------ |
  | access_token | Header   | string   | 是       | 接口访问token凭证                    |
  | id           | Body     | string   | 是       | droneId, 既获取无人机列表中的droneId |
  | longitude    | Body     | double   | 是       | 目标经度                             |
  | latitude     | Body     | double   | 是       | 目标纬度                             |

- 返回值

  ```
  {
  	"code": 0,
  	"msg": ""
  }
  ```


### 5.8.18开启/关闭 警示灯

- 接口说明

​      开启/关闭 警示灯操作

- 接口版本

  ```
  v2.0
  ```

- 接口地址

  ```
  {{base_url}}/portal/{nodeId}/drone/switchLed
  ```

- 请求方法

  ```
  POST
  ```

- 数据提交方式

  ```
  application/json
  ```

- 请求参数

  | 参数名称     | 参数位置 | 数据类型 | 是否必须 | 参数描述                               |
  | ------------ | -------- | -------- | -------- | -------------------------------------- |
  | access_token | Header   | string   | 是       | 接口访问token凭证                      |
  | id           | Body     | string   | 是       | droneId, 既获取无人机列表中的droneId   |
  | on           | Body     | boolean  | 是       | true: 打开，false: 关闭  => "on": true |

- 返回值

  ```
  {
  	"code": 0,
  	"msg": ""
  }
  ```


### 5.8.19无人机降落

- 接口说明

​      无人机降落操作

- 接口版本

  ```
  v2.0
  ```

- 接口地址

  ```
  {{base_url}}/portal/{nodeId}/drone/land
  ```

- 请求方法

  ```
  POST
  ```

- 数据提交方式

  ```
  application/json
  ```

- 请求参数

  | 参数名称     | 参数位置 | 数据类型 | 是否必须 | 参数描述                             |
  | ------------ | -------- | -------- | -------- | ------------------------------------ |
  | access_token | Header   | string   | 是       | 接口访问token凭证                    |
  | id           | Body     | string   | 是       | droneId, 既获取无人机列表中的droneId |

- 返回值

  ```
  {
  	"code": 0,
  	"msg": ""
  }
  ```


### 5.8.20设定巡航速度

- 接口说明

​      设定巡航速度操作

- 接口版本

  ```
  v2.0
  ```

- 接口地址

  ```
  {{base_url}}/portal/{nodeId}/drone/setCruiseSpeed
  ```

- 请求方法

  ```
  POST
  ```

- 数据提交方式

  ```
  application/json
  ```

- 请求参数

  | 参数名称     | 参数位置 | 数据类型 | 是否必须 | 参数描述                             |
  | ------------ | -------- | -------- | -------- | ------------------------------------ |
  | access_token | Header   | string   | 是       | 接口访问token凭证                    |
  | id           | Body     | string   | 是       | droneId, 既获取无人机列表中的droneId |
  | speed        | Body     | double   | 是       | 巡航速度                             |

- 返回值

  ```
  {
  	"code": 0,
  	"msg": ""
  }
  ```


### 5.8.21查询巡航速度

- 接口说明

​      查询返航高度

- 接口版本

  ```
  v2.0
  ```

- 接口地址

  ```
  {{base_url}}/portal/{nodeId}/drone/queryCruiseSpeed?id={droneId}
  ```

- 请求方法

  ```
  GET
  ```

- 数据提交方式

  ```
  application/json
  ```

- 请求参数

  | 参数名称     | 参数位置 | 数据类型 | 是否必须 | 参数描述                             |
  | ------------ | -------- | -------- | -------- | ------------------------------------ |
  | access_token | Header   | string   | 是       | 接口访问token凭证                    |
  | id           | Query    | string   | 是       | droneId, 既获取无人机列表中的droneId |

- 返回值

  ```
  {
  	"code": 0,
  	"msg": ""
  	"data": "10.0"
  }
  ```


### 5.8.22返航到机场

- 接口说明

​       返航到机场操作

- 接口版本

  ```
  v2.0
  ```

- 接口地址

  ```
  {{base_url}}/portal/{nodeId}/drone/returnToDock
  ```

- 请求方法

  ```
  POST
  ```

- 数据提交方式

  ```
  application/json
  ```

- 请求参数

  | 参数名称     | 参数位置 | 数据类型 | 是否必须 | 参数描述                                 |
  | ------------ | -------- | -------- | -------- | ---------------------------------------- |
  | access_token | Header   | string   | 是       | 接口访问token凭证                        |
  | droneId      | Body     | string   | 是       | droneId, 既获取无人机列表中的droneId     |
  | dockId       | Body     | double   | 是       | platformId, 既获取机场列表中的platformId |

- 返回值

  ```
  {
  	"code": 0,
  	"msg": ""
  }
  ```


## 5.9.编队飞行

### 5.9.1联合调度 - 指点

- 接口说明

​       联合调度 - 指点操作，特殊情况下需选择多台无人机进行统一调度，系统检测各无人机在第一阶段位置就位后，同一时间点前往下一阶段位置

- 接口版本

  ```
  v2.0
  ```

- 接口地址

  ```
  {{base_url}}/portal/{nodeId}/cluster/go
  ```

- 请求方法

  ```
  POST
  ```

- 数据提交方式

  ```
  application/json
  ```

- 请求参数

  | 参数名称     | 参数位置 | 数据类型 | 是否必须 | 参数描述                             |
  | ------------ | -------- | -------- | -------- | ------------------------------------ |
  | access_token | Header   | string   | 是       | 接口访问token凭证                    |
  | id           | Body     | string   | 是       | droneId, 既获取无人机列表中的droneId |
  | nodeId       | Body     | string   | 是       | nodeId                               |
  | longitude    | Body     | double   | 是       | 经度                                 |
  | latitude     | Body     | double   | 是       | 纬度                                 |
  | altitudeMsl  | Body     | double   | 是       | 绝对海拔                             |
  | velocity     | Body     | double   | 是       | 速度                                 |

示例：

```
[
	[ {
		"id": "无人机1 id",
		"nodeId": "节点1 id",
		"longitude": 114.xxxx,
		"latitude": 24.xxx,
		“altitudeMsl": 100,
		“velocity": 12.0
	}, {
		"id": "无人机2 id",
		"nodeId": "节点2 id",
		"longitude": 114.xxxx,
		"latitude": 24.xxx,
		“altitudeMsl": 100,
		“velocity": 12.0
	}],
	[ {
		"id": "无人机3 id",
		"nodeId": "节点3 id",
		"longitude": 114.xxxx,
		"latitude": 24.xxx,
		“altitudeMsl": 100,
		“velocity": 12.0
	}
   ]
] 
```



- 返回值

  ```
  {
  	"code": 0,
  	"msg": ""
  }
  ```


### 5.9.2联合调度 - 指点朝向

- 接口说明

​        联合调度 - 指点朝向操作

- 接口版本

  ```
  v2.0
  ```

- 接口地址

  ```
  {{base_url}}/portal/{nodeId}/cluster/conditionYaw
  ```

- 请求方法

  ```
  POST
  ```

- 数据提交方式

  ```
  application/json
  ```

- 请求参数

  | 参数名称     | 参数位置 | 数据类型 | 是否必须 | 参数描述                             |
  | ------------ | -------- | -------- | -------- | ------------------------------------ |
  | access_token | Header   | string   | 是       | 接口访问token凭证                    |
  | id           | Body     | string   | 是       | droneId, 既获取无人机列表中的droneId |
  | nodeId       | Body     | string   | 是       | nodeId                               |
  | longitude    | Body     | double   | 是       | 精度                                 |
  | latitude     | Body     | double   | 是       | 纬度                                 |
  | pitch        | Body     | double   | 是       | 俯仰角                               |

示例

```
[
	{
		"id": "无人机1 id",
		"nodeId": "节点1 id",
		"longitude": 113.11,
		"latitude": 22.11,
		"pitch": -33
	},
	{
		"id": "无人机2 id",
		"nodeId": "节点2 id",
		"longitude": 113.11,
		"latitude": 22.11,
		"pitch": -33
	}
]
```

返回值

```
{
	"code": 0,
	"msg": ""
}
```

### 5.9.3联合调度 - 悬停

- 接口说明

​        联合悬停操作

- 接口版本

  ```
  v2.0
  ```

- 接口地址

  ```
  {{base_url}}/portal/{nodeId}/cluster/hold
  ```

- 请求方法

  ```
  POST
  ```

- 数据提交方式

  ```
  application/json
  ```

- 请求参数

  | 参数名称     | 参数位置 | 数据类型 | 是否必须 | 参数描述                             |
  | ------------ | -------- | -------- | -------- | ------------------------------------ |
  | access_token | Header   | string   | 是       | 接口访问token凭证                    |
  | id           | Body     | string   | 是       | droneId, 既获取无人机列表中的droneId |
  | nodeId       | Body     | string   | 是       | nodeId                               |

示例

```
[
	{
		"id": "无人机1 id",
		"nodeId": "节点1 id"
	},
	{
		"id": "无人机2 id",
		"nodeId": "节点2 id"
	}
]
```

返回值

```
{
	"code": 0,
	"msg": ""
}
```

### 5.9.4联合调度 - 继续任务

- 接口说明

​        联合返航操作

- 接口版本

  ```
  v2.0
  ```

- 接口地址

  ```
  {{base_url}}/portal/{nodeId}/cluster/continue
  ```

- 请求方法

  ```
  POST
  ```

- 数据提交方式

  ```
  application/json
  ```

- 请求参数

  | 参数名称     | 参数位置 | 数据类型 | 是否必须 | 参数描述                             |
  | ------------ | -------- | -------- | -------- | ------------------------------------ |
  | access_token | Header   | string   | 是       | 接口访问token凭证                    |
  | id           | Body     | string   | 是       | droneId, 既获取无人机列表中的droneId |
  | nodeId       | Body     | string   | 是       | nodeId                               |

示例

```
[
	{
		"id": "无人机1 id",
		"nodeId": "节点1 id"
	},
	{
		"id": "无人机2 id",
		"nodeId": "节点2 id"
	}
]
```

返回值

```
{
	"code": 0,
	"msg": ""
}
```

### 5.9.2联合调度 - 返航

- 接口说明

​        联合返航操作

- 接口版本

  ```
  v2.0
  ```

- 接口地址

  ```
  {{base_url}}/portal/{nodeId}/cluster/return
  ```

- 请求方法

  ```
  POST
  ```

- 数据提交方式

  ```
  application/json
  ```

- 请求参数

  | 参数名称     | 参数位置 | 数据类型 | 是否必须 | 参数描述                             |
  | ------------ | -------- | -------- | -------- | ------------------------------------ |
  | access_token | Header   | string   | 是       | 接口访问token凭证                    |
  | id           | Body     | string   | 是       | droneId, 既获取无人机列表中的droneId |
  | nodeId       | Body     | string   | 是       | nodeId                               |

示例

```
[
	{
		"id": "无人机1 id",
		"nodeId": "节点1 id"
	},
	{
		"id": "无人机2 id",
		"nodeId": "节点2 id"
	}
]
```

返回值

```
{
	"code": 0,
	"msg": ""
}
```

## 5.10.巡航管理

### 5.10.1添加巡航记录

- 接口说明

​       添加巡航记录

- 接口版本

  ```
  v2.0
  ```

- 接口地址

  ```
  {{base_url}}/backend/executionmission/add
  ```

- 请求方法

  ```
  POST
  ```

- 数据提交方式

  ```
  application/json
  ```

- 请求参数

  | 参数名称     | 参数位置 | 数据类型 | 是否必须 | 参数描述                                                     |
  | ------------ | -------- | -------- | -------- | ------------------------------------------------------------ |
  | access_token | Header   | string   | 是       | 接口访问token凭证                                            |
  | executionsId | Body     | string   | 是       | 巡航ID, 参考 5.6.1获取执行ID                                 |
  | platformId   | Body     | string   | 是       | 机场ID                                                       |
  | droneId      | Body     | string   | 是       | 无人机ID                                                     |
  | exeType      | Body     | string   | 是       | 巡航类型：0；手动任务、1定时任务、2快速起飞、3报警响应、4跳点飞行 |
  | missionId    | Body     | string   | 是       | 航线ID                                                       |

- 返回值

  {

    "code": 0,

    "msg": "操作成功",

    "data": "GDM002S2312178-20240926-43522513"

  }

### 5.10.2结束巡航记录

- 接口说明

​       结束巡航记录

- 接口版本

  ```
  v2.0
  ```

- 接口地址

  ```
  {{base_url}}/backend/executionmission/update
  ```

- 请求方法

  ```
  POST
  ```

- 数据提交方式

  ```
  application/json
  ```

- 请求参数

  | 参数名称     | 参数位置 | 数据类型 | 是否必须 | 参数描述                         |
  | ------------ | -------- | -------- | -------- | -------------------------------- |
  | access_token | Header   | string   | 是       | 接口访问token凭证                |
  | executionsId | Body     | string   | 是       | 巡航ID                           |
  | endTime      | Body     | string   | 否       | 结束时间,格式yyyy-mm-dd hh-mm-ss |

### 5.10.3查询巡航记录

- 接口说明

​       查询巡航记录

- 接口版本

  ```
  v2.0
  ```

- 接口地址

  ```
  {{base_url}}/backend/executionmission/QueryFlightExecuteList
  ```

- 请求方法

  ```
  POST
  ```

- 数据提交方式

  ```
  application/json
  ```

- 请求参数

  | 参数名称     | 参数位置 | 数据类型 | 是否必须 | 参数描述                                                     |
  | ------------ | -------- | -------- | -------- | ------------------------------------------------------------ |
  | access_token | Header   | string   | 是       | 接口访问token凭证                                            |
  | pageNum      | Body     | int      | 是       | 开始页数                                                     |
  | pageSize     | Body     | int      | 是       | 每页大小                                                     |
  | custId       | Body     | string   | 否       | 租户ID                                                       |
  | beginTime    | Body     | string   | 否       | 开始日期 格式：yyyy-mm-dd hh:mm:ss                           |
  | endTime      | Body     | string   | 否       | 截止日期 格式：yyyy-mm-dd hh:mm:ss                           |
  | droneId      | Body     | string   | 否       | 无人机ID                                                     |
  | exeType      | Body     | string   | 否       | 巡航类型：0；手动任务、1定时任务、2快速起飞、3报警响应、4跳点飞行 |
  | missionId    | Body     | string   | 否       | 航线id                                                       |
  | missionType  | Body     | string   | 否       | 航线类型                                                     |
  | missionFlag  | Body     | string   | 否       | 任务类型                                                     |
  | IsDesc       | Body     | string   | 否       | 升序或降序（按创建时间），0 降序；1 升序                     |

- 返回值

```
{
    "code": 0,
    "msg": "查询成功",
    "data": {
        "total": 6,
        "list": [
            {
                "altitude": 0.0,
                "flightSummary": null,
                "isExeWarnActive": 0,
                "activeId": "",
                "fifthComSwitch": 1,
                "droneId": "1678574134839349248122416040",
                "missionFlyKilometer": "137m",
                "custId": "999001",
                "missionName": "120m测试航线",
                "startTime": "2024-09-26 11:34:46",
                "operateName": null,
                "activeName": "",
                "longitudeDeg": 114.2429686,
                "missionFlagName": "",
                "creator": "zjc",
                "missionId": "1629683220738084864542999075",
                "unitName": "高度创新",
                "executionsId": "GDM002S2312178-20240926-46646622",
                "minutes": 1,
                "plateformName": "龙岗-113清林径水库",
                "platformId": "1678573624660987904387873618",
                "creatName": "张金城",
                "latitudeDeg": 22.759096,
                "missionTypeName": null,
                "missionFlag": null,
                "exeTypeName": "手动执行任务",
                "endTime": "2024-09-26 11:35:25",
                "nodeId": "113",
                "droneName": "龙岗-113清林径水库",
                "exeType": 0,
                "actureFlyKilometer": 0.0
            }
        ],
        "pageNum": 1,
        "pageSize": 10,
        "size": 6,
        "startRow": 1,
        "endRow": 6,
        "pages": 1,
        "prePage": 0,
        "nextPage": 0,
        "isFirstPage": true,
        "isLastPage": true,
        "hasPreviousPage": false,
        "hasNextPage": false,
        "navigatePages": 8,
        "navigatepageNums": [
            1
        ],
        "navigateFirstPage": 1,
        "navigateLastPage": 1
    }
}
```

返回字段说明

| 字段                | 字段描述                                                     |
| ------------------- | ------------------------------------------------------------ |
| executionsId        | 巡航ID                                                       |
| custId              | 客户id                                                       |
| unitName            | 客户                                                         |
| activeId            | 事件ID                                                       |
| activeName          | 事件                                                         |
| isExeWarnActive     | 是否执行预警飞行；1 正在执行告警点任务，2 结束               |
| exeType             | 巡航类型ID：0；手动任务、1定时任务、2快速起飞、3报警响应、4跳点飞行 |
| exeTypeName         | 巡航类型                                                     |
| plateformName       | 起飞机场                                                     |
| nodeId              | 起飞机场nodeId                                               |
| platformId          | 起飞机场ID                                                   |
| longitudeDeg        | 起飞机场精度                                                 |
| latitudeDeg         | 起飞机场维度                                                 |
| droneId             | 巡飞无人机ID                                                 |
| droneName           | 巡飞无人机                                                   |
| fifthComSwitch      | 0 关闭5G， 1 打开5G                                          |
| missionId           | 航线id                                                       |
| missionName         | 航线                                                         |
| startTime           | 开始时间                                                     |
| endTime             | 结束时间                                                     |
| minutes             | 飞行时长                                                     |
| missionFlyKilometer | 航线预估执行时长                                             |
| actureFlyKilometer  | 实际飞行时长                                                 |
| missionTypeName     | 任务类型                                                     |
| missionFlag         | 飞行标签ID                                                   |
| missionFlagName     | 飞行标签                                                     |
| creator             | 巡飞员                                                       |
| creatName           | 巡飞员名                                                     |
| operateName         | 第三方实际飞手                                               |
| flightSummary       | 飞行总结                                                     |



### 5.10.4查询巡航中任务

- 接口说明

​      查询正在巡飞的任务列表

- 接口版本

  ```
  v2.0
  ```

- 接口地址

  ```
  {{base_url}}/backend/executionmission/QueryIsExecutingMissions
  ```

- 请求方法

  ```
  POST
  ```

- 数据提交方式

  ```
  application/json
  ```

- 请求参数

  | 参数名称     | 参数位置 | 数据类型 | 是否必须 | 参数描述          |
  | ------------ | -------- | -------- | -------- | ----------------- |
  | access_token | Header   | string   | 是       | 接口访问token凭证 |

- 返回值

  ```
  {
      "code": 0,
      "msg": "操作成功",
      "data": [
          {
              "flightSummary": null,
              "takePictureExceptions": "",
              "isExeWarnActive": 0,
              "activeId": null,
              "fifthComSwitch": 1,
              "missionKilometer": null,
              "droneId": "1725358456837378048289495838",
              "platformAddress": "红花岭",
              "missionFlyKilometer": null,
              "missionTypeId": null,
              "custId": "999001",
              "missionName": null,
              "startTime": "2024-09-26 14:42:26",
              "platformName": "103测试机场",
              "longitudeDeg": 114.24295786452763,
              "activeName": null,
              "creator": "flj",
              "missionId": null,
              "unitName": "高度创新",
              "executionsId": "GDM002S2312178-20240926-27075374",
              "platformId": "1725358456837378048289490001",
              "latitudeDeg": 22.759178995556777,
              "missionTypeName": null,
              "exeTypeName": "快速起飞",
              "endTime": "",
              "nodeId": "98",
              "droneName": "103无人机",
              "exeType": 2
          }
      ]
  }
  ```

  

### 5.10.5查询正在巡航的预警点

- 接口说明

​       查询正在巡航的预警点

- 接口版本

  ```
  v2.0
  ```

- 接口地址

  ```
  {{base_url}}/backend/executionmission/getWarningByExecuteId/{executeId}
  ```

- 请求方法

  ```
  POST
  ```

- 数据提交方式

  ```
  application/json
  ```

- 请求参数

  | 参数名称     | 参数位置 | 数据类型 | 是否必须 | 参数描述          |
  | ------------ | -------- | -------- | -------- | ----------------- |
  | access_token | Header   | string   | 是       | 接口访问token凭证 |
  | executeId    | Body     | string   | 是       | 巡航ID            |

- 返回值

```
{
    "code": 0,
    "msg": "操作成功",
    "data": [
        {
            "suspend": 1,
            "distance": 0.0,
            "activeLevelId": "550402",
            "endDate": null,
            "latitude": 22.75917879081023,
            "warnTriggerId": "1725686153803337728137165755",
            "beginDate": "2023-11-06 14:23:23",
            "warnName": "测试-森林火警3",
            "activeType": "森林火情",
            "activeTypeId": "560401",
            "activeLevel": "二级",
            "cameraName": "1号山头摄像机",
            "longitude": 114.24295764956,
            "createDate": "2023-11-18 09:23:35"
        },
        {
            "suspend": 0,
            "distance": 0.0,
            "activeLevelId": "550402",
            "endDate": null,
            "latitude": 22.75917879081023,
            "warnTriggerId": "1753265341712175104657366255",
            "beginDate": "2023-11-06 14:23:23",
            "warnName": "红花岭-森林火警3",
            "activeType": "森林火情",
            "activeTypeId": "560401",
            "activeLevel": "二级",
            "cameraName": "1号山头摄像机",
            "longitude": 114.24295764956,
            "createDate": "2024-02-02 11:53:26"
        }
    ]
}
```

- 返回值说明

| 字段          | 字段描述       |
| ------------- | -------------- |
| warnTriggerId | 事件ID         |
| warnName      | 事件名         |
| beginDate     | 发生时间       |
| endDate       | 结束日期       |
| longitude     | 经度           |
| latitude      | 纬度           |
| activeType    | 事件类型       |
| activeLevel   | 事件等级       |
| suspend       | 暂不处理(挂起) |
| distance      | 距离           |





### 5.10.6查询巡航关联的预警点

- 接口说明

​      查询巡航关联的预警点

- 接口版本

  ```
  v2.0
  ```

- 接口地址

  ```
  {{base_url}}/backend/executionmission/queryFlightRelationWarnPointByExecuteId/{executeId}
  ```

- 请求方法

  ```
  POST
  ```

- 数据提交方式

  ```
  application/json
  ```

- 请求参数

  | 参数名称     | 参数位置 | 数据类型 | 是否必须 | 参数描述          |
  | ------------ | -------- | -------- | -------- | ----------------- |
  | access_token | Header   | string   | 是       | 接口访问token凭证 |
  | executeId    | Body     | string   | 是       | 巡航ID            |

- 返回值

  ```
  {
      "code": 0,
      "msg": "操作成功",
      "data": [
          {
              "executionsId": "1725763500699160576460425989",
              "activeLevelId": "550402",
              "latitude": 22.75917879081023,
              "warnTriggerId": "1725686153803337728137165755",
              "activeId": "2023010909041401111129001",
              "beginDate": "2023-11-06 14:23:23",
              "warnName": "测试-森林火警3",
              "createBy": "1725684357466820608438748095",
              "activeType": "森林火情",
              "activeTypeId": "560401",
              "custId": "999001",
              "activeLevel": "二级",
              "longitude": 114.24295764956,
              "createDate": "2023-11-18 09:23:35"
          }
      ]
  }
  ```

  

- 返回值说明

| 字段          | 字段描述       |
| ------------- | -------------- |
| warnTriggerId | 事件ID         |
| warnName      | 事件名         |
| beginDate     | 发生时间       |
| endDate       | 结束日期       |
| longitude     | 经度           |
| latitude      | 纬度           |
| activeType    | 事件类型       |
| activeLevel   | 事件等级       |
| suspend       | 暂不处理(挂起) |
| distance      | 距离           |



### 5.10.7查询预警点关联的巡航

- 接口说明

​      查询预警点关联的巡航记录

- 接口版本

  ```
  v2.0
  ```

- 接口地址

  ```
  {{base_url}}/backend/executionmission/queryFlightRelationWarnPointByExecuteId/{warnTriggerId}
  ```

- 请求方法

  ```
  POST
  ```

- 数据提交方式

  ```
  application/json
  ```

- 请求参数

  | 参数名称      | 参数位置 | 数据类型 | 是否必须 | 参数描述          |
  | ------------- | -------- | -------- | -------- | ----------------- |
  | access_token  | Header   | string   | 是       | 接口访问token凭证 |
  | warnTriggerId | Body     | string   | 是       | 预警点ID          |

- 返回值

```
{
    "code": 0,
    "msg": "操作成功",
    "data": [
        {
            "flightDate": "2023-11-18 14:31:06",
            "executionsId": "1725763500699160576460425989",
            "missionName": "快速起飞"
        },
        {
            "flightDate": "2023-11-20 17:02:04",
            "executionsId": "1726526307854061568704699112",
            "missionName": "快速起飞"
        }
    ]
}
```



- 返回说明

| 字段         | 字段说明 |
| ------------ | -------- |
| executionsId | 巡航ID   |
| missionName  | 航线名   |
| flightDate   | 起飞时间 |

### 5.10.8查询正在巡航的预警点

- 接口说明

​       查询正在巡航的预警点

- 接口版本

  ```
  v2.0
  ```

- 接口地址

  ```
  {{base_url}}/backend/executionmission/getWarningByExecuteId/{executeId}
  ```

- 请求方法

  ```
  POST
  ```

- 数据提交方式

  ```
  application/json
  ```

- 请求参数

  | 参数名称     | 参数位置 | 数据类型 | 是否必须 | 参数描述          |
  | ------------ | -------- | -------- | -------- | ----------------- |
  | access_token | Header   | string   | 是       | 接口访问token凭证 |
  | executeId    | Body     | string   | 是       | 巡航ID            |

- 返回值

```
{
    "code": 0,
    "msg": "操作成功",
    "data": [
        {
            "suspend": 1,
            "distance": 0.0,
            "activeLevelId": "550402",
            "endDate": null,
            "latitude": 22.75917879081023,
            "warnTriggerId": "1725686153803337728137165755",
            "beginDate": "2023-11-06 14:23:23",
            "warnName": "测试-森林火警3",
            "activeType": "森林火情",
            "activeTypeId": "560401",
            "activeLevel": "二级",
            "cameraName": "1号山头摄像机",
            "longitude": 114.24295764956,
            "createDate": "2023-11-18 09:23:35"
        },
        {
            "suspend": 0,
            "distance": 0.0,
            "activeLevelId": "550402",
            "endDate": null,
            "latitude": 22.75917879081023,
            "warnTriggerId": "1753265341712175104657366255",
            "beginDate": "2023-11-06 14:23:23",
            "warnName": "红花岭-森林火警3",
            "activeType": "森林火情",
            "activeTypeId": "560401",
            "activeLevel": "二级",
            "cameraName": "1号山头摄像机",
            "longitude": 114.24295764956,
            "createDate": "2024-02-02 11:53:26"
        }
    ]
}
```

- 返回值说明

| 字段          | 字段描述       |
| ------------- | -------------- |
| warnTriggerId | 事件ID         |
| warnName      | 事件名         |
| beginDate     | 发生时间       |
| endDate       | 结束日期       |
| longitude     | 经度           |
| latitude      | 纬度           |
| activeType    | 事件类型       |
| activeLevel   | 事件等级       |
| suspend       | 暂不处理(挂起) |
| distance      | 距离           |

### 5.10.9查询巡航航点

- 接口说明

​     查询巡航航点

- 接口版本

  ```
  v2.0
  ```

- 接口地址

  ```
  {{base_url}}/backend/missionmonitor/QueryMissionExecuteLinePoint/{executeId}
  ```

- 请求方法

  ```
  POST
  ```

- 数据提交方式

  ```
  application/json
  ```

- 请求参数

  | 参数名称     | 参数位置 | 数据类型     | 是否必须 | 参数描述          |
  | ------------ | -------- | ------------ | -------- | ----------------- |
  | access_token | Header   | string       | 是       | 接口访问token凭证 |
  | executionsId | Body     | PathVariable | 是       | 巡航ID            |

- 返回值

```
{
    "code": 0,
    "msg": "操作成功",
    "data": [
        {
            "monitorId": "1790318020028141568817493347",
            "executionsId": "GDM002S2312178-20240514-77381979",
            "droneId": "1725358456837378048289495838",
            "recordTime": "2024-05-14 17:47:33.128",
            "latitudeDeg": 22.759178995556777,
            "longitudeDeg": 114.24295786452764,
            "altitude": 57.0,
            "altitudeRelative": 0.0,
            "landedState": "2",
            "flightMode": "2",
            "roll": 0.0,
            "pitch": 0.0,
            "yaw": 0.0,
            "gPSCount": 35,
            "groundSpeed": 10.0,
            "voltage": 0.0,
            "distance": 0.0,
            "batteryLife": 85.0,
            "connected": "true",
            "msg": "",
            "armed": "true",
            "throttle": 0.0,
            "bmsTemp": 0.0,
            "secGpsCount": 0,
            "pwm": null,
            "pwms": null,
            "windN": 0.0,
            "windE": 0.0,
            "current": 0.0
        }
    ]
}
```

- 返回值说明

| 字段             | 字段描述                                                     |
| ---------------- | ------------------------------------------------------------ |
| MonitorId        | 航点ID                                                       |
| ExecutionsId     | 任务执行id                                                   |
| DroneId          | 无人机ID                                                     |
| RecordTime       | 监测时间                                                     |
| LongitudeDeg     | 经度(度)                                                     |
| LatitudeDeg      | 纬度(度)                                                     |
| Distance         | 公里数                                                       |
| Altitude         | 海拔高度(米)                                                 |
| AltitudeRelative | 相对高度(米)                                                 |
| LandedState      | 飞行状态 1 ON_GROUND：已经降落，2 IN_AIR：3 在空中，TAKING_OFF：正在起飞，4 LANDING：正在降薪 UNKNOWN：不明状态 |
| FlightMode       | 是否已经解锁                                                 |
| Roll             | 翻滚角                                                       |
| Pitch            | 俯仰角                                                       |
| Yaw              | 航向角                                                       |
| GPSCount         | 卫星个数                                                     |
| GroundSpeed      | 地面速度                                                     |
| Voltage          | 电池电压                                                     |
| BatteryLife      | 剩余电量百分比                                               |
| Connected        | 连接状态                                                     |
| Msg              | 无人机发送的的状态文本                                       |
| Armed            | 是否已经解锁                                                 |
| Throttle         | 油门                                                         |
| BmsTemp          | BMS温度                                                      |
| SecGpsCount      | 备用GPS星数                                                  |
| Pwm              | SecGpsCount                                                  |
| WindN            | 估计风速N                                                    |
| WindE            | 估计风速E                                                    |
| Current          | 无人机电流                                                   |

### 5.10.10查询巡航图片

- 接口说明

​      查询巡航记录的图片信息

- 接口版本

  ```
  v2.0
  ```

- 接口地址

  ```
  {{base_url}}/backend/VideoCutPic/queryVideoCutPicByCondition/{executeId}
  ```

- 请求方法

  ```
  POST
  ```

- 数据提交方式

  ```
  application/json
  ```

- 请求参数

  | 参数名称     | 参数位置 | 数据类型 | 是否必须 | 参数描述                                      |
  | ------------ | -------- | -------- | -------- | --------------------------------------------- |
  | access_token | Header   | string   | 是       | 接口访问token凭证                             |
  | executionsId | Body     | string   | 是       | 巡航ID                                        |
  | aiFlag       | Body     | string   | 是       | 默认值 0；0:普通图片；1 ai图片 2，UE5采集图片 |
  | pageNum      | Body     | string   | 是       | 1                                             |
  | pageSize     | Body     | string   | 是       | 20                                            |

- 返回值

```
{
    "code": 0,
    "msg": "operate success.",
    "data": {
        "total": 22,
        "list": [
            {
                "longitudeDeg": 114.24563055555555,
                "aiTypeName": "",
                "altitude": null,
                "bucketName": "gdcx-dev",
                "gimbalYaw": null,
                "fileName": "GDCX_20240824083013_0021.jpg",
                "missionId": "1827261040075616256680039817",
                "gimbalPitch": null,
                "executionsId": "GDM001S2111103-20240824-69035621",
                "picType": "0",
                "filePath": "UE5/999001/2024-08-24/GDM001S2111103-20240824-69035621",
                "aiTypeId": null,
                "remark": "",
                "flagId": null,
                "latitudeDeg": 22.75592222222222,
                "videoCutPicId": "1827262827046252544444978857",
                "createBy": "10000100000999900000000001",
                "fileSize": "3.02 MB",
                "flagName": null,
                "auditStatus": 0,
                "fileUrl": "https://gdcx-dev.oss-cn-shenzhen.aliyuncs.com/UE5/999001/2024-08-2421/GDCX_20240824083013_0021.jpg",
                "aiFlag": 2,
                "createDate": "2024-08-24 16:33:01"
            },
            {
                "longitudeDeg": 114.24562777777778,
                "aiTypeName": "",
                "altitude": null,
                "bucketName": "gdcx-dev",
                "gimbalYaw": null,
                "fileName": "GDCX_20240824083017_0022.jpg",
                "missionId": "1827261040075616256680039817",
                "gimbalPitch": null,
                "executionsId": "GDM001S2111103-20240824-69035621",
                "picType": "0",
                "filePath": "UE5/999001/2024-08-24/GDM001S2111103-20240824-69035621",
                "aiTypeId": null,
                "remark": "",
                "flagId": null,
                "latitudeDeg": 22.756058333333332,
                "videoCutPicId": "1827262957027733504683215437",
                "createBy": "10000100000999900000000001",
                "fileSize": "2.96 MB",
                "flagName": null,
                "auditStatus": 0,
                "fileUrl": "https://gdcx-dev.oss-cn-shenzhen.aliyuncs.com/UE5/999001/2024-08-24/GDM001S2111103-20017_0022.jpg",
                "aiFlag": 2,
            }
        ],
        "pageNum": 1,
        "pageSize": 25,
        "size": 22,
        "startRow": 1,
        "endRow": 22,
        "pages": 1,
        "prePage": 0,
        "nextPage": 0,
        "isFirstPage": true,
        "isLastPage": true,
        "hasPreviousPage": false,
        "hasNextPage": false,
        "navigatePages": 8,
        "navigatepageNums": [
            1
        ],
        "navigateFirstPage": 1,
        "navigateLastPage": 1
    }
}
```

- 返回值说明

| 字段          | 字段描述                            |
| ------------- | ----------------------------------- |
| videoCutPicId | 事件ID                              |
| missionId     | 任务ID                              |
| executionsId  | 巡航id                              |
| latitudeDeg   | 经度                                |
| longitudeDeg  | 纬度                                |
| aiFlag        | 0:普通图片；1 ai图片 2，UE5采集图片 |
| auditStatus   | 审核状态                            |
| aiTypeId      | ai类型ID                            |
| aiTypeName    | ai类型                              |
| picType       | 0正常 1绿色常规 2黄色警告 3红色异常 |
| gimbalPitch   | 吊舱航向角                          |
| gimbalYaw     | 吊舱俯仰角                          |
| altitude      | 无人机海拔                          |
| bucketName    | 桶名                                |
| fileName      | 文件名                              |
| filePath      | 文件路径                            |
| fileUrl       | 地址                                |
| fileSize      | 大小                                |
| remark        | 备注                                |
| flagName      | 标会名                              |

### 5.10.11查询巡航视频

- 接口说明

​     查询巡航视频

- 接口版本

  ```
  v2.0
  ```

- 接口地址

  ```
  {{base_url}}/backend/videorecord/QueryVideoRecord/{executeId}
  ```

- 请求方法

  ```
  POST
  ```

- 数据提交方式

  ```
  application/json
  ```

- 请求参数

  | 参数名称     | 参数位置    | 数据类型 | 是否必须 | 参数描述          |
  | ------------ | ----------- | -------- | -------- | ----------------- |
  | access_token | Header      | string   | 是       | 接口访问token凭证 |
  | executionsId | pathVarable | string   | 是       | 巡航ID            |

- 返回值

```
{
    "code": 0,
    "msg": "查询成功",
    "data": [
        {
            "fileName": null,
            "endTime": "2024-09-13 16:05:08",
            "createDate": "2024-09-13 16:05:08.000",
            "createBy": "10000100000999900000000001",
            "bucketName": null,
            "executionsId": "GDM002S2312178-20240913-75276448",
            "cameraId": "1725359469224923136146623831",
            "custId": "999001",
            "beginTime": "2024-09-13 15:02:46",
            "unitName": null,
            "missionId": "",
            "filePath": null,
            "missionName": null,
            "nodeId": null,
            "playPath": "record/192.168.98.151/static/1725359469224923136146623831_20240913150246.mp4",
            "videoRecordId": "1834503568708018176479627052",
            "videoType": 0,
            "storeType": 1,
            "payLong": null,
            "cameraName": null
        }
    ]
}
```

- 返回值说明

| 字段          | 字段描述                                                     |
| ------------- | ------------------------------------------------------------ |
| VideoRecordId | 视频ID                                                       |
| executionsId  | 巡航id                                                       |
| custId        | 租户ID                                                       |
| missionId     | 航线id                                                       |
| cameraId      | 摄像机ID                                                     |
| videoType     | 0:吊舱(普通视频); 1 ai视频；2;机舱外-起飞视频，3：机舱外-降落视频 4:机舱内-起飞视频；5.机场内-降落视频 |
| storeType     | 文件存储类型,0: 自组网本地路径,1:自组网云端地址,2:云端绝对地址,3:云端相对地址 |
| bucketName    | 桶名                                                         |
| fileName      | 文件名                                                       |
| filePath      | 文件路径                                                     |
| fileUrl       | 地址                                                         |
| fileSize      | 大小                                                         |
| remark        | 备注                                                         |
| flagName      | 标会名                                                       |

## 5.11.预警管理

### 5.11.1预警推送

- 接口说明

​       第三方平台推送预警 信息到无人机远程调度平台

- 接口版本

  ```
  v2.0
  ```

- 接口地址

  ```
  {{base_url}}/gis/warn/trigger
  ```

- 请求方法

  ```
  POST
  ```

- 数据提交方式

  ```
  application/json
  ```

- 请求参数

  | 参数名称      | 参数位置 | 数据类型 | 是否必须 | 参数描述                                                     |
  | ------------- | -------- | -------- | -------- | ------------------------------------------------------------ |
  | access_token  | Header   | string   | 是       | 接口访问token凭证                                            |
  | activeId      | Body     | string   | 是       | 巡航ID, 参考 5.6.1获取执行ID                                 |
  | platformId    | Body     | string   | 是       | 机场ID, 该字段不为空，则将触发该机场中的无人机巡飞到预警点，一般不填 |
  | activeTypeId  | Body     | string   | 否       | 事件类型id                                                   |
  | activeLevelId | Body     | string   | 否       | 事件等级id                                                   |
  | warnName      | Body     | string   | 是       | 预警名                                                       |
  | imgUrl        | Body     | string   | 否       | 预警图片访问地址                                             |
  | cameraName    | Body     | string   | 否       | 摄像机名                                                     |
  | beginDate     | Body     | string   | 是       | 发生时间; 时间格式："2023-11-09 11:36:22"                    |
  | longitude     | Body     | double   | 是       | 精度                                                         |
  | latitude      | Body     | double   | 是       | 维度                                                         |
  | remark        | Body     | string   | 否       | 备注                                                         |

- 返回值

  ```
  {
      "code": 0,
      "msg": "操作成功",
      "data": null
  }
  ```

​       ![image-20240927100255068](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\image-20240927100255068.png)



### 5.11.2预警结束

- 接口说明

​       第三方平台推送预警结束信息到无人机远程调度平台,预警将自动结束

- 接口版本

  ```
  v2.0
  ```

- 接口地址

  ```
  {{base_url}}/gis/warn/end
  ```

- 请求方法

  ```
  POST
  ```

- 数据提交方式

  ```
  application/json
  ```

- 请求参数

  | 参数名称     | 参数位置 | 数据类型 | 是否必须 | 参数描述                                 |
  | ------------ | -------- | -------- | -------- | ---------------------------------------- |
  | access_token | Header   | string   | 是       | 接口访问token凭证                        |
  | activeId     | Body     | string   | 是       | 巡航ID, 参考 5.6.1获取执行ID             |
  | endDate      | Body     | string   | 是       | 结束时间 时间格式："2023-11-09 11:36:22" |

- 返回值

  ```
  {
      "code": 0,
      "msg": "操作成功",
      "data": nul
  }
  ```

  

## 5.12.实时消息订阅

本文档介绍MQTT topic以及对应的消息体

### 5.12.1 js 连接demo

https://gitee.com/romeo_zpl/gdoc/tree/master/mqtt_demo



### 5.12.2订阅机场实时数据

- Topic

  ```
  node/{nodeId}/ap/{platdormId}/station
  ```

  

- Body

  ```
  {
  	"version": 0,               // 机场型号,见AirportVersion 定义
      "allowRemoteControl": 1,    // 是否允许远程控制
  	"connected": 1,             // 是否连接
  	"missionState": 1,          // 任务阶段
      "emergency": 0,             // 机场紧急模式
      "fault":  0,                // 机场错误模式
  	"innerHumidity": 55.0,      // 内部湿度
  	"innerTemperature": 35.0,   // 内部温度
  	"interruptDone": 1,         // 复位是否完成
      "takeOffDone": 1,           // 飞机起飞完毕
      "landingDone": 0,           // 飞机降落完毕
  	"landingReady": 0,          // 降落准备完毕
      "batteryOP":  0,            // 电池操作, 见BatteryOP 定义
  	"batteries": [
  	 	{
  			"slot": 1,// 槽位
  			"empty": false,// 是否空
  			"voltage": 24.5，// 电压
  			"current": 1.3 ,// 电流
  			"capacity": 90,// 电池容量
  		}
  	],
      "placeBatteryFinished": 1,// 放置无人机电池完毕
      "removeBatteryFinished": 0,// 移除无人机电池完毕
  }
  ```

- BatteryOP

  | 值   | 含义         |
  | ---- | ------------ |
  | 0    | 操作完成     |
  | 1    | 无人机换电池 |
  | 2    | 无人机拔电   |
  | 3    | 无人机上电   |

- AirportVersion

  | 0    | T2   |
  | ---- | ---- |
  | 1    | Lite |

### 5.12.3机场运动信息

- Topic


```
node/{nodeId}/ap/{platdormId}/moving
```

- Body


```
{
    "takeOffControl": true,// 起飞控制
    "landingControl": false,// 降落控制
    "doorState": 0,// 门状态, 见DevState
    "platformState": 3,// 平台状态
    "clapState": 1,// 夹子状态
    "doorMove": 0,// 门移动状态, 见MovingState
    "platformMove": 1,// 平台移动状态
    "clapMove": 0// 夹子移动状态
}
```

- DevState

  | 值   | 含义 |
  | ---- | ---- |
  | 0    | 关闭 |
  | 1    | 打开 |
  | 2    | 上   |
  | 3    | 下   |

### 5.12.4机场气象信息

- Topic


```
node/{nodeId}/ap/{platdormId}/weather
```

- Body


```
{
    "temperature": 25.0,    // 温度
    "humidity": 60,         // 湿度
    "pressure": 10001,      // 大气压
    "rain":  0.001,         // 雨量
    "windSpeedMin": 1.0,    // 最小风速
    "windSpeedMax": 3.0,    // 最大风速
    "windSpeedAvg": 2.0     // 平均风速
}
```



### 5.12.5无人机信息

- Topic


```
node/{nodeId}/drone/{droneId}
```

- Body


```
{
    "droneId": "无人机Id",
    "executionsId": "无人机任务id",
    "exeType": 0,                  // 执行类型， 见ExeType定义
    "recordTime": "记录时间戳",
    "connected": true,             // 无人机是否已连接
    "systemId": 1,                 // 无人机系统id, mavlink 通讯唯一标识
    "armed": true,                 // 无人机是否已解锁
    "uploadSuccess": true,         // 上传任务成功
    "flightMode": 1,               // 无人机飞行模式, 见FlightMode
    "flightModeDesc": "飞行模式描述",
    "home": {                     // 起飞点坐标
	"latitude": 12.345678,
	"longitude": 12.345678,
	"altitudeMSL": 30,
    },
    "latitudeDeg": 12.345678,      // 无人机实时位置： 纬度
    "longitudeDeg": 12.345678,     // 无人机实时位置： 经度
    "altitude": 30,                // 无人机实时位置： 海拔
    "altitudeRelative": 20,        // 无人机相对起飞点高度
    "voltage":  10.1,              // 电压
    "current":  -20.1,             // 电流
    "batteryLife": 0.8,            // 剩余电量
    "gPSCount": 30,                // RTK GPS 星数
    "groundSpeed": 5.0 ,           // 地速
    "landedState": 1,              // 降落状态， 见LandedState
    "landingType": 1,              // 降落类型，见LandingType
    "msg": "无人机文本状态, 无固定格式",
    "pitch":  0.01,                // 无人机姿态, 俯仰角
    "yaw": 0.01,                   // 无人机姿态，航向角
    "roll": 0.01,                  // 无人机姿态, 翻滚角
    "duration": 300,               // 飞行时间
    "distance": 30,                // 距home点距离, 米
    "timeRemain": 1800,            // 预估可续航时间
    "reached": 6,                  // 航点任务中已达到第几个航点
    "payload": {                   // 挂载
	"ledEnable": true,             // 警闪灯
	"ledOn": true
    }
}
```

- LandedState

  | 值   | 含义     |
  | ---- | -------- |
  | 1    | OnGround |
  | 2    | InAir    |
  | 3    | TakeOff  |
  | 4    | Landing  |

- FlightMode

  | 1    | FlightModeReady      | 准备模式     |
  | ---- | -------------------- | ------------ |
  | 2    | FlightModeTakeOff    | 起飞模式     |
  | 3    | FlightModeLoiter     | 悬停模式     |
  | 4    | FlightModeHold       | 保持模式     |
  | 5    | FlightModeMission    | 任务模式     |
  | 6    | FlightModeReturn     | 返航模式     |
  | 7    | FlightModeLand       | 降落模式     |
  | 8    | FlightModePRECLAND   | 精准降落模式 |
  | 9    | FlightModeOffBoard   | 板外模式     |
  | 10   | FlightModeFollow     | 跟随模式     |
  | 11   | FlightModeManual     | 手动模式     |
  | 12   | FlightModeALTCTL     | 定高模式     |
  | 13   | FlightModePOSCTL     | 定点模式     |
  | 14   | FlightModeACRO       | 特技模式     |
  | 15   | FlightModeSTABILIZED | 自稳模式     |
  | 16   | FlightModeRATTITUDE  | 半自稳模式   |

- ExeType

  | 0    | 手动飞行 |
  | ---- | -------- |
  | 1    | 定时任务 |
  | 2    | 快速起飞 |
  | 3    | 报警响应 |

- LandingType

  | 1    | NormalLanding |
  | ---- | ------------- |
  | 2    | SafeLanding   |

### 5.12.6无人机吊舱信息

- Topic


```
node/{nodeId}/drone/{drone}/{gimbalId}
```

- Body


```
{
    "yaw": 12.0,       // 航向角
	"pitch": 12.0,     // 俯仰角
	"fov": 12.0,       // 可见光 fov
	"irfov": 12.0      // 红外 fov
	"fl": 100.00,      // 可见光焦距
	"irfl": 100.00     // 红外焦距
}
```



### 5.12.7目标位移信息

- Topic


```
group/{gimbalId}/moving/
```

- Body


```
{
	"id": "目标唯一id，没有为空",
	"name": "目标名称",
	"type": 1,          // 见 ObjectType 定义
	"latitude": 22.0,   // 经度
	"longitude": 114.0, // 纬度
	"altitude": 80.0    // 海拔，没有为NAN
}
```

- ObjectType
  

| 值   | 含义 |
| ---- | ---- |
| 0    | 车   |
| 1    | 船   |

## 5.13.视频实时接入

视频实时接入功能提供了将高度无人机远程调度平台中客户自有设备的无人机信息接入到自有平台，实现视频流间的无缝集成。

### 多链路视频

无人机支持自组网链路和5G链路两种模式，在自组网或5G链路信号出现问题时可切换到另一种模式查看视频和控制无人机。（截止20230422需手动切换）

视频均采用WebRTC 方式，因自组网和5G链路的上传带宽不同，所以自组网上采用标准P2P模式，5G链路下采用推流/拉流模式，降低5G的上行带宽要求。

因此视频两个链路对应了两个独立的连接方式（截止20230422）

#### 20240905视频调整：

1. ionClient 拉流调整：

   ```
   原始：wsUrl    => 新： wsUrl+'?access_token='+当前登录用户的token   新增授权进行连接,否则ws未授权，无法连接视频
   ```

2. 视频推送方式整体划分为：P2P直推（webRTC），服务器分发（ionClient）

3. 无人机设备新增视频聚合的开关（如果开启聚合开关，默认链接聚合视频且链接方式为ionClient,无5g）

   ```
   clientLocal.join(cameraId);//聚合推流
   ```

4. 聚合开关关闭,判断机场推流方式，如果是P2P默认连接自组网视频(webRTC)

   如果为服务端分发则默认连接ionClient,当前自组网视频按照ionClient方式去连接

   ```
   clientLocal.join(cameraId+'_dock');//自组网通过服务器拉流
   ```

### DEMO

视频demo已将两种连接方式整合在一起，参见[video_demo](video_demo)

### webrtc协议

webrtc 协议采用websocket进行信令交互，消息内容采用json 编码。

视频源支持主辅码流，并支持动态切换。

建议小窗口非全屏下使用附码流，降低带宽，提高视频的流畅度, 在点击视频全屏时发送Stream消息切换到主码流。

#### 信令交互流程

```
skinparam backgroundColor #EEEBDC
    skinparam handwritten true
    客户端 -> 信令服务器: 连接
    信令服务器 -> 客户端: Rsp
    RTC服务-> 信令服务器: 连接
    信令服务器 -> RTC服务: Rsp
    RTC服务 -> 摄像头: 连接
    RTC服务 --> 客户端: Rsp
    客户端 --> RTC服务: SDP
    RTC服务 --> 客户端: Answer
    RTC服务 --> 客户端: SDP
    RTC服务 --> 客户端: IceCandidate
    客户端 --> RTC服务: IceCandidate
    RTC服务 --> 客户端: IceCandidate
    客户端 --> RTC服务: IceCandidate
	客户端 --> RTC服务: Stream
    客户端 --> RTC服务: Disconnect
```

#### 路径

- url: wss://drone.godouav.com/rtc
- Query:
  - verify=user
  - password: 用户token

#### 消息定义

```
{
    "from": "消息来源, 可不填充",
    "to": "消息目的地, 节点id",
    "cmd": "命令字",
    // 递增唯一序列号, 建议使用标准unix 时间戳，毫秒级
    "seq": 1,
    // 具体消息题
    "data": {}
}
```

#### 应答消息

- Cmd: "rsp"

- Body: 

  ```
  {
      // 错误码，0 无错误
      "code": 0,
      "msg": "错误信息"
  }
  ```

#### 心跳消息

> websocket 心跳保持消息，建议60秒一次

- Cmd: "hb"

- Body:

  ```
  {}
  ```

#### SDP消息

- Cmd: "sdp"

- Body: 

  ```
  {
      // 唯一标识, 可用uuid， 重复sesion将被拒绝
      "session": "会话标识",
      "camera": "camera id",
  	"streamType" "main/sub, 主辅玛流",
      "sdp": "base64 编码后的sdp消息"
  }
  ```

#### Answer消息

- Cmd: "answer"

- Body: 

  ```
  {
      // 错误码: 0 无错误
      "code": 0,
      "session": "会话id"
  }
  ```

#### ICECandidate 消息

- Cmd: "icecandidate"

- Body: 

  ```
  {
      "session": "会话id",
      "camera": "camera id",
      "candidate": "base64 编码后的ice candidate消息"
  }
  ```

#### 切换码流消息

- Cmd: "stream"

- Body: 

  ```
  {
  	"cameraId": "摄像头id",
  	"session": "回话id",
  	"streamType": "main/sub, 主玛流/辅玛流"
  }
  ```

### IonClient连接(服务器拉流)

```
// 原始5g连接
        // const signalLocal = new Signal.IonSFUJSONRPCSignal(
        //     Config.server_5g
        // );
        // 20240905改版后,新增授权
        const signalLocal = new Signal.IonSFUJSONRPCSignal(
            Config.server_5g+'?access_token='+Config.token
        );
        const clientLocal = new IonSDK.Client(signalLocal, {
            codec: Config.codec,
            iceServers: Config.iceServers
        });
        this.clientLocal = clientLocal
        let cameraId = this.state.cameraId
        //聚合拉流则直接为cameraId 服务器分发拉流则为cameraId+'_dock',表示地面端拉流
        signalLocal.onopen = () => clientLocal.join(cameraId);
        clientLocal.ontrack = (track, stream) => {
            console.log("got track", track.id, "for stream", stream.id);
            if (track.kind === "video") {
                let remoteVideo = document.getElementById('rtc');
                if (!remoteVideo) {
                    remoteVideo = document.createElement("video");
                }        
                remoteVideo.srcObject = stream;
                remoteVideo.autoplay = true;
                remoteVideo.muted = true;
                // track.onremovetrack = () => remotesDiv.removeChild(remoteVideo);
            }
        };
```

### 录像文件路径

1. 调用QueryVideoRecord 接口 获取全部相关录像文件列表 

   - 旧版视频自组网和5g视频记录为一条 
   - 新版视频录像改为：一个视频文件一条记录

2. 增加参数说明

   - videoType: 视频类型（0:吊舱(普通); 1 ai视频；2;机舱外-起飞视频，3：机舱外-降落视频 4:机舱内-起飞视频；5.机场内-降落视频）
   - storeType: 文件存储类型（0老版视频存储类型、1自组网本地路径、2自组网云端地址、3云端绝对路径、4云端相对路径）
   - 其中1、2、3、4无需区分自组网和5g

3. 相关接口

      自定义方法（如getProxyRealUrl（fileName,token））发送 get请求：  

      url: https://drone.godouav.com/api/backend/videorecord/generate/visitUrl?fileName=\${fileName}&access_token=${token}  

      返回参数：真实的文件地址 
      fileName: 文件的完整相对路径 


4. 具体使用

     视频文件路径为playPath参数  

  * storeType==0:（兼容历史录像文件）  
    a.自组网视频：
    判断filePath是否为ali公网地址，如果是的话直接取用filePath作为视频路径；不包含则取出nodeId(109)和fileName(static/AAA.mp4)进行路径拼接(如：https://drone.godouav.com/record/192.168.109.151/static/AAA.mp4）
    b.5g视频：判断playPath是否为http开头，如果是的话直接使用


  * storeType==1  
    直接取出playPath，拼接域名例如：https://drone.godouav.com+playPath

  * storeType==2  
    取出playPath，作为参数fileName通过方法getProxyRealUrl获取
    公网：云端真实路径（代理后的地址）作为视频文件路径
    私有化部署：获取代理地址之后，进行下边的地址拼接方法

  * storeType==3  
    公网：取出playPath后边文件的相对路径，作为参数fileName通过方法getProxyRealUrl获取，云端真实路径（代理后的地址）
  私有化部署：可直接进行下边的地址拼接方法

  * storeType==4  
    取出playPath，作为参数fileName通过方法getProxyRealUrl获取	
  公网：云端真实路径（代理后的地址）作为视频文件路径
  私有化部署：获取代理地址之后，进行下边的地址拼接方法

**私有化部署拼接说明：**

  私有化文件存储采用minio,视频地址处理参考：

  ```
let testUrl='http://192.168.142.101:9091/gdcxvideo/record/1625428017968975872868399283/1625428017968975872868399283_1730364449.mp4?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=admin%2F20241101%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20241101T031346Z&X-Amz-Expires=86400&X-Amz-SignedHeaders=host&X-Amz-Signature=3491d550515b0004ae215ca1e3b70c3d444d45dfa50129867ad9840646008e79'
  let testUrl1 = 'http://192.168.142.101:9091/gdcxvideo/screenshot/1544592785276014001/20241031/GDCXM190012302100314-20241031-82/20241031165604f78baa18bc2548799033786368e8b261.jpg'
  let ip = 'http://113.108.32.190:9091'//域名
  //判断返回的路径是否属于ali
  function getVideoRealUrl(proxyUrl) {
      if (proxyUrl.indexOf('aliyuncs.com')>-1) {//公网
          return proxyUrl
      } else {//私有化
          if (!proxyUrl) {
              return ''
          }
          let arrUrl=proxyUrl.split("//")
          var start=arrUrl[1].indexOf('/')
          let relUrl=arrUrl[1].substring(start+1)
          if (relUrl.indexOf("?")>-1) {
              relUrl=relUrl.split('?')[0]
          }
          console.log('11', relUrl)
          let url=ip+"/"+relUrl
          return url
      }
  }
  let acuUrl= getVideoRealUrl(testUrl)
  console.log('最后', acuUrl)
  ```
  以上方法也可用于私有化部署，接口返回的图片地址的拼接
  
## 5.14.AI识别

### 5.14.1请求涉及内容

- **API接⼝调⽤**
- **mqtt订阅**
- **AI识别结果绘制**

### 5.14.2API接口调用

- AI数据字典查询
- 组织拥有AI模型能力查询
- 当前正在调用的AI能力
- 开启AI识别
- 关闭AI识别

#### AI数据字典查询

| **URL**                | {{base_url}}/backend/dictionary/queryDicDataByDicType/AIIdentifyType |
| ---------------------- | ------------------------------------------------------------ |
| **Method**             | post                                                         |
| **Headers**            | access_token                                                 |
| **Params**             | 无                                                           |
| **Response**           | 参考返回示例                                                 |
| **Response Parameter** | **code：** AI能力编码code<br />**dicId：** 字典编码<br />**content：** 能力名称（中）<br />**flag：** 能力名称（英） |

返回示例：

```json
{
            "code": 0,
            "msg": "操作成功",
            "data": [
                {
                    "code": "AI-00",
                    "flag": "somke",
                    "remark": null,
                    "dicId": "AI-00",
                    "content": "烟雾",
                    "dicType": "AIIdentifyType"
                },
                {
                    "code": "AI-01",
                    "flag": "pedestrian",
                    "remark": null,
                    "dicId": "AI-01",
                    "content": "行人",
                    "dicType": "AIIdentifyType"
                },
                {
                    "code": "AI-02",
                    "flag": "people",
                    "remark": null,
                    "dicId": "AI-02",
                    "content": "人",
                    "dicType": "AIIdentifyType"
                },
                {
                    "code": "AI-03",
                    "flag": "bicycle",
                    "remark": null,
                    "dicId": "AI-03",
                    "content": "自行车",
                    "dicType": "AIIdentifyType"
                },
                {
                    "code": "AI-04",
                    "flag": "car",
                    "remark": null,
                    "dicId": "AI-04",
                    "content": "汽车",
                    "dicType": "AIIdentifyType"
                },
                {
                    "code": "AI-05",
                    "flag": "van",
                    "remark": null,
                    "dicId": "AI-05",
                    "content": "面包车",
                    "dicType": "AIIdentifyType"
                },
                {
                    "code": "AI-06",
                    "flag": "truck",
                    "remark": null,
                    "dicId": "AI-06",
                    "content": "卡车",
                    "dicType": "AIIdentifyType"
                },
                {
                    "code": "AI-07",
                    "flag": "tricycle",
                    "remark": null,
                    "dicId": "AI-07",
                    "content": "三轮车",
                    "dicType": "AIIdentifyType"
                },
                {
                    "code": "AI-08",
                    "flag": "awning-tricycle",
                    "remark": null,
                    "dicId": "AI-08",
                    "content": "遮阳三轮车",
                    "dicType": "AIIdentifyType"
                },
                {
                    "code": "AI-09",
                    "flag": "bus",
                    "remark": null,
                    "dicId": "AI-09",
                    "content": "公交车",
                    "dicType": "AIIdentifyType"
                },
                {
                    "code": "AI-10",
                    "flag": "motor ",
                    "remark": null,
                    "dicId": "AI-10",
                    "content": "摩托车",
                    "dicType": "AIIdentifyType"
                },
                {
                    "code": "AI-11",
                    "flag": "Floating debris",
                    "remark": null,
                    "dicId": "AI-11",
                    "content": "漂浮物",
                    "dicType": "AIIdentifyType"
                },
                {
                    "code": "AI-12",
                    "flag": "illegal structure",
                    "remark": null,
                    "dicId": "AI-12",
                    "content": "蓝色彩钢瓦",
                    "dicType": "AIIdentifyType"
                },
                {
                    "code": "AI-13",
                    "flag": "yc",
                    "remark": null,
                    "dicId": "AI-13",
                    "content": "渔船",
                    "dicType": "AIIdentifyType"
                },
                {
                    "code": "AI-14",
                    "flag": "xlc",
                    "remark": null,
                    "dicId": "AI-14",
                    "content": "巡逻船",
                    "dicType": "AIIdentifyType"
                },
                {
                    "code": "AI-15",
                    "flag": "ljc",
                    "remark": null,
                    "dicId": "AI-15",
                    "content": "垃圾船",
                    "dicType": "AIIdentifyType"
                },
                {
                    "code": "AI-16",
                    "flag": "guard",
                    "remark": null,
                    "dicId": "AI-16",
                    "content": "防护网",
                    "dicType": "AIIdentifyType"
                },
                {
                    "code": "AI-17",
                    "flag": "bottle",
                    "remark": null,
                    "dicId": "AI-17",
                    "content": "瓶子",
                    "dicType": "AIIdentifyType"
                },
                {
                    "code": "AI-18",
                    "flag": "plastic",
                    "remark": null,
                    "dicId": "AI-18",
                    "content": "塑料垃圾",
                    "dicType": "AIIdentifyType"
                },
                {
                    "code": "AI-19",
                    "flag": "garbage",
                    "remark": null,
                    "dicId": "AI-19",
                    "content": "其他垃圾",
                    "dicType": "AIIdentifyType"
                },
                {
                    "code": "AI-20",
                    "flag": "rubbish",
                    "remark": null,
                    "dicId": "AI-20",
                    "content": "垃圾堆放",
                    "dicType": "AIIdentifyType"
                },
                {
                    "code": "AI-21",
                    "flag": "move vendors",
                    "remark": null,
                    "dicId": "AI-21",
                    "content": "流动摊贩",
                    "dicType": "AIIdentifyType"
                },
                {
                    "code": "AI-22",
                    "flag": "Dam abnormal alarm",
                    "remark": "",
                    "dicId": "AI-22",
                    "content": "大坝异常",
                    "dicType": "AIIdentifyType"
                }
            ]
        }
```

#### **组织拥有AI模型能力查询**

| **URL**                | {{base_url}}/ai/customer/queryAiByCustId/{{custId}}          |
| ---------------------- | ------------------------------------------------------------ |
| **Method**             | post                                                         |
| **Headers**            | access_token                                                 |
| **Params**             | 无                                                           |
| **Response**           | 参考返回示例                                                 |
| **Response Parameter** | **aiInvokeMaxCount：** AI可调用模型数量  <br/>**aiDetail：** 具体模型能力 <br/>**aiTypeId：** 能力Id <br/>**aiTypeName：** 识别能力名称（中） <br/>**aiTypeNameEn：** 识别能力名称（英文） <br/>**modelId：** 模型Id <br/>**modelName：** 模型名称 <br/>**custId：** 组织id <br/>**aiSwitch：** 能力开关 <br/>**aiServers：** AI服务器 <br/>**aiEndDate：** 到期时间 <br/>**aiEffDate：** 生效时间 |

返回示例：

```json
{
            "code": 0,
            "msg": "operate success.",
            "data": {
                "aiInvokeMaxCount": 3,
                "aiDetail": [
                    {
                        "aiTypeName": "烟雾",
                        "modelName": "烟雾模型",
                        "createBy": "1725684357466820608438748095",
                        "creator": "lrz",
                        "modelId": "1811314484164317184331193567",
                        "aiTypeId": "AI-00",
                        "aiTypeNameEn": "somke"
                    },
                    {
                        "aiTypeName": "人",
                        "modelName": "人车模型",
                        "createBy": "1725684357466820608438748095",
                        "creator": "lrz",
                        "modelId": "1811591883006808064129620382",
                        "aiTypeId": "AI-02",
                        "aiTypeNameEn": "people"
                    },
                    {
                        "aiTypeName": "汽车",
                        "modelName": "人车模型",
                        "createBy": "1725684357466820608438748095",
                        "creator": "lrz",
                        "modelId": "1811591883006808064129620382",
                        "aiTypeId": "AI-04",
                        "aiTypeNameEn": "car"
                    },
                    {
                        "aiTypeName": "蓝色彩钢瓦",
                        "modelName": "非法搭建模型",
                        "createBy": "1725684357466820608438748095",
                        "creator": "lrz",
                        "modelId": "1812014756104249344317781687",
                        "aiTypeId": "AI-12",
                        "aiTypeNameEn": "illegal structure"
                    },
                    {
                        "aiTypeName": "垃圾堆放",
                        "modelName": "垃圾堆放模型",
                        "createBy": "1725684357466820608438748095",
                        "creator": "lrz",
                        "modelId": "1814495434871373824148428250",
                        "aiTypeId": "AI-20",
                        "aiTypeNameEn": "rubbish"
                    },
                    {
                        "aiTypeName": "流动摊贩",
                        "modelName": "流动摊贩模型",
                        "createBy": "1725684357466820608438748095",
                        "creator": "lrz",
                        "modelId": "1814496782174093312366919308",
                        "aiTypeId": "AI-21",
                        "aiTypeNameEn": "move vendors"
                    }
                ],
                "custId": "999001",
                "aiEffDate": "2024-06-01 00:00:00",
                "aiSwitch": 1,
                "aiServers": "aiserver1",
                "aiEndDate": "2024-12-31 00:00:00"
            }
        }
```

#### 当前正在调用AI能力

| **URL**                | {{base_url}}/ai/schedule/object/identify/info/{{executionsId}} |
| ---------------------- | ------------------------------------------------------------ |
| **Method**             | get                                                          |
| **Headers**            | access_token                                                 |
| **Params**             | 无                                                           |
| **Response**           | 参考返回示例                                                 |
| **Response Parameter** | **aiTypeId：** 能力Id <br/>**aiTypeName：** 识别能力名称<br/>**modelId：** 模型Id<br/>**modelName：** 模型名称<br/>**status：** 调用状态（0调用中） |

返回示例：

```json
{
            "code": 0,
            "msg": "operate success.",
            "data":[
        	    {
                    "aiTypeId": "AI-00",
                    "aiTypeName": 0,
                    "modelId": '1811591883006808064129620382',
                    "modelName": '人车模型',
                    "reliability": "0.6",
                    "status": 0,
                }
            ]
        }
```

#### 开启AI识别

| **URL**                | {{base_url}}/ai/schedule/object/identify/start               |
| ---------------------- | ------------------------------------------------------------ |
| **Method**             | post                                                         |
| **Headers**            | access_token                                                 |
| **Params**             | **executionsId：** 执行id<br/>**infers：** 具体调用<br/>**aiTypeId：** 能力Id<br/>**aiTypeName：** 识别能力名称<br/>**modelId：** 模型Id<br/>**reliability：** 置信度（**默认0.6**） |
| **Response**           | 参考返回示例                                                 |
| **Response Parameter** | **execute-ai-server-id：** 执行的AI服务器                    |

请求示例：

```json
{
        	"executionsId": "GDM002S2312178-20240930-60886504",
        		"infers": [
        			{
        			"aiTypeId": "AI-04",
        			"aiTypeName": "汽车",
        			"reliability": 0.6,
        			"modelId": "1811591883006808064129620382"
        			}
        		]
        }
```

返回示例：

```json
{
            "code": 0,
            "msg": "ai schedule request success,command code has sent to ai server. ",
            "data": {
                "execute-ai-server-id": "aiserver1"
            }
        }
```

#### 关闭AI识别

| **URL**                | {{base_url}}/ai/schedule/object/identify/sub                 |
| ---------------------- | ------------------------------------------------------------ |
| **Method**             | post                                                         |
| **Headers**            | access_token                                                 |
| **Params**             | **executionsId：** 执行id<br/>**infers：** 具体调用<br/>**aiTypeId：** 能力Id<br/>**aiTypeName：** 识别能力名称<br/>**modelId：** 模型Id<br/>**reliability：** 置信度（**默认0.6**） |
| **Response**           | 参考返回示例                                                 |
| **Response Parameter** | **execute-ai-server-id：** 执行的AI服务器                    |

请求示例：

```json
{
        	"executionsId": "GDM002S2312178-20240930-60886504",
        		"infers": [
        			{
        			"aiTypeId": "AI-04",
        			"aiTypeName": "汽车",
        			"reliability": 0.6,
        			"modelId": "1811591883006808064129620382"
        			}
        		]
        }
```

返回示例：

```json
{
            "code": 0,
            "msg": "ai schedule request success,command code has sent to ai server. ",
            "data": {
                "execute-ai-server-id": "aiserver1"
            }
        }
```

#### 置信度修改

| **URL**                | {{base_url}}/ai/schedule/object/identify/change/reliability                 |
| ---------------------- | ------------------------------------------------------------ |
| **Method**             | post                                                         |
| **Headers**            | access_token                                                 |
| **Params**             | **executionsId：** 执行id<br/>**infers：** 具体调用<br/>**aiTypeId：** 能力Id<br/>**aiTypeName：** 识别能力名称<br/>**modelId：** 模型Id<br/>**reliability：** 置信度（**默认0.6**） |
| **Response**           | 参考返回示例                                                 |
| **Response Parameter** | **execute-ai-server-id：** 执行的AI服务器                    |

请求示例：

```json
{
        	"executionsId": "GDM002S2312178-20240930-60886504",
        		"infers": [
        			{
        			"aiTypeId": "AI-04",
        			"aiTypeName": "汽车",
        			"reliability": 0.7,
        			"modelId": "1811591883006808064129620382"
        			}
        		]
        }
```

返回示例：

```json
{
            "code": 0,
            "msg": "ai schedule request success,command code has sent to ai server. ",
            "data": {
                "execute-ai-server-id": "aiserver1"
            }
        }
```

### 5.14.3MQTT订阅（AI）

#### **颜色参考**

**['#FF0000', '#00FF00', '#FF00FF', '#FFFF00', '#FF6700', '#912CEE', '#F45A8E', '#00BFFF', '#00FFFF', '#1E90FF']**

#### **识别事件触发推送**

| **topic**              | **gis/{{droneId}}/AIPicWarnTip**                             |
| ---------------------- | ------------------------------------------------------------ |
| **Response**           | 参考返回示例                                                 |
| **Response Parameter** | **videoCutPicId：** 保存的图片id<br/>**custId：** 组织id<br/>**missionId：** 任务id<br/>**executionsId：** 执行id<br/>**longitudeDeg：** 经度<br/>**latitudeDeg：** 纬度<br/>**altitude：** 高度<br/>**picType：** 图片类别（0普通 1异常 2警告 3事件）<br/>**aiFlag：** 图片类型（0普通图片 1AI图片）<br/>**fileName：** 图片名称<br/>**fileUrl：** 图片地址<br/>**modelId：** 模型id<br/>**identifyType：** 识别能力编码<br/>**identifyTypeName：** 识别能力名称<br/>**IdentifyQty：** 识别结果数量（多少个识别框）<br/>**reliability：** 置信度<br/>**auditStatus：** 审核状态<br/>**beginTime：** 发生时间 |

返回示例：

```json
{
    "videoCutPicId": "1840642066134167552823980406",
    "custId": "999001",
    "missionId": "",
    "executionsId": "GDM002S2312178-20240930-60886504",
    "latitudeDeg": 22.759178995556777,
    "longitudeDeg": 114.24295786452764,
    "picType": "2",
    "aiFlag": 1,
    "bucketName": "gdcx-dev",
    "fileName": "2024093014372007b1c36bccb04b9992d4be4deaa28f11.jpg",
    "filePath": "AI/999001/pic/20240930/GDM002S2312178-20240930-60886504",
    "fileUrl": "https://gdcx-dev.oss-cn-shenzhen.aliyuncs.com/AI/999001/pic/20240930/GDM002S2312178-20240930-60886504/2024093014372007b1c36bccb04b9992d4be4deaa28f11.jpg",
    "remark": "AI",
    "createBy": "10000100000999900000000001",
    "modelId": "1811591883006808064129620382",
    "identifyType": "AI-04",
    "identifyTypeName": "car",
    "IdentifyQty": "21",
    "reliability": 0.849418044090271,
    "altitude": "100.0",
    "auditStatus": 0,
    "beginTime": "2024-09-30 14:37:20"
}
```

#### **识别结果推送**（识别框）

| **topic**              | aiserver/{{droneId}}/infer                                   |
| ---------------------- | ------------------------------------------------------------ |
| **Response**           | 参考返回示例                                                 |
| **Response Parameter** | **1811591883006808064129620382** 表示AI模型id<br/>**cresult：** 具体识别结果<br/>**rect：** 识别框数据<br/> **x：** 左上角顶点横坐标<br/>**y：** 左上角顶点纵坐标<br/>**w：** 识别框宽度<br/>**x：** 识别框高度<br/>**strcode：** AI识别能力<br/>**cidx：** 对应矩形框颜色下标 |
| **description**        | 1. 目前通用无人机视频分辨率1920*1080<br/>2. 绘制原点为当前视频画面的左上角<br/>3. 绘制AI识别框，需要将当前元素的宽高和无人机视频真实宽高做等比换算，再进行绘制 |

返回示例：

```json
{"1811591883006808064129620382":[
        {"cresult":{"rect":{"x":970,"y":915,"w":25,"h":48},"conf":0.8596795},"strcode":"AI-04","cidx":0},
        {"cresult":{"rect":{"x":767,"y":968,"w":51,"h":27},"conf":0.83327514},"strcode":"AI-04","cidx":0},
        {"cresult":{"rect":{"x":759,"y":857,"w":49,"h":25},"conf":0.8217843},"strcode":"AI-04","cidx":0},
        {"cresult":{"rect":{"x":761,"y":881,"w":48,"h":25},"conf":0.81388754},"strcode":"AI-04","cidx":0},
        {"cresult":{"rect":{"x":740,"y":665,"w":43,"h":22},"conf":0.8130608},"strcode":"AI-04","cidx":0},
        {"cresult":{"rect":{"x":737,"y":687,"w":45,"h":22},"conf":0.80385333},"strcode":"AI-04","cidx":0},
        {"cresult":{"rect":{"x":778,"y":1007,"w":47,"h":20},"conf":0.7984146},"strcode":"AI-04","cidx":0},
        {"cresult":{"rect":{"x":728,"y":594,"w":44,"h":23},"conf":0.7954998},"strcode":"AI-04","cidx":0},
        {"cresult":{"rect":{"x":812,"y":339,"w":19,"h":33},"conf":0.79113454},"strcode":"AI-04","cidx":0},
        {"cresult":{"rect":{"x":762,"y":920,"w":49,"h":24},"conf":0.78745794},"strcode":"AI-04","cidx":0},
        {"cresult":{"rect":{"x":743,"y":738,"w":44,"h":23},"conf":0.77644974},"strcode":"AI-04","cidx":0},
        {"cresult":{"rect":{"x":731,"y":634,"w":45,"h":26},"conf":0.7555676},"strcode":"AI-04","cidx":0},
        {"cresult":{"rect":{"x":956,"y":848,"w":22,"h":41},"conf":0.72812295},"strcode":"AI-04","cidx":0},
        {"cresult":{"rect":{"x":722,"y":565,"w":46,"h":26},"conf":0.7061017},"strcode":"AI-04","cidx":0},
        {"cresult":{"rect":{"x":748,"y":780,"w":46,"h":25},"conf":0.69504964},"strcode":"AI-04","cidx":0},
        {"cresult":{"rect":{"x":716,"y":473,"w":37,"h":20},"conf":0.68678445},"strcode":"AI-04","cidx":0},
        {"cresult":{"rect":{"x":766,"y":943,"w":49,"h":26},"conf":0.6539735},"strcode":"AI-04","cidx":0},
        {"cresult":{"rect":{"x":732,"y":615,"w":42,"h":22},"conf":0.6513415},"strcode":"AI-04","cidx":0},
        {"cresult":{"rect":{"x":708,"y":445,"w":37,"h":22},"conf":0.64585465},"strcode":"AI-04","cidx":0},
        {"cresult":{"rect":{"x":708,"y":416,"w":36,"h":18},"conf":0.64570165},"strcode":"AI-04","cidx":0},
        {"cresult":{"rect":{"x":744,"y":758,"w":45,"h":24},"conf":0.64337564},"strcode":"AI-04","cidx":0},
        {"cresult":{"rect":{"x":753,"y":816,"w":45,"h":21},"conf":0.6375995},"strcode":"AI-04","cidx":0},
        {"cresult":{"rect":{"x":799,"y":414,"w":17,"h":31},"conf":0.6231104},"strcode":"AI-04","cidx":0}
        ]}
```

绘制示例：（**目前是以无人机视频1920*1080比例做绘制，有其他分辨率则需要根据视频实际来做适配**）

```
//上面为mqtt返回AI识别结果的订阅数据message，在订阅数据回调中做具体绘制调用

let ele = document.getElementById("videoCanvas");//要绘制识别框的画布元素
let ctx = ele.getContext("2d");
let videoWidth = ele.width;
let videoHeight = ele.height;
ctx.clearRect(0, 0, videoWidth, videoHeight);
clearTimeout(drawTimeout);//收到新的ai绘制数据，清理上一次的绘制
let results = message.results;
let resultKeys = Object.keys(results);
if (resultKeys.length > 0 && resultKeys instanceof Array) {
     resultKeys.forEach((modelId) => {
          let resultList = results[modelId];
          resultList.forEach((result) => {
          		getCoordnatePliex(result,ele,ctx,videoWidth,videoHeight);
          })
        })
}
//3s后自动清除上一次绘制，以防有历史框遗留
drawTimeout = setTimeout(() => {
    ctx.clearRect(0, 0, videoWidth, videoHeight);
}, 3000);





//AI对应识别颜色组
let colors = ['#FF0000', '#00FF00', '#FF00FF', '#FFFF00', '#FF6700', '#912CEE', '#F45A8E', '#00BFFF', '#00FFFF', '#1E90FF']
//获取当前AI坐标在屏幕画面中实际所占的顶点像素值及矩形框的长和宽（目前按照无人机实际视频分辨率为1920*1080做适配）
const getCoordnatePliex = (result, drawing, ctx, videoWidth, videoHeight) => {
	let cResult = result.cresult;
	if(drawing){
		let receiveRect = cResult.rect;
        let realLeftTopX = receiveRect.x;
        let realLeftTopY = receiveRect.y;

        let rectWidth = receiveRect.w;
        let rectHeight = receiveRect.h;

        let canvasLeftTopX = 0;
        let canvasLeftTopY = 0;
        canvasLeftTopX = (realLeftTopX * videoWidth) / 1920;
        canvasLeftTopY = (realLeftTopY * videoHeight) / 1080;

        rectWidth = (rectWidth * videoWidth) / 1920;
        rectHeight = (rectHeight * videoHeight) / 1080;
        
        // 矩形
        ctx.lineWidth = 2;//大视频窗口，建议为2 ，小视频窗口建议为1
        ctx.strokeStyle =
          result.cidx != undefined ? colors[result.cidx] : colors[0];
        ctx.strokeRect(canvasLeftTopX, canvasLeftTopY, rectWidth, rectHeight);
	}
}
```



# 6.MQTT 登陆

采用动态用户名 密码，需要匹配时间戳，防止泄漏。



- 用户名生成

  ```
  username = third__{appId}__{timstamp}
  
  其中：third 为固定，appId 为分配的id,timstamp为毫秒，third ,appId ,timstamp三者这间用“__”连接
       long timestamp = System.currentTimeMillis();
        
  例如：third__VUVxPG1gcjTCplDXwAgPmnUj__1728642326935
  ```

  

- 密码生成

  ```
   password = GetSign(username)
  ```

- 密码加密

  signSecret授予的签名信息

  ```
   public String GetSign(String username) {
          String signSecret = "xxxxxxxx";
          String usernameBase64 = Base64Util.enCodeBase64NoSalt(username);
          String Result = Hmac256Utils.encryptHmacSHA256(usernameBase64.getBytes(), signSecret.getBytes());
          return Result;
      }
  ```

  

- 涉及加密类

  ```
  import java.nio.charset.Charset;
  
  public class Base64Util {
      public static String enCodeBase64NoSalt(String str){
          String enc = java.util.Base64.getEncoder().encodeToString(str.getBytes());
          return  enc;
      }
      public static String enCodeBase64(String str){
          String salt="ABCDEFG123456ABC";
          str = str + salt;
          String enc = java.util.Base64.getEncoder().encodeToString(str.getBytes());
          return  enc;
      }
      public static String DeCodeBase64(String str){
          byte[] decode = java.util.Base64.getDecoder().decode(str);
          String aSrc = new String(decode);
          return  aSrc.replace("ABCDEFG123456ABC","");
  
      }
  }
  
  
  
  
  
  import javax.crypto.KeyGenerator;
  import javax.crypto.Mac;
  import javax.crypto.SecretKey;
  import javax.crypto.spec.SecretKeySpec;
  import java.nio.charset.Charset;
  
  public class Hmac256Utils {
  
      // 获取 HmacMD5 Key
      public static byte[] getHmacMd5Key() {
          return getHmacKey("HmacMD5");
      }
  
      // 获取 HmacSHA256
      public static byte[] getHmacSha256Key() {
          return getHmacKey("HmacSHA256");
      }
  
      // 获取 HmacSHA512
      public static byte[] getHmacSha512Key() {
          return getHmacKey("HmacSHA512");
      }
  
      // 获取 HMAC Key
      public static byte[] getHmacKey(String type) {
          try {
              // 1、创建密钥生成器
              KeyGenerator keyGenerator = KeyGenerator.getInstance(type);
              // 2、产生密钥
              SecretKey secretKey = keyGenerator.generateKey();
              // 3、获取密钥
              byte[] key = secretKey.getEncoded();
              return key;
          } catch (Exception e) {
              throw new RuntimeException(e);
          }
      }
  
      // HMAC MD5 加密
      public static String encryptHmacMD5(byte[] data, byte[] key) {
          return encryptHmac(data, key, "HmacMD5");
      }
  
      // HMAC SHA256 加密
      public static String encryptHmacSHA256(byte[] data, byte[] key) {
          return encryptHmac(data, key, "HmacSHA256");
      }
  
      // HMAC SHA521 加密
      public static String encryptHmacSHA512(byte[] data, byte[] key) {
          return encryptHmac(data, key, "HmacSHA512");
      }
  
      // 基础MAC 算法
      public static String encryptHmac(byte[] data, byte[] key, String type) {
          try {
              // 1、还原密钥
              SecretKey secretKey = new SecretKeySpec(key, type);
              // 2、创建MAC对象
              Mac mac = Mac.getInstance(type);
              // 3、设置密钥
              mac.init(secretKey);
              // 4、数据加密
              byte[] bytes = mac.doFinal(data);
              // 5、生成数据
              String rs = encodeHex(bytes);
              return rs;
          } catch (Exception e) {
              throw new RuntimeException(e);
          }
      }
  
      // 数据准16进制编码
      public static String encodeHex(final byte[] data) {
          return encodeHex(data, true);
      }
  
      // 数据转16进制编码
      public static String encodeHex(final byte[] data, final boolean toLowerCase) {
          final char[] DIGITS_LOWER = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };
          final char[] DIGITS_UPPER = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };
          final char[] toDigits = toLowerCase ? DIGITS_LOWER : DIGITS_UPPER;
          final int l = data.length;
          final char[] out = new char[l << 1];
          // two characters form the hex value.
          for (int i = 0, j = 0; i < l; i++) {
              out[j++] = toDigits[(0xF0 & data[i]) >>> 4];
              out[j++] = toDigits[0x0F & data[i]];
          }
          return new String(out);
      }
  }
  ```

  

