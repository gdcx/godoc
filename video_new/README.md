[toc]

最新参考[Readme.md](Readme.md)

# VIDEO_NEW (Vue 3 + Vite)

This template should help get you started developing with Vue 3 in Vite. The template uses Vue 3 `<script setup>` SFCs, check out the [script setup docs](https://v3.vuejs.org/api/sfc-script-setup.html#sfc-script-setup) to learn more.

Learn more about IDE Support for Vue in the [Vue Docs Scaling up Guide](https://vuejs.org/guide/scaling-up/tooling.html#ide-support).

## 多链路视频
无人机支持聚合/5g链路、自组网链路两种模式,在任一链路信号出现问题时，可切换到另一链路查看视频(需手动切换)
机场新增拉流方式，p2p和服务器推流，根据配置连接其中一种查看视频（pullStreamType 0:p2p,1服务器推流）
视频均采用WebRTC 方式

## webrtc 协议

webrtc 协议采用websocket进行信令交互，消息内容采用json 编码。

视频源支持主附码流，并支持动态切换。

建议小窗口非全屏下使用辅码流，降低带宽，提高视频的流畅度, 在点击视频全屏时发送Stream消息切换到主码流。

## Demo
   demo参考[video_new](video_new)

## 执行步骤

1. 进入video_new文件夹 

2. 执行npm i 下载所需依赖

3. 检查src/pligins/Config.js中 iceServers - urls ，需要联系对接人员获取地址并填入(公网常用： turn:stun.godouav.com)

   ![image-20250407182831576](C:\Users\29177\AppData\Roaming\Typora\typora-user-images\image-20250407182831576.png)

4. 执行npm run dev浏览器中默认打开链接

## 新版视频改造
1. 所有视频信令均通过同一路ws进行连接

2. 每一路单独Connection实例，进行webRtc信令交互

3. 区分无人机详情中，是否开启聚合；机场详情中，推流方式（0 p2p   , 1服务器推流）

4. 飞行结束，单独关闭对应的Connection    .stop()

5. 码流切换 changeStream()

   ## 参数说明

   | demo页面参数说明 | Type    | Description                                                  |
   | ---------------- | ------- | ------------------------------------------------------------ |
   | websocket url    | String  | ws请求地址（例如：ws://{{ip}}/rtc1/ws）                      |
   | token            | String  | 用户token（对接文档返回的access_token）                      |
   | userId           | String  | 用户id（该参数只做请求来源标识，不做校验；请求token时，如果参数中包括该字段，可直接使用，如果有custId也可以直接使用，都没有的话，可以使用请求组织的名称缩写 示例：深圳创新写做'szcx'） |
   | NodeId           | String  | 设备列表中返回的nodeId                                       |
   | cameraId         | String  | 摄像机id（机场内外摄像头id、无人机吊舱id）                   |
   | 推流方式         | Number  | 0：P2P     1：服务器推流 （获取机场及无人机信息 - pushStreamType ） |
   | 视频来源         | Number  | 0：无人机    1：机场                                         |
   | sfu              | Boolean | sfu支持                                                      |
   | 无人机聚合开关   | Number  | 0：关闭      1：开启  （获取机场及无人机信息 - videoAgg ）   |
   | 5g               | Boolean | 是否为5g （无人机自组网信号不好时，可做5g链路切换）          |
   | streamType       | Number  | 0：主码流    1：辅码流  （摄像头数据中openSub==1 表示支持辅码流，可以连接辅码流） |
   
   
   
   | WS参数说明 | Type   | Description                                                  |
   | ---------- | ------ | ------------------------------------------------------------ |
   | url        | String | ws请求地址                                                   |
   | token      | String | 用户token                                                    |
   | userId     | String | 用户id（该参数只做请求来源标识，不做校验；请求token时，如果参数中包括该字段，可直接使用，如果有custId也可以直接使用，都没有的话，可以使用请求组织的名称缩写 示例：深圳创新 -> 'szcx'） |
   
   
   
   | Connection参数说明 | Type          | Description                                                  |
   | ------------------ | ------------- | ------------------------------------------------------------ |
   | ws                 | String        | websocke连接实例                                             |
   | cameraId           | String        | 摄像机id（注意：无人机开启聚合videoAgg==1：cameraId；未开启聚合videoAgg==0，同时机场采用服务器推流pushStreamType ==1: cameraId+'_dock';未开启聚合，同时机场采用p2p拉流，直接为cameraId;5g视频直接为cameraId）                                                             (机场视频：机场采用服务器推流pushStreamType ==1: cameraId+'_dock';机场采用p2p拉流，直接为cameraId;) |
   | nodeId             | String/Number | nodeId                                                       |
   | sfu                | Boolean       | sfu支持（无人机开启聚合videoAgg==1：sfu=true；未开启聚合videoAgg==0，同时机场采用服务器推流pullStreamType==1:  sfu=true;未开启聚合，同时机场采用p2p拉流，sfu=false;5g视频: sfu=true）                                                                                                 (机场采用服务器推流pushStreamType ==1: sfu=true;机场采用p2p拉流，sfu=false;)                                                              videoAgg 查询无人机信息中返回；                                                                                                                                        pushStreamType ：查询机场信息返回 |
   | streamType         | Number        | 码流（0主码流 1辅码流 具体根据单个摄像头是否支持辅码流做判断，openSub==1支持辅码流） |
   | audio_send         | Boolean       | 音频发送支持（开启音频发送支持，调用 start() 会默认打开音频授权，仅支持localhost/https；调用stopGatherAudioStream() 关闭音频采集） |
   | audio_recv         | Boolean       | 音频接收支持                                                 |
   
   

#### 信令交互流程

```plantuml
@startuml
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

@enduml
```
#### 路径
- url: wss://drone.godouav.com/rtc1/ws
- Query:
	- access_token= access_token

#### 消息定义

```json
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
```json
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
```json
{
}
```


#### SDP 消息

- Cmd: "sdp"
- Body:
```json
{
    // 唯一标识, 可用uuid， 重复sesion将被拒绝
    "session": "会话标识",
    "camera": "camera id",
	"streamType" "main/sub, 主辅玛流",
    "sdp": "base64 编码后的sdp消息"
}
```

#### Answer 消息

- Cmd: "answer"
- Body:
```json
{
    // 错误码: 0 无错误
    "code": 0,
    "session": "会话id"
}
```

#### ICECandidate 消息

- Cmd: "icecandidate"
- Body:
```json
{
    "session": "会话id",
    "camera": "camera id",
    "candidate": "base64 编码后的ice candidate消息"
}
```

#### 切换码流消息

- Cmd: "stream"
- Body:
```json
{
	"cameraId": "摄像头id",
	"session": "回话id",
	"streamType": "0/1, 主玛流/辅玛流"
}
```
## 录像文件路径

1. 调用QueryVideoRecord 接口 获取全部相关录像文件列表  

* 旧版视频自组网和5g视频记录为一条  
* 新版视频录像改为：一个视频文件一条记录

2. 增加参数说明

* videoType: 视频类型（0:吊舱(普通); 1 ai视频；2;机舱外-起飞视频，3：机舱外-降落视频 4:机舱内-起飞视频；5.机场内-降落视频）
* storeType: 文件存储类型（0老版视频存储类型、1自组网本地路径、2自组网云端地址、3云端绝对路径、4云端相对路径）

其中1、2、3、4无需区分自组网和5g

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
getUrl.js路径拼接封装，参见[getUrl.js](video_demo/getUrl.js) 

以上方法也可用于私有化部署，接口返回的图片地址的拼接

## 私有化部署访问说明

1. 如果是通过服务器部署当前视频demo，在服务器中的Nginx配置对应websocket的代理，目前视频demo中可直接使用http+ws去做访问

   ```
   location /rtc {
           proxy_pass http://{{私有化ip}}/rtc;
           proxy_http_version 1.1;
           proxy_set_header Upgrade $http_upgrade;
           proxy_set_header Connection "upgrade";
           proxy_set_header Host $host;
           proxy_set_header X-Real-IP $remote_addr;
           proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
           proxy_set_header X-Forwarded-Proto $scheme;
       }
   location /sfu/ws {
      proxy_pass http://{{私有化ip}}/sfu/ws/;
      proxy_http_version 1.1;
      proxy_set_header Upgrade $http_upgrade;
      proxy_set_header Connection "upgrade";
      proxy_set_header Host $host;
      proxy_set_header X-Real-IP $remote_addr;
      proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
      proxy_set_header X-Forwarded-Proto $scheme;
   }
   location ^~ /uav_mqtt {
                   rewrite ^/uav_mqtt/(.*)$ /$1 break;
                   proxy_pass http://{{私有化ip}}/mqtt/mqtt/;
                   proxy_http_version 1.1;
                   proxy_set_header Upgrade $http_upgrade;
                   proxy_set_header Connection "upgrade";
                   proxy_set_header Host $host;
           }
   ```

   

2. demo中的配置文件,也需要更改配置 （**有端口的需要加上对应端口**）

   [Config.js]: /src/Config.js

   - **本地直接运行demo：**

     ```
     let Config = {
         rtc: {
             iceServers: [{
                 urls: ["turn:113.108.32.190"],//["turn:{{私有化真实的ip}}"],
                 username: 'kurento',
                 credential: 'kurento'
             }
             ]
         },
         server: "ws://113.108.32.190/rtc",//"ws://{{私有化真实的ip地址}}/rtc"
         token: "",
         node: "",
         cameraId: '',
     
         //5g方案
         server_5g: 'ws://113.108.32.190/sfu/ws',//"ws://{{私有化真实的ip地址}}/sfu/ws"
         codec: 'vp8',
         iceServers: [
             {
                 "urls": "stun:113.108.32.190",//["stun:{{私有化真实的ip}}"],
             }
         ]
     };
     
     export default Config;
     ```

     

   - **服务器代理运行demo：**

     ```
     let Config = {
         rtc: {
             iceServers: [{
                 urls: ["turn:113.108.32.190"],//["turn:{{私有化真实的ip}}"],
                 username: 'kurento',
                 credential: 'kurento'
             }
             ]
         },
         server: "ws://192.168.0.80:8082/rtc",//"ws://{{代理服务器访问地址}}/rtc"
         token: "",
         node: "",
         cameraId: '',
     
         //5g方案
         server_5g: 'ws://192.168.0.80:8082/sfu/ws',//"ws://{{代理服务器访问地址}}/sfu/ws"
         codec: 'vp8',
         iceServers: [
             {
                 "urls": "stun:113.108.32.190",//["stun:{{私有化真实的ip}}"],
             }
         ]
     };
     
     export default Config;
     ```

     

   3. **另外运行视频demo需要开放端口配置，具体端口：**

      |    端口     | 协议 | 描述              | Description         |
      | :---------: | ---- | ----------------- | ------------------- |
      |     443     | TCP  | HTTPS访问接口     | HTTPS access        |
      |    3478     | UDP  | 视频UDP TURN/STUN | Video UDP TURN/STUN |
      | 49152-65535 | UDP  | 视频UDP TURN/STUN | Video UDP TURN/STUN |
      |  5000-5200  | UDP  | 5G视频推流        | 5G video streaming  |
      |    1935     | TCP  | 5G录像            | RTMP                |

      - 443端口是用户浏览器与服务器之间的访问接口。
      - 3478、49152-65535端口是部署在公网的硬件设备通过阿里云转发服务器与业务系统服务器数据通信，和部署在公网的硬件设备与业务系统服务器建立通信连接（视频连接）使用的。
      - 5000-5200端口是建立了视频连接后，视频推流的端口，1路视频推流需要4个端口，1路视频拉流也需要4个端口，系统会自动根据实际推流/拉流情况动态分配端口。
      - 1935端口用于5G录像使用。