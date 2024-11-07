## 执行步骤
1. 进入video_demo文件夹 
2. 执行npm i 下载所需依赖
3. 执行npm start 浏览器中默认打开链接

参数说明：
1. Token 为生产中登录账号的token
2. Node 为当前无人机所在的nodeId
3. CameraID 为当前无人机的吊舱id （HD）
4. 连接自组网视频为自组网，连接5g为5g视频



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

   

2. video_demo中的配置文件,也需要更改配置 （**有端口的需要加上对应端口**）

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

