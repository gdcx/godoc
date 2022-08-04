[toc]

### HTTP 请求地址

请求地址前缀:

BASE_URL = https://drone.godouav.com/portal/%n%

> %n% 为节点id

### 请求头

所有请求必须包含access_token 头

### 应答消息

应答采用json结构体

```json
{
	// 状态码
    "code": 0,
    "msg": "内容，暂未填充",
	// 任意结构体或数组， 无数据一般为空
    "data": {}
}
```

### 状态码

0 无错误  
1 参数错误  
2 内部错误  
3 未连接  


### API 接口

#### 执行任务

##### Request

- Method: **POST**
- URL: $BASE_URL/aiprot/startMission
- Headers: 
	- access_token
- Body:

```json
{
	"airportId": "机场Id",
	"missionId": "任务Id",
	"executionId": "执行Id"
}
```

##### Response
- Body:
```json
{
	"code": 0,
	"msg": ""
}
```

#### 取消任务

##### Request

- Method: **GET**
- URL: $BASE_URL/airport/cancelMission/$missionId
- Headers:
	- access_token
- Query:
- Body:

##### Response
- Body:
```json
{
	"code": 0,
	"msg": ""
}
```

#### 机场开门

##### Request

- Method: **GET**
- URL: $BASE_URL/airport/openDoor
- Headers:
	- access_token
- Query:
	- id=$airportId
- Body: 

##### Response
- Body:
```json
{
	"code": 0,
	"msg": ""
}
```

#### 机场复位

##### Request
- Method: **GET**
- URL: $BASE_URL/airport/reset
- Headers:
	- access_token
- Query:
	- id=$airportId
- Body: 

##### Response
- Body:
```json
{
	"code": 0,
	"msg": ""
}
```

#### 机场重启

##### Request
- Method: **GET**
- URL: $BASE_URL/airport/reboot
- Headers:
	- access_token
- Query:
	- id=$airportId
- Body: 

##### Response
- Body:
```json
{
	"code": 0,
	"msg": ""
}
```

#### 机场紧急停止

##### Request
- Method: **GET**
- URL: $BASE_URL/airport/emergencyStop
- Headers:
	- access_token
- Query:
	- id=$airportId
- Body: 

##### Response
- Body:
```json
{
	"code": 0,
	"msg": ""
}
```

#### 机场取消紧急停止

##### Request
- Method: **GET**
- URL: $BASE_URL/airport/cancelEmergencyStop
- Headers:
	- access_token
- Query:
	- id=$airportId
- Body: 

##### Response
- Body:
```json
{
	"code": 0,
	"msg": ""
}
```

#### 吊舱回中

##### Request
- Method: **GET**
- URL: $BASE_URL/gimbal/center
- Headers:
	- access_token
- Query:
	- id=$gimbalId
- Body: 

##### Response
- Body:
```json
{
	"code": 0,
	"msg": ""
}
```

#### 吊舱跟随机头

##### Request
- Method: **GET**
- URL: $BASE_URL/gimbal/followHead
- Headers:
	- access_token
- Query:
	- id=$gimbalId
- Body: 

##### Response
- Body:
```json
{
	"code": 0,
	"msg": ""
}
```

#### 吊舱连续动作停止

> 用于移动操作的停止指令

##### Request
- Method: **GET**
- URL: $BASE_URL/gimbal/stop
- Headers:
	- access_token
- Query:
	- id=$gimbalId
- Body: 

##### Response
- Body:
```json
{
	"code": 0,
	"msg": ""
}
```

#### 吊舱左转

##### Request
- Method: **GET**
- URL: $BASE_URL/gimbal/left
- Headers:
	- access_token
- Query:
	- id=$gimbalId
- Body: 

##### Response
- Body:
```json
{
	"code": 0,
	"msg": ""
}
```

#### 吊舱右转

##### Request
- Method: **GET**
- URL: $BASE_URL/gimbal/right
- Headers:
	- access_token
- Query:
	- id=$gimbalId
- Body: 

##### Response
- Body:
```json
{
	"code": 0,
	"msg": ""
}
```

#### 吊舱上移

##### Request
- Method: **GET**
- URL: $BASE_URL/gimbal/up
- Headers:
	- access_token
- Query:
	- id=$gimbalId
- Body: 

##### Response
- Body:
```json
{
	"code": 0,
	"msg": ""
}
```

#### 吊舱下移

##### Request
- Method: **GET**
- URL: $BASE_URL/gimbal/down
- Headers:
	- access_token
- Query:
	- id=$gimbalId
- Body: 

##### Response
- Body:
```json
{
	"code": 0,
	"msg": ""
}
```
#### 吊舱左上移动

##### Request
- Method: **GET**
- URL: $BASE_URL/gimbal/leftUp
- Headers:
	- access_token
- Query:
	- id=$gimbalId
- Body: 

##### Response
- Body:
```json
{
	"code": 0,
	"msg": ""
}
```
#### 吊舱左下移动

##### Request
- Method: **GET**
- URL: $BASE_URL/gimbal/leftDown
- Headers:
	- access_token
- Query:
	- id=$gimbalId
- Body: 

##### Response
- Body:
```json
{
	"code": 0,
	"msg": ""
}
```
#### 吊舱右上移动

##### Request
- Method: **GET**
- URL: $BASE_URL/gimbal/rightUp
- Headers:
	- access_token
- Query:
	- id=$gimbalId
- Body: 

##### Response
- Body:
```json
{
	"code": 0,
	"msg": ""
}
```
#### 吊舱右下移动

##### Request
- Method: **GET**
- URL: $BASE_URL/gimbal/rightDown
- Headers:
	- access_token
- Query:
	- id=$gimbalId
- Body: 

##### Response
- Body:
```json
{
	"code": 0,
	"msg": ""
}
```

#### 吊舱变焦放大

##### Request
- Method: **GET**
- URL: $BASE_URL/gimbal/zoomIn
- Headers:
	- access_token
- Query:
	- id=$gimbalId
- Body: 

##### Response
- Body:
```json
{
	"code": 0,
	"msg": ""
}
```

#### 吊舱变焦缩小

##### Request
- Method: **GET**
- URL: $BASE_URL/gimbal/zoomOut
- Headers:
	- access_token
- Query:
	- id=$gimbalId
- Body: 

##### Response
- Body:
```json
{
	"code": 0,
	"msg": ""
}
```

#### 吊舱变焦停止

##### Request
- Method: **GET**
- URL: $BASE_URL/gimbal/zoomStop
- Headers:
	- access_token
- Query:
	- id=$gimbalId
- Body: 

##### Response
- Body:
```json
{
	"code": 0,
	"msg": ""
}
```

#### 吊舱一键向下

##### Request
- Method: **GET**
- URL: $BASE_URL/gimbal/oneKeyDown
- Headers:
	- access_token
- Query:
	- id=$gimbalId
- Body: 

##### Response
- Body:
```json
{
	"code": 0,
	"msg": ""
}
```

#### 吊舱切换视频源

> 用于切换可见光、红外

##### Request
- Method: **GET**
- URL: $BASE_URL/gimbal/switchCam
- Headers:
	- access_token
- Query:
	- id=$gimbalId
- Body: 

##### Response
- Body:
```json
{
	"code": 0,
	"msg": ""
}
```

#### 起飞

> 用于飞机已通电情况下直接arm起飞,起飞后飞机将悬停

##### Request
- Method: **GET**
- URL: $BASE_URL/drone/takeOff
- Headers:
	- access_token
- Query:
	- id=$droneId
- Body: 

##### Response
- Body:
```json
{
	"code": 0,
	"msg": ""
}
```

#### 一键起飞

> 无任务模式直接上电起飞，起飞后悬停，一般配合指点功能使用

##### Request
- Method: **GET**
- URL: $BASE_URL/airport/oneKeyTakeOffInAirport
- Headers:
	- access_token
- Query:
- Body: 
```json
{
	""
}
```

##### Response
- Body:
```json
{
	"code": 0,
	"msg": ""
}
```

#### 指点飞行

##### Request
- Method: **GET**
- URL: $BASE_URL/drone/goTo
- Headers:
	- access_token
- Query:
- Body: 
```json
{
	"id": "无人机id",
	// 经度
	"longitude": 22.0,
	// 纬度
	"latitude": 114.0,
	// 相对高度,米
	"altitude": 50.0,
	// 障碍物高度，米
	"obstacle": 60.0
}
```

##### Response
- Body:
```json
{
	"code": 0,
	"msg": ""
}
```

#### 精准指点飞行

##### Request
- Method: **GET**
- URL: $BASE_URL/drone/preciseGoTo
- Headers:
	- access_token
- Query:
- Body: 
```json
{
	"id": "无人机id",
	// 终点经度
	"longitude": 22.0,
	// 终点纬度
	"latitude": 114.0,
	"heights": [
		// 相对高度1, 米
		10.0,
		// 相对高度2, 米
		15.0
	],
	// 间隔距离,米
	"interval": 5
}
```

##### Response
- Body:
```json
{
	"code": 0,
	"msg": ""
}
```

#### 继续执行任务

##### Request
- Method: **GET**
- URL: $BASE_URL/drone/continueMission
- Headers:
	- access_token
- Query:
	- id=$droneId
- Body: 

##### Response
- Body:
```json
{
	"code": 0,
	"msg": ""
}
```
#### 悬停

##### Request
- Method: **GET**
- URL: $BASE_URL/drone/hold
- Headers:
	- access_token
- Query:
	- id=$droneId
- Body: 

##### Response
- Body:
```json
{
	"code": 0,
	"msg": ""
}
```

#### 返航

##### Request
- Method: **GET**
- URL: $BASE_URL/drone/return
- Headers:
	- access_token
- Query:
	- id=$droneId
- Body: 

##### Response
- Body:
```json
{
	"code": 0,
	"msg": ""
}
```

#### 持续升高

##### Request
- Method: **GET**
- URL: $BASE_URL/drone/continuousOP
- Headers:
	- access_token
- Query:
- Body: 
```json
{
    "id": "无人机id",
	// 见 ContinuousOP 
	"op": 0
}
```

##### Response
- Body:
```json
{
	"code": 0,
	"msg": ""
}
```

#### 航向锁定

##### Request
- Method: **GET**
- URL: $BASE_URL/drone/lockYaw
- Headers:
	- access_token
- Query:
- Body: 
```json
{
    "id": "无人机id",
	// [0, 360), -1 为解锁
	"yaw": 220
}
```

##### Response
- Body:
```json
{
	"code": 0,
	"msg": ""
}
```
#### 查询航向锁定

##### Request
- Method: **GET**
- URL: $BASE_URL/drone/queryLockYaw
- Headers:
	- access_token
- Query:
	- id=$droneId
- Body: 

##### Response
- Body:
```json
{
	"code": 0,
	"msg": ""
}
```

#### 环绕飞行

##### Request
- Method: **GET**
- URL: $BASE_URL/drone/orbit
- Headers:
	- access_token
- Query:
- Body: 
```json
{
	"id": "无人机id",
	// 半径,米
	"radius": 10,
	// 速度
	"velocity": 3,
	// 经度
	"longitude": 114.11,
	// 纬度
	"latitude": 22.11,
	// 海拔
	"altitude": 50.00
}

```

##### Response
- Body:
```json
{
	"code": 0,
	"msg": ""
}
```

#### 指点朝向

##### Request
- Method: **GET**
- URL: $BASE_URL/drone/conditionYaw
- Headers:
	- access_token
- Query:
- Body: 
```json
{
	"id": "无人机id",
	// 经度
	"longitude": 114.11,
	// 纬度
	"latitude": 22.11
}
```

##### Response
- Body:
```json
{
	"code": 0,
	"msg": ""
}
```


### MQTT 消息

> %n% 为节点id  
> %a% 为机场Id  
> %d% 为无人机id

#### 机场信息

- Topic: node/%n%/ap/%a%/station
- 消息体： 
```json
{
	// 机场型号,见AirportVersion 定义
	"version": 0,
	// 是否允许远程控制
    "allowRemoteControl": 1,
	// 是否连接
	"connected": 1,
	// 任务阶段
	"missionState": 1,
	// 机场紧急模式
    "emergency": 0,
	// 机场错误模式
    "fault":  0,
	// 内部湿度
	"innerHumidity": 55.0,
	// 内部温度
	"innerTemperature": 35.0,
	// 复位是否完成
	"interruptDone": 1,
	// 飞机起飞完毕
    "takeOffDone": 1,
	// 飞机降落完毕
    "landingDone": 0,
	// 降落准备完毕
	"landingReady": 0,
	// 电池操作, 见BatteryOP 定义
    "batteryOP":  0,
	"batteries": [
	 	{
			// 槽位
			"slot": 1,
			// 是否空
			"empty": false,
			// 电压
			"voltage": 24.5，
			// 电流
			"current": 1.3 ,
			// 电池容量
			"capacity": 90,
		}
	],
	// 放置无人机电池完毕
    "placeBatteryFinished": 1,
	// 移除无人机电池完毕
    "removeBatteryFinished": 0,
}
```


#### 机场运动信息
- Topic: node/%n%/ap/%a%/moving
- 消息体： 
```json
{
	// 起飞控制
    "takeOffControl": true,
	// 降落控制
    "landingControl": false,
	// 门状态, 见DevState
    "doorState": 0,
	// 平台状态
    "platformState": 3,
	// 夹子状态
    "clapState": 1,
	// 门移动状态, 见MovingState
    "doorMove": 0,
	// 平台移动状态
    "platformMove": 1,
	// 夹子移动状态
    "clapMove": 0
}
```

#### 机场气象信息
- Topic: node/%n%/ap/%a%/weather
- 消息体： 
```json
{
	// 温度
    "temperature": 25.0,
	// 湿度
    "humidity": 60,
	// 大气压
    "pressure": 10001,
	// 雨量
    "rain":  0.001,
	// 最小风速
    "windSpeedMin": 1.0,
	// 最大风速
    "windSpeedMax": 3.0,
	// 平均风速
    "windSpeedAvg": 2.0 
}

```

#### 无人机信息

- Topic: node/%n%/drone/%d%
- 消息体：

```json
{
    // drone system id
    "droneId": 1,
	"executionsId": "无人机任务id",
	// 执行类型， 见ExeType定义
	"exeType": 0,
	"recordTime": "记录时间戳",
	// 无人机是否已连接
	"connected": true,
	// 无人机系统id, mavlink 通讯唯一标识
	"systemId": 1,
	// 是否arm
	"armed": true,
	// 上传任务成功
    "uploadSuccess": true,
	// 无人机飞行模式, 见FlightMode
    "flightMode": 1,
    "flightModeDesc": "飞行模式描述",
	"home": {
		"latitude": 12.345678,
		"longitude": 12.345678,
		"altitudeMSL": 30,
	},
    "latitudeDeg": 12.345678,
    "longitudeDeg": 12.345678,
    "altitude": 30,
    "altitudeRelative": 20,
	// 电压
	"voltage":  10.1,
	// 剩余电量
	"batteryLife": 0.8,
	// GPS 星数
	"gPSCount": 30,
	// 地速
	"groundSpeed": 5.0 ,
	// 降落状态， 见LandedState
	"landedState": 1,
	// 降落类型，见LandingType
	"landingType": 1,
	"msg": "无人机文本状态, 无固定格式",
	// 无人机姿态
	"pitch":  0.01,
	// 无人机姿态
	"yaw": 0.01,
	// 无人机姿态
	"roll": 0.01,
	// 飞行时间
	"duration": 300,
	// 距home点距离, 米
	"distance": 30
}
```

### 类型定义

* BatteryOP

| 值 | 含义 |
|----|--------|
|0 | 操作完成 |
|1 | 无人机换电池 |
|2 | 无人机拔电  |
|3 | 无人机上电  |


* DevState

| 值 | 含义 |
|----|--------|
|0 | 关闭  |
|1 | 打开  |
|2| 上   |
|3| 下  |

* MoveMode

| 值 | 含义 |
|----|--------|
|0| 静止  |
|1| 向上   |
|2| 向下   |
|3| 向左  |
|4| 向右  |
|5| 开    |
|6| 合   |

* LandedState

| 值 | 含义 |
|----|--------|
|1| OnGround  |
|2| InAir  |
|3| TakeOff | 
|4| Landing  |

* ContinuousOP 

| 值 | 含义 |
|----|--------|
|0| Stop  |
|1| Up  |
|2| Down | 

* FlightMode

| 值 | 含义 |
|----|--------|
|1| FlightModeReady  |
|2| FlightModeTakeOff | 
|3| FlightModeLoiter | 
|4| FlightModeHold  |
|5| FlightModeMission  |
|6| FlightModeReturn  |
|7| FlightModeLand   |
|8| FlightModePRECLAND   |
|9| FlightModeOffBoard  |
|10| FlightModeFollow  |
|11| FlightModeManual  |
|12| FlightModeALTCTL  |
|13| FlightModePOSCTL | 
|14| FlightModeACRO  |
|15| FlightModeSTABILIZED  |
|16| FlightModeRATTITUDE  |


* LandingType

| 值 | 含义 |
|----|--------|
|1| NormalLanding  |
|2| SafeLanding  |

* AirportVersion

| 值 | 含义 |
|----|--------|
|0| T2 |
|1| Lite |

* ExeType

| 值 | 含义 |
|----|--------|
|0| 手动飞行  |
|1| 定时任务  |
|2| 快速起飞  |
|3| 报警响应   |

