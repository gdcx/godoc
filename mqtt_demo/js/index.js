
class MqttClient {
  constructor(clientId, username) {
    this.connection = {
      host: 'wss://drone.godouav.com',
      port: '',//403,
      endpoint: '/mqtt/mqtt',
      clean: true, // 保留会话
      connectTimeout: 30000, // 超时时间
      reconnectPeriod: 30000, // 重连时间间隔
      // 认证信息
      clientId: clientId,
      username: username,
      password: '',
      keepalive: 30
    };
    this.subscription = {
      topic: '',
      qos: 0,
    };
    this.publication = {
      topic: '',
      qos: 0,
      payload: '{ "msg": "Hello, I am browser." }',
    };
    this.receiveNews = '';
    this.qosList = [
      { label: 0, value: 0 },
      { label: 1, value: 1 },
      { label: 2, value: 2 },
    ];
    this.client = this.initMqttClient.bind(this);
    this.subscribeSuccess = false;
    this.doSubscribe = this.doSubscribe.bind(this);
    this.doUnSubscribe = this.doUnSubscribe.bind(this);
    this.seq = Math.round(new Date() / 1000);
  }

  //初始化mqtt客户端
  initMqttClient(){
    console.log('mqtt init' + new Date())
    let receiveMsg = $('#receiveMsg')
    receiveMsg.append(new Date() + ':   <div>mqtt init</div>')
    let _this = this
    // 连接字符串, 通过协议指定使用的连接方式
    // ws 未加密 WebSocket 连接
    // wss 加密 WebSocket 连接
    // mqtt 未加密 TCP 连接
    // mqtts 加密 TCP 连接
    // wxs 微信小程序连接
    // alis 支付宝小程序连接
    //   _this.connection.clientId = _this.connection.clientId;
    //   _this.connection.username = _this.connection.username;

    const { host, port, endpoint, ...options } = _this.connection;
    const connectUrl = `${host}:${port}${endpoint}`;
    // console.log(connectUrl)
    // console.log(options)
    try {
      _this.client = mqtt.connect(connectUrl, options);
    } catch (error) {
      console.log('mqtt.connect error', error)
      receiveMsg.append(new Date() + ':   <div>mqtt.connect error!</div>')
    }
    _this.client.on('connect', () => {
      console.log('mqtt Connection succeeded!' + new Date())
      receiveMsg.append(new Date() + ':   <div>mqtt Connection succeeded!</div>')
      _this.client.connected = true

    })
    _this.client.on('error', error => {
      console.log('mqtt Connection failed', error)
      receiveMsg.append(new Date() + ':   <div>mqtt Connection failed!</div>')
    })
  }

  doSubscribe(topicUrl, callback){
    this.subscription.topic = topicUrl
    const { topic, qos } = this.subscription
    if (this.client.connected) {
      this.client.subscribe(topic, qos, (error, res) => {
        if (error) {
          console.log('Subscribe to topics error', error)
          return
        }
        this.subscribeSuccess = true
        // console.log('Subscribe to topics res', res)

        this.client.on('message', (topic, message) => {
          if (topic === topicUrl) {
            callback(topic, JSON.parse(message));
          }
        })

      })
    }

  }
  //取消订阅
  doUnSubscribe(topicUrl){
    this.subscription.topic = topicUrl
    const { topic } = this.subscription
    this.client.unsubscribe(topic, error => {
      if (error) {
        console.log('Unsubscribe error', error)
      }
    })
  }
  //消息发布
  doPublish(topicUrl, payloadMsg){
    this.i++;
    this.publication.topic = topicUrl
    this.publication.payload = payloadMsg
    const { topic, qos, payload } = this.publication
    this.client.publish(topic, payload, qos, error => {
      if (error) {
        console.log('Publish error', error)
      }
    })
  }
  //断开连接
  destroyConnection(){
    if (this.client.connected) {
      try {
        this.client.end()
        this.client = {
          connected: false,
        }
        console.log('Successfully disconnected!')
      } catch (error) {
        console.log('Disconnect failed', error.toString())
      }
    }
  }

}