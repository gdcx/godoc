var host = window.location.host; 
let protocolType = window.location.protocol; //获取当前协议类别
let wsProtocol = 'wss://';
let isDev = false
let wsPort = '443';
if (protocolType === 'http:') { 
    wsProtocol = 'ws://'
    wsPort = '80'
    if(host.indexOf(':')>-1){
        let portSplit = host.split(':')
        let receivePort = portSplit[1]
        if(receivePort){
            wsProtocol = 'ws://'
            wsPort = receivePort
            host = portSplit[0]
        }
    }
    if (host.indexOf('localhost') > -1 || host.indexOf('192.168.0.82') > -1) {//测试环境开启
        wsProtocol = 'ws://'
        wsPort = '80'
        host = 'dev.godouav.com'
    }
    // 生产环境开启
    // if (host.indexOf('localhost') > -1 || host.indexOf('192.168.0.82') > -1) {//测试环境开启
    //     wsProtocol = 'wss://'
    //     wsPort = '443'
    //     host = 'drone.godouav.com'
    // }
}else if(protocolType === 'https:'){
    wsProtocol = 'wss://'
    wsPort = '443';
    if(host.indexOf(':')>-1){
        let portSplit = host.split(':')
        let receivePort = portSplit[1]
        if(receivePort){
            wsProtocol = 'wss://'
            wsPort = receivePort
            host = portSplit[0]
        }
    }
}
if(host.indexOf('dev.')>-1||host.indexOf('192.168.0.82')>-1||host.indexOf('localhost') > -1){
    isDev = true
}
let Config = {
    wsUrl: '',//视频连接ws 测试地址ws://dev.godouav.com/rtc1/ws
    accessToken: '',
    nodeId: '',//测试用98
    cameraId: '',//98无人机1725359469224923136146623831 机场视频1725358458292801536435857524  1725358458276024320243987971
    userId: '',//测试用1725361181457256448485625223
    rtc: {
        iceServers: [{
            urls: ["turn:qstun.godouav.com"],//"turn:stun.godouav.com"
            username: 'kurento',
            credential: 'kurento'
        }
        ]
    }
};

export default Config;