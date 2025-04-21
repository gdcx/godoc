import * as Msg from './Message';
class WSClass {
    constructor(wsUrl, token, userId) {
        this.wsUrl=wsUrl
        this.token=token
        this.userSession = userId+ '_'+parseInt(new Date().getTime());
        this.userId=userId+ '_'+parseInt(new Date().getTime());
        this.connid = null;

        this.cameras=new Map()
        this.seq=parseInt(new Date().getTime());

        this.socket=null
        this.lockReturn=false;
        this.timeout=1000*30;
        this.timeoutObj=null;
        this.timeoutNum=null;
        this.serverTimeoutObj=null;
        this.heartCheckNum=0;
        this.notReconnect=false;
        this.initWebSocket=this.initWebSocket.bind(this)
        this.sendHeartbeat=this.sendHeartbeat.bind(this)
        this.reConnect=this.reConnect.bind(this)
        this.sendMsg=this.sendMsg.bind(this);
        this.storageMsg=[];


        this.connected=false;
        this.from='web_'+Math.round(new Date()/1000);
        this.to='server'

        //摄像头
        this.addCamera=this.addCamera.bind(this)
    }

    initWebSocket() {
        console.log('initWebSocket')
        //初始化websocket连接
        this.socket=new WebSocket(this.wsUrl+'?access_token='+this.token)
        this.socket.onopen=this.onOpen.bind(this);
        this.socket.onmessage=this.onMessage.bind(this);
        this.socket.onclose=this.onClose.bind(this);

    }
    onOpen() {
        // console.log('ws onOpen');
        //开始心跳检测
        this.sendHeartbeat(this);
        this.connected=true;
        // this.sendRegisterAll();
        if(Number(this.socket.readyState)==1){
            if(this.storageMsg.length>0){
                this.storageMsg.forEach((msg,index)=>{
                    this.socket.send(JSON.stringify(msg));
                    if(index==this.storageMsg.length-1){
                        this.storageMsg = []
                    }
                    
                })
            }
            
        }
        if (this.onConnected) {
            this.onConnected();
        }
    }
    onMessage(evt) {
        let _this=this
        let obj=JSON.parse(evt.data);
        // console.log('ws onMessage',obj)
        obj.data=obj.data;
        _this.notReconnect=false
        if (obj.data.code&&obj.data.code==1) {
            _this.notReconnect=true
            // console.log(obj.data.code)
            _this.connected=false;
        } else {
            this.heartCheckNum=0
            // if(obj.data.connid!=''){
            //     _this.connid = obj.data.connid
            // }else{
                if (obj.data.session!='') {
                    for (let [k, v] of this.cameras) {
                        if (k===obj.data.session) {
                            v.onMessage(obj);
                        }
                    }
                }
            // }
            
        }

    }
    onClose(e) {
        let _this=this
        console.log('ws closed', e);
        _this.connected=false;
        if (e.code===4000) {
            for (let [k, v] of _this.cameras) {
                v.stop()
            }
            _this.notReconnect=true
        } else {
            _this.reConnect()
        }
    }

    sendHeartbeat(_this) {
        _this.timeoutObj&&clearInterval(_this.timeoutObj)
        _this.timeoutObj=setInterval(function () {
            // console.log(_this.socket.readyState)
            if (_this.socket.readyState!=1&&!_this.notReconnect) {
                _this.reConnect()
            } else {
                let hb=new Msg.HeartBeat(_this.nextSeq(), _this.from, _this.to)
                _this.sendMsg(hb)
                _this.heartCheckNum++;
                if (_this.heartCheckNum>3) {
                    if (_this.socket) {
                        _this.socket.close()
                    }
                }
            }
        }, _this.timeout)
    }
    reConnect() {
        let _this=this
        if (_this.lockReturn) {
            return;
        }
        _this.lockReturn=true;
        _this.timeoutNum&&clearTimeout(_this.timeoutNum);
        _this.timeoutNum=setTimeout(function () {
            setTimeout(() => {
                if (!_this.notReconnect) {
                    //重连websocket
                    //token失效需要获取新的token
                    let token=localStorage.getItem("accessToken");
                    console.log(token)
                    if (token) {
                        _this.token = token
                        _this.initWebSocket()
                    }
                }

            }, 400);
            _this.lockReturn=false;
        }, 3000);
    }
    sendMsg(msg) {
        // console.log('send: ', msg);
        if (Number(this.socket.readyState)!==1) {//ws状态不正常堆积的消息
            this.storageMsg.push(msg);
        } else {
            this.socket.send(JSON.stringify(msg));
        }
    }
    addCamera(session, connection) {
        for (let [k, v] of this.cameras) {
            if (v.cameraId===connection.camera) {
                this.cameras.delete(k)
            }
        }
        this.cameras.set(session, connection)
        // console.log('ws' ,this.cameras)
    }
    nextSeq() {
        this.seq++;
        return this.seq;
    }
    getUserId() {
        return this.userId;
    }
    setPeer(peer) {
        this.peer=peer
    }
    getPeer() {
        return this.peer
    }
    getUserSession(){
        if(this.connid){
            return this.userId + '_'+this.connid
        }else{
            return this.userSession
        }   
        
    }
}
export default WSClass;