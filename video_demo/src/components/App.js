import React from 'react';
import Video from './Video';
import WS from '../WS';
import WebRTC from '../WebRTC';
import Config from '../Config';


class App extends React.Component {
    constructor(props) {
        super(props);

        this.state = {
            wsAddr: Config.server,
            token: Config.token,
            node: Config.node,
            cameraId: Config.cameraId,
            showVideo: false,
            connecting: false,
            stream: 'main',

            clientLocal: null,
            rtcObj: null,
            connecting5g: false,
        };

        this.changeWS = this.changeWS.bind(this);
        this.changeToken = this.changeToken.bind(this);
        this.changeNode = this.changeNode.bind(this);
        this.changeCameraId = this.changeCameraId.bind(this);
        this.onBtnClick = this.onBtnClick.bind(this);
        this.onSwitchStream = this.onSwitchStream.bind(this);
        this.onPlay = this.onPlay.bind(this);
        this.onDisconnect = this.onDisconnect.bind(this);
        this.getBtnText = this.getBtnText.bind(this);

        this.get5gBtnText = this.get5gBtnText.bind(this);

        this.on5gBtnClick = this.on5gBtnClick.bind(this)
    }

    render() {
        let btnText = this.getBtnText();
        let btn5gText = this.get5gBtnText();
        return (
            <form >
                <div>
                    <label>Websocket 地址:</label>
                    <input type="text" value={this.state.wsAddr} size="50" onChange={this.changeWS}></input>
                </div>
                <br></br>

                <div>
                <label>Token:</label>
                <input type="text" value={this.state.token} size="50" onChange={this.changeToken}></input>
                </div>
                <br></br>

                <div>
                <label> Node:
                </label>
                <input type="text" value={this.state.node} size="10" onChange={this.changeNode}></input>
                </div>
                <br></br>

                <div>
                <label> CameraID:
                </label>
                <input type="text" value={this.state.cameraId} size="30" onChange={this.changeCameraId}></input>
                </div>
                <br></br>

                <div>
                    <input type="button" value={btnText} onClick={this.onBtnClick}></input>
                </div>
                <div>
                <input type="button" value="切换玛流" onClick={this.onSwitchStream}></input>
                {this.state.showVideo &&
                    < Video cameraId={this.state.cameraId} rtc={this.rtc} />
                }
                </div>
                <input type="button" value={btn5gText} onClick={this.on5gBtnClick}></input>
            </form>
        )
    };

    changeWS(event) {
        this.setState({
            wsAddr: event.target.value
        })
    }

    changeToken(event) {
        this.setState({
            token: event.target.value
        })
    }

    changeNode(event) {
        this.setState({
            node: event.target.value
        })
    }

    changeCameraId(event) {
        this.setState({
            cameraId: event.target.value
        })
    }

    onBtnClick(event) {
        if (this.state.connecting) {
            this.onDisconnect(event)
        } else {
            this.onPlay(event)
        }
    }
    on5gBtnClick(event){
        if(this.state.connecting5g){
            this.onDisconnect5g(event)
        }else{
            this.onSwitch5gVideo(event)
        }
    }

    onSwitchStream(event) {
        if (this.state.stream == 'main') {
            this.state.stream = 'sub';
        } else {
            this.state.stream = 'main';
        }
        this.rtc.switchStream(this.state.stream);
    }

    //切换5g视频方案
    onSwitch5gVideo(event){
        console.log(this.state)
        if(this.rtc){
            this.rtc.stop()//切换5g视频选择关闭rtc
            this.rtc = null
            this.setState({
                connecting: false
            });
        }
        if (this.state.cameraId === '') {
            alert('无效CameraID!');
            return;
        }
        if (this.state.token === '') {
            alert('无效token!');
            return;
        }
        // 原始5g连接
        // const signalLocal = new Signal.IonSFUJSONRPCSignal(
        //     Config.server_5g
        // );
        // 20240905改版后,新增授权
        const signalLocal = new Signal.IonSFUJSONRPCSignal(
            Config.server_5g+'?access_token='+this.state.token
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
        this.setState({
            showVideo: true,
            connecting5g: true
        });
    }

    onDisconnect(event) {
        this.rtc.stop()
        this.rtc = null
        document.getElementById('rtc').pause();
        this.setState({
            connecting: false
        })
    }
    onDisconnect5g(event){
        if(this.clientLocal){
            this.clientLocal.close()
            this.clientLocal = null;
        }
        this.setState({
            connecting5g: false
        })
    }

    onPlay(event) {
        if(this.clientLocal){
            this.clientLocal.close()//关闭5g视频流
            this.clientLocal = null;
            this.setState({
                connecting5g: false
            });
        }
        if (this.state.wsAddr === '') {
            alert('无效websocket地址')
            return;
        }

        if (this.state.token === '') {
            alert('无效token!');
            return;
        }

        if (this.state.cameraId === '') {
            alert('无效CameraID!');
            return;
        }


        this.userId = this.getUserID();
        this.ws = new WS(this.state.wsAddr, this.state.token, this.userId, this.state.node);

        this.rtc = new WebRTC(this.ws, this.state.cameraId);
        console.log('cameraId:', this.state.cameraId, ', object:', document.getElementById('rtc'));
        this.rtc.updateElement(document.getElementById('rtc'));

        this.ws.onConnected = () => {
            this.rtc.start();
        }

        this.setState({
            showVideo: true,
            connecting: true
        });
    }

    getBtnText() {
        if (this.state.connecting) {
            return '断开自组网视频';
        }
        return '连接自组网视频';
    }
    get5gBtnText(){
        if (this.state.connecting5g) {
            return '断开5g视频';
        }
        return '连接5g视频';
    }

    getUserID() {
        return Date.parse(new Date()).toString();
    }

    componentDidUpdate(prevProps) {
        console.log('App componentDidUpdate');
        // for (let rtc of this.rtcs) {
        //     rtc.updateElement(document.getElementById(rtc.cameraId));
        // }
        if (this.rtc != null) {
            this.rtc.updateElement(document.getElementById('rtc'));
        }
    }

    componentDidMount() {
        console.log('App componentDidMount');
        // for (let rtc of this.rtcs) {
        //     rtc.updateElement(document.getElementById(rtc.cameraId));
        // }
    }
}

export default App;
