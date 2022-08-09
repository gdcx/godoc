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
            cameraId: Config.camerId,
            showVideo: false,
            connecting: false,
            stream: 'main'
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
    }

    render() {
        let btnText = this.getBtnText();
        return (
            <form >
                <label>Websocket 地址:</label>
                <input type="text" value={this.state.wsAddr} size="50" onChange={this.changeWS}></input>
                <br></br>

                <label>Token:</label>
                <input type="text" value={this.state.token} size="50" onChange={this.changeToken}></input>
                <br></br>

                <label> Node:
                </label>
                <input type="text" value={this.state.node} size="10" onChange={this.changeNode}></input>
                <br></br>

                <label> CameraID:
                </label>
                <input type="text" value={this.state.cameraId} size="30" onChange={this.changeCameraId}></input>
                <br></br>

                <input type="button" value={btnText} onClick={this.onBtnClick}></input><br></br>
                <input type="button" value="切换玛流" onClick={this.onSwitchStream}></input>
                {this.state.showVideo &&
                    < Video cameraId={this.state.cameraId} rtc={this.rtc} />
                }
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
            cameraID: event.target.value
        })
    }

    onBtnClick(event) {
        if (this.state.connecting) {
            this.onDisconnect(event)
        } else {
            this.onPlay(event)
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

    onDisconnect(event) {
        //this.rtc.stop()
        document.getElementById(this.cameraId).pause();
        this.setState({
            connecting: false
        })
    }

    onPlay(event) {
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
            return '断开';
        }
        return '连接';
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
