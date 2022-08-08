import * as Msg from './Message';

class WS {
    constructor(addr, token, userId, node) {
        this.addr = addr;
        this.token = token;
        this.userId = userId;
        this.peer = node;
        this.companyId = 1;
        this.cameras = new Map();
        this.seq = 0;

        this.socket = new WebSocket(this.addr + "?verify=user&id=" + this.userId + "&password=" + this.token);
        this.sendMsg = this.sendMsg.bind(this);
        this.socket.onopen = this.onOpen.bind(this);
        this.socket.onmessage = this.onMessage.bind(this);
        this.socket.onclose = this.onClose.bind(this);
        this.sendHA = this.sendHA.bind(this);
        this.addCamera = this.addCamera.bind(this);
        this.connected = false;
    }

    onOpen() {
        console.log('ws onOpen');
        this.connected = true;
        this.haTimer = setInterval(this.sendHA, 30000);
        this.seq = Math.floor(Date.now() / 1000);
        if (this.onConnected) {
            this.onConnected();
        }
    }

    addCamera(k, v) {
        this.cameras.set(k, v)
    }

    onMessage(evt) {
        let obj = JSON.parse(evt.data);
        if (obj.data.session != '') {
            for (let [k, v] of this.cameras) {
                console.log('k:', k)
                if (k === obj.data.session) {
                    v.onMessage(obj);
                }
            }
        }
    }

    onClose() {
        console.log('ws closed');
        this.connected = false;
        clearInterval(this.haTimer);
    }

    nextSeq() {
        this.seq++;
        return this.seq;
    }

    getUserId() {
        return this.userId;
    }

    getPeer() {
        return this.peer;
    }

    sendMsg(msg) {
        console.log('send: ', msg);
        this.socket.send(JSON.stringify(msg));
    }

    sendHA() {
        let msg = new Msg.HeartBeat(this.nextSeq(), this.getUserId(), "server");
        this.sendMsg(msg);
    }
};

export default WS;