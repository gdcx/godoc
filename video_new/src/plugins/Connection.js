import { Ability } from "./Ability"
import { TargetMain, TargetSub,Stream } from "./Message"
import WebRTC from "./WebRTC"
class Connection {
    //ws 摄像机，streamType码流 sfu支持
    constructor(signal,cameraId,peer,sfu,streamType,audio_send,audio_recv){
        this.signal = signal
        this.signal.setPeer(peer)
        this.cameraId = cameraId
        this.sfu = sfu
        this.streamType = streamType;//0主 1辅

        this.session = cameraId+'_'+Math.floor(Date.now() / 1000).toString();
        this.onMessage = this.onMessage.bind(this);
        this.start = this.start.bind(this)
        this.stop = this.stop.bind(this)
        this.updateElement = this.updateElement.bind(this)
        this.changeStream = this.changeStream.bind(this)
        this.changeElement = this.changeElement.bind(this)

        if(sfu){
            this.mainAbility = new Ability(audio_send, false, false)//发送能力
            this.subAbility = new Ability(false, true, audio_recv)//接收能力
        }else{
            this.mainAbility = new Ability(false, true, false)//接收能力
        }
        this.main = new WebRTC(this.session,signal,cameraId,sfu,streamType,TargetMain,true,this.mainAbility)
        this.sub = null
        this.signal.addCamera(this.session,this)
        this.playCallback = null
    }

    start() {
        this.main.start()
    }

    stop() {
        this.main.stop()
        if (this.sub) {
            this.sub.stop()
        }
    }
    updateElement(element) {
        // console.log('updateElement:', element);
        this.element = element
        if (this.sfu) {
            if (this.sub == null) {
                return
            }
            this.sub.updateElement(element)
            return
        }
        this.main.updateElement(element)
    }
    changeStream(stream) {
        // console.log('切换码流con',stream)
        this.signal.sendMsg(new Stream(
            this.signal.nextSeq(),
            this.signal.getUserId(),
            this.signal.getPeer(),
            this.cameraId,
            this.session,
            stream
        ));
        this.streamType = stream
    }
    // this is called when a message to cameraid is delivered
    onMessage(msg) {
        console.log("conn onMessage:", msg);
        // on sub
        if (msg.cmd == "sdp" || (msg.cmd == "icecandidate" && msg.data.target == TargetSub)) {
            if (this.sub == null) {
                this.sub = new WebRTC(this.session, this.signal, this.cameraId,this.streamType, this.sfu, TargetSub, false, this.subAbility)
                this.sub.start()
                this.sub.updateElement(this.element)
            }
            this.sub.onMessage(msg)
            return
        }

        if (msg.cmd == "answer" || msg.cmd == "icecandidate") {
            if(this.playCallback){
                this.playCallback(true)
                this.playCallback = null
            }
            this.main.onMessage(msg)
        } else if (msg.cmd == "hb") {
        }
        else {
            if(msg instanceof Function){
                this.playCallback = msg
            }else{
                console.log('unhandled message:', msg)
            }
            
        }
    }

    changeElement(element){
        this.element = document.getElementById(element)
        if (this.sfu) {
            if (this.sub == null) {
                return
            }
            this.sub.changeElement(this.element)
            return
        }
        this.main.changeElement(this.element)
    }

}
export { Connection };