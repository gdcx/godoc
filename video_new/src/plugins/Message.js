class WSMsg{
    constructor(cmd,from,to,seq,data){
        this.cmd = cmd;
        this.from = from;
        this.to=to;
        this.seq = seq;
        this.data =data;
    }
}
class HeartBeat extends WSMsg {
    constructor(seq, from, to) {
        super("hb", from, to, seq, JSON.stringify({}));
    }
}
class Disconnect extends WSMsg {
    constructor(seq, from, to, session) {
        super("disconnect", from, to, seq, {
            "session": session
        });
    }
}

class JoinConfig {
    constructor(NoPublish,NoSubscribe, NoAutoSubscribe, StreamType, SFU) {
        this.NoPublish = NoPublish
        this.NoSubscribe = NoSubscribe
        this.NoAutoSubscribe = NoAutoSubscribe
        this.StreamType = StreamType
        this.SFU = SFU
    }
}

class SDP extends WSMsg {
    constructor(seq, from, to, session, cameraId, sdp, config) {
        super("sdp", from, to, seq, {
            "session": session,
            "cameraId": cameraId,
            "sdp": sdp,
            "config": config,
        });
    }
}
class Answer extends WSMsg {
    constructor(seq, from, to, session, cameraId, sdp) {
        super("answer", from, to, seq, {
            "session": session,
            "cameraId": cameraId,
            "sdp": sdp,
        });
    }
}
class ICECandidate extends WSMsg {
    constructor(seq, from, to, session, cameraId, candidate, target) {
        super("icecandidate", from, to, seq, {
            "session": session,
            "cameraId": cameraId,
            "candidate": candidate,
            "target": target
        });
    }
}
class Rsp extends WSMsg {
    constructor(seq, from, to, code) {
        super("rsp", from, to, seq, {
            "code": code
        });
    }
}
class Stream extends WSMsg {
    constructor(seq, from, to, cameraId, session, stream) {
        super("stream", from, to, seq, {
            "cameraId": cameraId,
            "session": session,
            "streamType": stream
        });
    }
}
const StreamFull = 0;
const StreamHalf = 1;
const StreamQuartor = 2;

const TargetMain = 0;//发送
const TargetSub = 1;//接收


export { WSMsg, Disconnect, SDP, Answer, ICECandidate, Rsp, HeartBeat, Stream, JoinConfig, StreamFull, StreamHalf, StreamQuartor, TargetMain, TargetSub }

