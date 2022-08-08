class WSMsg {
    constructor(cmd, from, to, seq, data) {
        this.cmd = cmd;
        this.from = from;
        this.to = to;
        this.seq = seq;
        this.data = data;
    }
}

class SDP extends WSMsg {
    constructor(seq, from, to, session, cameraId, sdp, stream) {
        super("sdp", from, to, seq, {
            "session": session,
            "cameraId": cameraId,
            "sdp": sdp,
            "streamType": stream
        });
    }
}


class Answer extends WSMsg {
    constructor(seq, from, to, code, session) {
        super("answer", seq, from, to, {
            "code": code,
            "session": session
        });
    }
}

class ICECandidate extends WSMsg {
    constructor(seq, from, to, session, cameraId, candidate) {
        super("icecandidate", from, to, seq, {
            "session": session,
            "cameraId": cameraId,
            "candidate": candidate,
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

class Stream extends WSMsg {
    constructor(seq, from, to, cameraId, session, stream) {
        super("stream", from, to, seq, {
            "cameraId": cameraId,
            "session": session,
            "streamType": stream
        });
    }
}


export { WSMsg, Disconnect, SDP, ICECandidate, Rsp, HeartBeat, Stream }