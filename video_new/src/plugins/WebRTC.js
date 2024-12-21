import Config from "./Config";
import { ICECandidate, JoinConfig, SDP, Stream, Answer } from "./Message";
/**
 * session 会话id
 * signal ws
 * cameraId 摄像机
 * sfu 采用sfu还是rtc
 * target 发/收
 * initial 是否支持创建offer
 * ability 能力支持
 */
class WebRTC {
    constructor(session, signal, cameraId, sfu,streamType, target, initial, ability) {
        this.signal = signal;

        this.cameraId = cameraId
        this.session = session
        this.sfu = sfu;
        this.streamType = streamType
        this.target = target;
        this.initial = initial
        this.ability = ability
        this.sdpExchanged = false

        this.start = this.start.bind(this);
        this.stop = this.stop.bind(this);

        this.config = {
            iceServers: Config.rtc.iceServers
        };

        this.handleICECandidate = this.handleICECandidate.bind(this);
        this.handleICEConnectionStateChange = this.handleICEConnectionStateChange.bind(this);
        this.handleNegotiationNeededEvent = this.handleNegotiationNeededEvent.bind(this);
        this.updateElement = this.updateElement.bind(this);
        this.printStatistics = this.printStatistics.bind(this);

        this.start = this.start.bind(this);
        this.stop = this.stop.bind(this);
        this.onMessage = this.onMessage.bind(this)
        this.pendingIces = []
    }


    // this is called when a message to cameraid is delivered
    onMessage(msg) {
        // console.log("rtc onMessage, target:", this.target);
        if (msg.cmd == "sdp" || msg.cmd == "answer") {
            const sdp = msg.data.sdp;
            this.pc.setRemoteDescription(
                new RTCSessionDescription(sdp)
            );
            if (msg.cmd == "sdp") {
                this.pc.createAnswer()
                    .then((answer) => this.pc.setLocalDescription(answer))
                    .then(() => {
                        this.signal.sendMsg(new Answer(
                            this.signal.nextSeq(),
                            this.signal.getUserId(),
                            this.signal.getPeer(),
                            this.session,
                            this.cameraId,
                            this.pc.localDescription))

                    })
            }
            this.pendingIces.forEach((item, _index) => {
                this.onMessage(item)
            })
            this.pendingIces = []
            this.sdpExchanged = true
        } else if (msg.cmd == "icecandidate") {
            if (!this.sdpExchanged) {
                // console.log('store candidates cauz remoteDescription is not set')
                this.pendingIces.push(msg)
                return
            }
            // console.log(msg.data);
            this.pc.addIceCandidate(msg.data.candidate);
        } else {
            console.log('unhandled message:', msg)
        }
    }

    start() {
        console.log('rtc start');

        this.pc = new RTCPeerConnection(this.config);
        this.pc.onnegotiationneeded = this.handleNegotiationNeededEvent;
        this.stream = new MediaStream();

        this.pc.ontrack = (event) => {
            this.stream.addTrack(event.track);
            // console.log(event.streams.length + ' track is delivered')
            if (this.element != null) {
                this.element.srcObject = this.stream;
            }
            //this.statisticsTimer = setInterval(this.printStatistics, 5000);
        };

        this.pc.oniceconnectionstatechange = this.handleICEConnectionStateChange;
        this.pc.onicecandidate = this.handleICECandidate;
        // console.log(this.ability)
        var audioDir = this.ability.getAudioDir()
        // console.log("audioDir:", audioDir)
        if (audioDir != "") {
            this.pc.addTransceiver('audio', {
                'direction': audioDir,
            });
        }

        var videoDir = this.ability.getVideoDir()
        if (videoDir == "" && audioDir == "") {
            console.log("pretend to recv video because audio is off")
            videoDir = "recvonly"
        }

        console.log("videoDir:", videoDir)
        if (videoDir != "") {
            this.pc.addTransceiver('video', {
                'direction': videoDir,
            });
        }
    }

    stop() {
        console.log('rtc stop');
        //clearInterval(this.statisticsTimer);
        // TODO
        this.pc.close()
    }

    handleNegotiationNeededEvent() {
        console.log('handleNegotiationNeededEvent, cameraId:', this.cameraId);
        if (this.initial) {
            this.pc.createOffer().then((offer) => {
                this.pc.setLocalDescription(offer);
                this.signal.sendMsg(new SDP(
                    this.signal.nextSeq(),
                    this.signal.getUserId(),
                    this.signal.getPeer(),
                    this.session,
                    this.cameraId,
                    offer,
                    new JoinConfig(false, false, false, this.streamType, this.sfu)))
            });
        }
    }

    handleICEConnectionStateChange() {
        console.log('handleICEConnectionStateChange:' + this.pc.iceConnectionState);
        if (this.pc.iceConnectionState === "disconnected") {
            // this.signal.socket.close()
            console.log("%c" + "rtc断开重连", "background: red; font-size: 20px;");
            this.start();
        }
    }

    handleICECandidate(ice) {
        // console.log('handleICECandidate', ice);
        if (ice.candidate == null) {
            console.log('ice candidate gathering finished');
            return;
        }
        this.signal.sendMsg(new ICECandidate(
            this.signal.nextSeq(),
            this.signal.getUserId(),
            this.signal.getPeer(),
            this.session,
            this.cameraId,
            ice.candidate,
            this.target,
        ));
    }

    changeStream(stream) {
        // console.log('切换码流rtc',stream)
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

    updateElement(element) {
        // console.log('updateElement:', element);
        this.element = element;
    }
    changeElement(element) {
        // console.log('changeElement:', element);
        this.element = element;
        if (this.element != null) {
            this.element.srcObject = this.stream;
        }
    }

    printStatistics() {
        this.pc.getStats(null).then(stats => {
            let statsOutput = "";

            stats.forEach(report => {
                statsOutput += `Report: ${report.type}\nID: ${report.id}\n` +
                    `Timestamp: ${report.timestamp}\n`;

                // Now the statistics for this report; we intentially drop the ones we
                // sorted to the top above

                Object.keys(report).forEach(statName => {
                    if (statName !== "id" && statName !== "timestamp" && statName !== "type") {
                        statsOutput += `${statName}: ${report[statName]}\n`;
                    }
                });
            });

            // console.log(statsOutput);
        });
    }
};

export default WebRTC;