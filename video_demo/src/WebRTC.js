import Config from "./Config";
import { ICECandidate, LivePlay, SDP, Stream } from "./Message";

class WebRTC {
    constructor(signal, cameraId) {
        this.signal = signal;

        this.cameraId = cameraId
        this.session = Math.floor(Date.now() / 1000).toString();

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
    }


    // this is called when a message to cameraid is delivered
    onMessage(msg) {
        console.log("rtc onMessage");
        if (msg.cmd == "sdp") {

            const sdp = msg.data.sdp;
            this.pc.setRemoteDescription(
                new RTCSessionDescription(sdp)
            );
        } else if (msg.cmd == "icecandidate") {
            console.log(msg.data);
            this.pc.addIceCandidate(msg.data.candidate);
        } else {
            console.log('unhandled message:', msg)
        }
    }

    start() {
        console.log('rtc start');

        this.signal.addCamera(this.session, this);

        this.pc = new RTCPeerConnection(this.config);
        this.pc.onnegotiationneeded = this.handleNegotiationNeededEvent;
        this.stream = new MediaStream();

        this.pc.ontrack = (event) => {
            this.stream.addTrack(event.track);
            this.element.srcObject = this.stream;
            console.log(event.streams.length + ' track is delivered')
            //this.statisticsTimer = setInterval(this.printStatistics, 5000);
        };

        this.pc.oniceconnectionstatechange = this.handleICEConnectionStateChange;
        this.pc.onicecandidate = this.handleICECandidate;

        this.pc.addTransceiver('video', {
            'direction': 'recvonly',
        });
    }

    stop() {
        console.log('rtc stop');
        //clearInterval(this.statisticsTimer);
        // TODO
        this.pc.close()
    }

    handleNegotiationNeededEvent() {
        console.log('handleNegotiationNeededEvent, cameraId:', this.cameraId);
        this.pc.createOffer().then((offer) => {
            this.pc.setLocalDescription(offer);
            this.signal.sendMsg(new SDP(
                this.signal.nextSeq(),
                this.signal.getUserId(),
                this.signal.getPeer(),
                this.session,
                this.cameraId,
                offer,
                'main'))
        });
    }

    handleICEConnectionStateChange() {
        console.log('handleICEConnectionStateChange:' + this.pc.iceConnectionState);
    }

    handleICECandidate(ice) {
        console.log('handleICECandidate', ice);
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
            ice.candidate
        ));
    }

    switchStream(stream) {
        this.signal.sendMsg(new Stream(
            this.signal.nextSeq(),
            this.signal.getUserId(),
            this.signal.getPeer(),
            this.cameraId,
            this.session,
            stream
        ));
    }

    updateElement(element) {
        console.log('updateElement:', element);
        this.element = element;
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

            console.log(statsOutput);
        });
    }
};

export default WebRTC;