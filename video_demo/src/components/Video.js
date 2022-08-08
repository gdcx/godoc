import React from 'react';
import WebRTC from '../WebRTC';

class Video extends React.Component {
    constructor(props) {
        super(props);

        this.state = {
            'id': props.cameraId,
        };
        this.rtc = props.rtc;

        this.handleClick = this.handleClick.bind(this);
        this.onStart = this.onStart.bind(this);
        this.onStop = this.onStop.bind(this);
        this.onStreamReady = this.onStreamReady.bind(this);
    }

    render() {
        return (
            <div>
                <video width="640" height="480" controls autoPlay id="rtc" />
            </div>
        );
    };

    handleClick(evt) {
        if (evt.target.paused) {
            this.onStart();
        } else {
            this.onStop();
        }
    }

    onStart() {
        console.log('onStart');
        this.rtc.start();
    }

    onStop() {
        console.log('onStop');
        this.rtc.stop();
    }

    onStreamReady(stream) {
        document.getElementById(this.props.cameraId).srcObject = this.stream;
    }
}

export default Video;