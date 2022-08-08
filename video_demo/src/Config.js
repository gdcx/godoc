// all the config for this project
let Config = {
    rtc: {
        iceServers: [{
            urls: ["turn:p.godouav.com"],
            username: 'kurento',
            credential: 'kurento'
        }
        ]
    }
};

export default Config;