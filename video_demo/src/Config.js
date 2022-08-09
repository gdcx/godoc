// all the config for this project
let Config = {
    rtc: {
        iceServers: [{
            urls: ["turn:p.godouav.com"],
            username: 'kurento',
            credential: 'kurento'
        }
        ]
    },
    server: "wss://drone.godouav.com/rtc",
    token: "",
    node: "",
    camerId: ""
};

export default Config;