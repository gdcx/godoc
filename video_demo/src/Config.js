// all the config for this project
let Config = {
    rtc: {
        iceServers: [{
            urls: ["turn:stun.godouav.com"],
            username: 'kurento',
            credential: 'kurento'
        }
        ]
    },
    server: "wss://drone.godouav.com/rtc",
    token: "",
    node: "",
    cameraId: "",

    //5g方案
    server_5g: 'wss://drone.godouav.com:443/sfu/ws',
    codec: 'vp8',
    iceServers: [
        {
            "urls": "stun:stun.godouav.com",
        }
    ]
};

export default Config;