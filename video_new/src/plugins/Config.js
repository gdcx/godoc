
let Config = {
    wsUrl: '',//视频连接ws 测试地址ws://dev.godouav.com/rtc1/ws 公网地址：wss://drone.godouav.com/rtc1/ws
    accessToken: 'eyJhbGciOiJIUzI1NiJ9.eyJTdGF0dXMiOjAsIkNyZWF0ZUJ5IjoiMTAwMDAxMDAwMDAwMDAwMDAwMDAwMDAwMDEiLCJpc3MiOiJnZGN4IiwiTW9iaWxlIjoiMTgzMDE2NTAyNjciLCJDcmVhdGVEYXRlIjoxNjU4MjIxMDQ3MDAwLCJOYW1lIjoi546L6ZuqIiwiVXBkYXRlQnkiOiIxNTQ5MzE3NDgzMjcyNDc0NjI0IiwiVXBkYXRlRGF0ZSI6MTc0MjQ0MjU0MjAwMCwiVXNlcklkIjoiMTU0OTMxNzQ4MzI3MjQ3NDYyNCIsIkZhY2VJbWFnZSI6bnVsbCwiZXhwIjoxNzQ0MDI4NzY1LCJpYXQiOjE3NDQwMTQzNjUsIkFjY291bnRzIjoid3giLCJqdGkiOiI5ZTJmN2ExNi1hZTcxLTRkZDUtYmYwZC04YmNlYjZhZjgxYWEifQ.CvzA6-5Xl72K_nWkbdA0q-CLq5jbXscRLfxs6ZvmB1g',
    nodeId: '',//测试用98
    cameraId: '',//98无人机1725359469224923136146623831 机场视频1725358458292801536435857524  1725358458276024320243987971
    userId: '',//测试用1725361181457256448485625223
    rtc: {
        iceServers: [{
            urls: [""],//"turn:stun.godouav.com" //turn:qstun.godouav.com
            username: 'kurento',
            credential: 'kurento'
        }
        ]
    }
};

export default Config;