class Ability {
    constructor(audio_send, video_recv, audio_recv) {
        // default off
        this.video_send = false
        this.audio_send = audio_send
        this.video_recv = video_recv
        this.audio_recv = audio_recv

        this.getVideoDir = this.getVideoDir.bind(this)
        this.getAudioDir = this.getAudioDir.bind(this)
    }

    getVideoDir() {
        if (this.video_recv && this.video_send) {
            return "sendrecv"
        } else if (this.video_recv) {
            return "recvonly"
        } else if (this.video_send) {
            return "sendonly"
        } else {
            return ""
        }
    }

    getAudioDir() {
        if (this.audio_recv && this.audio_send) {
            return "sendrecv"
        } else if (this.audio_recv) {
            return "recvonly"
        } else if (this.audio_send) {
            return "sendonly"
        } else {
            return ""
        }
    }
}

export { Ability }