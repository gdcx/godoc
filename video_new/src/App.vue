<script setup>
import { ElMessage } from "element-plus"; // 引入el 提示框，这个项目里用什么组件库这里引什么
import "element-plus/theme-chalk/el-message.css";
import "element-plus/theme-chalk/el-message-box.css";
import VideoComp from './components/Video.vue'
import NewConfig from './plugins/Config'
import WS from './plugins/WS'
import { Connection } from './plugins/Connection';
import { watch } from "vue";
import Config from "./plugins/Config";
const ruleForm = reactive({
  url: Config.wsUrl,
  token: Config.accessToken,
  nodeId: Config.nodeId,
  cameraId: Config.cameraId,
  sfu: false,
  streamType: 0,
  // from: 0,//0无人机视频 1 机场视频
  userId: Config.userId,
  pullStreamType: 0//自组网推流0  服务器推流1
})
// const userId = Config.userId;
const rules = reactive({
  url: [
    { required: true, message: 'Please input Websocket Url', trigger: 'blur' }
  ],
  token: [
    {
      required: true,
      message: 'Please input Token',
      trigger: 'blur',
    },
  ],
  userId: [
    {
      required: true,
      message: 'Please input userId',
      trigger: 'blur',
    },
  ],
  nodeId: [
    {
      required: true,
      message: 'Please input NodeId',
      trigger: 'blur',
    },
  ],
  cameraId: [
    {
      required: true,
      message: 'Please input CameraId',
      trigger: 'blur',
    },
  ]
})
const ruleFormRef = ref()

let showVideoComp = ref(false)
let connected = ref(0);//0未建立连接 1已连接
let streamType = ref(0);//0为主码流 1为辅码流

let ws = null
let conn = null
const btnClick = ()=>{
  if(connected.value){
    disConnectFun()
  }else{
    connectFun()
  }
}
//连接
const connectFun = async()=>{
  if(!ruleFormRef.value) return;

  await ruleFormRef.value.validate((valid, fields) => {
    if (valid) {
      // 建立连接
      console.log('检验通过')
      ws = new WS(ruleForm.url,ruleForm.token,ruleForm.userId)
      ws.initWebSocket()
      if(conn && conn.main){
        conn.stop()
        conn = null
      }
      if(ruleForm.pullStreamType == 1){
        if(ruleForm.sfu){
          let cameraId = ruleForm.cameraId
          conn = new Connection(ws,cameraId,ruleForm.nodeId,ruleForm.sfu,ruleForm.streamType,false,false)
        }else{
          let cameraId = ruleForm.cameraId+'_dock'
          conn = new Connection(ws,cameraId,ruleForm.nodeId,ruleForm.sfu,ruleForm.streamType,false,false)
        }
        
      }else{
        conn = new Connection(ws,ruleForm.cameraId,ruleForm.nodeId,ruleForm.sfu,ruleForm.streamType,false,false)
      }
      let rtcEle = document.getElementById('rtc')
      conn.updateElement(rtcEle);
      if (ws) {
        conn.start();
      }
      connected.value = 1
      // connectText.value = connected.value?'断开连接':'建立连接'
    } else {
      console.log('error submit!', fields)
    }
  })

}
//断开连接
const disConnectFun = ()=>{
  if(conn && conn.main){
    conn.stop()
    conn = null
  }
  if(ws && ws.socket){
    ws.socket.close()
  }
  connected.value = 0
}
const changeStreamType = ()=>{
  if(streamType.value == 0){//表示主切辅
    streamType.value = 1
  }else{
    streamType.value = 0
  }
  conn.changeStream(streamType.value)
}

const connectText = computed(() => {
        return connected.value?'断开连接':'建立连接'
    })
const streamTypeText = computed(()=>{
  return streamType.value == 0 ?'主码流':'辅码流'
})
// watch(()=>connected.value,(val,Oval))
</script>

<template>
  <el-form
    label-width="auto"
    :model="ruleForm"
    :rules="rules"
    style="max-width: 600px"
    ref="ruleFormRef"
    status-icon
  >
    <el-form-item label="websocket url" label-position="right" prop="url">
      <el-input v-model="ruleForm.url" />
    </el-form-item>
    <el-form-item label="Token" label-position="right" prop="token">
      <el-input v-model="ruleForm.token" />
    </el-form-item>
    <el-form-item label="UserId" label-position="right" prop="userId">
      <el-input v-model="ruleForm.userId" />
    </el-form-item>
    <el-form-item label="NodeId" label-position="right" prop="nodeId">
      <el-input v-model="ruleForm.nodeId" />
    </el-form-item>
    <el-form-item label="cameraId" label-position="right" prop="cameraId">
      <el-input v-model="ruleForm.cameraId" />
    </el-form-item>
    <el-form-item label="SFU/5g" label-position="right" prop="sfu">
      <el-switch v-model="ruleForm.sfu" />
    </el-form-item>
    <!-- <el-form-item label="视频来源" prop="from">
      <el-radio-group v-model="ruleForm.from">
        <el-radio :value="0">无人机</el-radio>
        <el-radio :value="1">机场</el-radio>
      </el-radio-group>
    </el-form-item> -->
    <el-form-item label="推流方式" prop="pullStreamType">
      <el-radio-group v-model="ruleForm.pullStreamType">
        <el-radio :value="0">P2P</el-radio>
        <el-radio :value="1">服务器推流</el-radio>
      </el-radio-group>
    </el-form-item>
    <el-form-item label="streamType" prop="streamType">
      <el-radio-group v-model="ruleForm.streamType" @change="changeStreamType">
        <el-radio :value="0">主码流</el-radio>
        <el-radio :value="1">辅码流</el-radio>
      </el-radio-group>
    </el-form-item>
    <el-form-item>
      <el-button type="primary" @click="btnClick()">{{connectText}}</el-button>
      <el-button :disabled="ruleForm.sfu" @click="changeStreamType">切换码流（当前：{{streamTypeText}}）</el-button>
    </el-form-item>
  </el-form>
  <VideoComp/>
</template>

<style scoped>
.input-div{
  width: 800px;
  height: 400px;
  font-size: 16px;
}

</style>
