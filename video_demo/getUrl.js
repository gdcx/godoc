let testUrl='http://192.168.142.101:9091/gdcxvideo/record/1625428017968975872868399283/1625428017968975872868399283_1730364449.mp4?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=admin%2F20241101%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20241101T031346Z&X-Amz-Expires=86400&X-Amz-SignedHeaders=host&X-Amz-Signature=3491d550515b0004ae215ca1e3b70c3d444d45dfa50129867ad9840646008e79'
let testUrl1 = 'http://192.168.142.101:9091/gdcxvideo/screenshot/1544592785276014001/20241031/GDCXM190012302100314-20241031-82/20241031165604f78baa18bc2548799033786368e8b261.jpg'
let ip = 'http://113.108.32.190:9091'
//判断返回的路径是否属于ali
export function getVideoRealUrl(proxyUrl) {
    if (proxyUrl.indexOf('aliyuncs.com')>-1) {//公网
        return proxyUrl
    } else {//私有化
        if (!proxyUrl) {
            return ''
        }
        let arrUrl=proxyUrl.split("//")
        var start=arrUrl[1].indexOf('/')
        let relUrl=arrUrl[1].substring(start+1)
        if (relUrl.indexOf("?")>-1) {
            relUrl=relUrl.split('?')[0]
        }
        console.log('11', relUrl)
        let url=ip+"/"+relUrl
        return url
    }
}
let acuUrl= getVideoRealUrl(testUrl)
console.log('最后', acuUrl)