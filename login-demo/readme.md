## 说明文档 
    直接网页运行html，输入用户名和密码即可完成登录
    目前支持html+js访问，如需其他引入方式可自行下载依赖库
### index.html
    baseUrl：
    http://dev.godouav.com/api//为测试环境地址
    https://drone.godouav.com/api//为生产地址 
 <br>登录所需用户名和密码为平台真实用户
### 登录请求路径
    /sso/login
### 登录参数说明
    - APP_ID
    - SIGN_SECRET
    - publicKey 
    上面三个参数由高度颁发,下边为真实用户
    - account 用户名
    - password 密码
    - baseUrl 根请求路径

 
