# **山东联通 IPTV 机顶盒鉴权流程模拟**

## **设备信息**

- **设备型号**：e900v21c
- **设置界面密码**：6321
- **开启 ADB 调试模式**：
  1. 进入设置界面。
  2. 点击“更多设置”。
  3. 多次点击右键，启用 USB 调试。

## **WRITEUP**

#### 0x0000 抓包分析

openwrt + sshdump 使用 wireshark 抓包，过滤出 http 查看认证流程，找到获取频道信息的 http 请求，curl 模拟几次发现认证所需要的凭据为`jsessionid`字段，要获取节目单只需要这样就可以：

```bash
curl -X GET "http://{ip}:{port}/iptvepg/frame205/action/getchannelprogram.jsp?channelcode={channelcode}&currdate={yyyy.mm.dd} \
-H "Host: {ip}:{port}" \
-H "Connection: keep-alive" \
-H "User-Agent: Mozilla/5.0 (X11; Linux x86_64; SkyworthBrowser) AppleWebKit/534.24 (KHTML, like Gecko) Safari/534.24 SkWebKit-SD-CU" \
-H "Cookie: JSESSIONID={jsessionid}; " 
```

首次获取`jsessionid`是在`POST /iptvepg/platform/auth.jsp`：

```bash
POST /iptvepg/platform/auth.jsp?easip=&ipVersion=&networkid=&serterminalno= HTTP/1.1
Host: 
Connection: keep-alive
Content-Length: 311
Pragma: no-cache
Cache-Control: no-cache
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Origin: 
User-Agent: Mozilla/5.0 (X11; Linux x86_64; SkyworthBrowser) AppleWebKit/534.24 (KHTML, like Gecko) Safari/534.24 SkWebKit-SD-CU
Content-Type: application/x-www-form-urlencoded
Referer: 
Accept-Encoding: gzip,deflate
Accept-Language: zh-cn,en-us,en

UserID=&Authenticator=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx&StbIP=HTTP/1.1 200 OK
Date: 
Content-Type: text/html;charset=GBK
Content-Length: 4243
Connection: keep-alive
Set-Cookie: JSESSIONID=xxxxxxxxxxxxxxxxxxxxxxxxxxxx; Path=/iptvepg; HttpOnly
```

这里提交的时候有个`Authenticator`字段，再找找发现是在`document.authform.Authenticator.value = GetAuthInfo('@@xxxxx');`生成的，

注意到`GetAuthInfo`函数的实参位置在`/iptvepg/platform/getencrypttoken.jsp`得到，正则匹配一下提取出来就好：

```python
def getEncryptToken():
    url = f"http://{eas_ip}:{eas_port}/iptvepg/platform/getencrypttoken.jsp"

    queries = {
        "UserID": userID,
        "Action": "Login",
        "TerminalFlag": "1",
        "TerminalOsType": "0",
        "STBID": "",
        "stbtype": "",
    }

    query_string = "&".join([f"{key}={value}" for key, value in queries.items()])

    full_url = f"{url}?{query_string}"

    response = requests.get(full_url)

    if response.status_code == 200:
        match = re.search(r"GetAuthInfo\('(.*?)'\)", response.text)
        if match:
            encryptToken = match.group(1)
            return encryptToken
        else:
            print("getEncryptToken: 未找到 GetAuthInfo 函数中的值, 请检查网络连接")
    else:
        print(f"getEncryptToken: 请求失败，状态码：{response.status_code}")
```

#### 0x0001 生成 Authentication

接下来找`GetAuthInfo`函数的实现，需要 adb 连上去，直接`adb pull`把所有 apk 都拖出来，使用 jadx 解包出来后一顿搜，最终定位到了 Skiptv.apk 里面的`Authentication.java`文件，大概在这个位置：

```
└── com
    └── skyworth
        └── iptv
            ├── common
            │   └── SkCommon.java
            └── webkitex
                └── Authentication.java
```

`GetAuthInfo`函数实现：

```java
    public String GetAuthInfo(String EncryToken, String CustomStr) {
        Debug("GetAuthInfo, EncryToken:" + EncryToken + ", CustomStr:" + CustomStr);
        Random rnd = new Random(System.currentTimeMillis());
        long random = rnd.nextInt(100000000);
        String username = this.mParams.Username();
        String sn = this.mParams.Sn();
        String ip = this.mParams.Ip();
        String mac = this.mParams.Mac();
        if ((username.equals("") || sn.equals("") || mac.equals("")) && !this.mParams.hasSkParam()) {
            Skiptv.sendMessage(Skiptv.EVENT_SHOW_SETTING);
            return "";
        }
        String strEncry = String.valueOf(random) + "$" + EncryToken;
        String strEncry2 = ((((strEncry + "$" + username) + "$" + sn) + "$" + ip) + "$" + mac) + "$" + CustomStr;
        String password = this.mParams.Password();
        String encryptKey = null;
        if (this.mEncryptType == 2) {
            encryptKey = GetHuaWeiMD5(password, "99991231");
        } else if (this.mEncryptType == 3) {
            encryptKey = GetGDMD5(password);
        }
        if (encryptKey == null) {
            encryptKey = password;
        }
        String strRet = SkCommon.Union3DesEncrypt(strEncry2, encryptKey);
        return strRet;
    }

    @JavascriptInterface
    public String CTCGetAuthInfo(String EncryToken) {
        Debug("CTCGetAuthInfo, EncryToken:" + EncryToken);
        return GetAuthInfo(EncryToken, "$CTC");
    }
```

有了这段就可以构造Authentication的明文了，密文的话还不知道`Union3DesEncrypt`函数加密所需的`password`值，观察一波`Union3DesEncrypt`函数：

```java
    public static String Union3DesEncrypt(String strMsg, String strKey) {
        String ret = "";
        try {
            int keyappend = 24 - strKey.length();
            for (int i = 0; i < keyappend; i++) {
                strKey = strKey + '0';
            }
            DESedeKeySpec ks = new DESedeKeySpec(strKey.getBytes());
            SecretKeyFactory kf = SecretKeyFactory.getInstance("DESede");
            SecretKey ky = kf.generateSecret(ks);
            Cipher c = Cipher.getInstance("DESede");
            c.init(1, ky);
            ret = byte2hex(c.doFinal(strMsg.getBytes()));
        } catch (Exception e) {
            e.printStackTrace();
        }
        Debug("3DES ret:" + ret);
        return ret;
    }
```

`SecretKeyFactory.getInstance("DESede");`使用的是3DES加密。另外注意到：

```java
            int keyappend = 24 - strKey.length();
            for (int i = 0; i < keyappend; i++) {
                strKey = strKey + '0';
            }
```

密钥不够24位，后面用0填充。

函数名作关键字Google一下找到了**IPTV机顶盒的技术规范**，两方对比发现上面的代码是符合规范的，貌似各运营商在iptv这一块的规范是一样的。根据网上的说法密钥是一个**八位的纯数字**，这倒也合理，技术规范要求**使用用户的密码作为3des密钥进行加密**（大概率纯数字）。

那么不妨直接穷举：抓包得到一个正确的Authentication，穷举00000000-99999999的密码进行解密，这样就得到了加密密钥。

或者可以adb进去找，但我没找到。

#### 0x0002 获取节目单

拿到`jsessionid`之后，要获取节目单的话需要双鉴权：

```python
def authEPG(jsessionid):
    url = f"http://{epgIP}:{epgPort}/iptvepg/function/funcportalauth.jsp"

    headers = {"Cookie": f"JSESSIONID={jsessionid}"}

    data = {
        "UserToken": user_token,
        "UserID": userID,
        "STBID": stbID,
        "stbinfo": "",
        "prmid": "",
        "easip": eas_ip,
        "networkid": 1,
        "stbtype": "",
        "drmsupplier": "",
        "stbversion": "",
    }

    response = requests.post(url, headers=headers, data=data)

    if response.status_code == 200:
        return
```

`user_token` 是与 `jsessionid` 一起返回的，详细见代码。

