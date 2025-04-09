import requests
import re
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad
import binascii
import random


##########################

eas_ip = ""
eas_port = ""

epgIP = ""
epgPort = ""

userID = ""
stbID = ""

ip = ""
MAC = "" ## 字母大写，要包含:符号
encryptKey = "" ##八位纯数字，穷举获得

##########################

CustomStr = "$CTC"


# def Entrance():
#     url = f"http://{eas_ip}:{eas_port}/iptvepg/platform/index.jsp?UserID={userID}&Action=Login&Mode=MENU"
#     response = requests.get(url)
#     if response.status_code == 200:
#         return
#     else:
#         print(f"Entrance: 请求失败，状态码：{response.status_code}")


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


def generateAuthenticator():
    try:
        random_number = random.randint(10000000, 99999999)
        strEncry = str(random_number) + "$" + encryptToken
        strEncry2 = (
            strEncry
            + "$"
            + userID
            + "$"
            + stbID
            + "$"
            + ip
            + "$"
            + MAC
            + "$"
            + CustomStr
        )
        res = UnionDesEncrypt(strEncry2, encryptKey)
        return res

    except Exception as e:
        print(f"generateAuthenticator: {e}")


def auth(Authenticator):
    user_token = ""
    url = f"http://{epgIP}:{epgPort}/iptvepg/platform/auth.jsp?easip={eas_ip}&ipVersion=4&networkid=1&serterminalno=311"

    data = {"UserID": userID, "Authenticator": Authenticator, "StbIP": ip}

    response = requests.post(url, data=data)

    cookies = response.cookies
    jsessionid = cookies.get("JSESSIONID")

    url_pattern = r"window\.location\s*=\s*'(http[^']+)'"
    match = re.search(url_pattern, response.content.decode("gbk"))

    if match:
        extracted_url = match.group(1)

        response = requests.post(
            extracted_url, headers={"Cookie": f"JSESSIONID={jsessionid}"}
        )
        if response.status_code == 200:
            pattern = r"UserToken=([A-Za-z0-9_\-\.]+)"
            match = re.search(pattern, extracted_url)

            if match:
                user_token = match.group(1)
    else:
        print("auth: 鉴权链接获取失败.")

    return jsessionid, user_token


def epgAuth(jsessionid):
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


def UnionDesEncrypt(strMsg, strKey):
    try:
        keyappend = 8 - len(strKey)
        if keyappend > 0:
            strKey = strKey + "0" * keyappend

        key_bytes = strKey.encode("utf-8")
        msg_bytes = strMsg.encode("utf-8")

        padded_msg = pad(msg_bytes, DES.block_size)

        cipher = DES.new(key_bytes, DES.MODE_ECB)
        encrypted = cipher.encrypt(padded_msg)

        return binascii.hexlify(encrypted).decode("utf-8").upper()

    except Exception as e:
        print(f"UnionDesEncrypt: {e}")


encryptToken = getEncryptToken()

Authenticator = generateAuthenticator()

jsessionid, user_token = auth(Authenticator)

epgAuth(jsessionid)

print(f"jsessionid: {jsessionid}")
print(f"user_token: {user_token}")
