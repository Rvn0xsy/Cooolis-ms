import requests
from argparse import ArgumentParser
import msgpack
import ssl
import sys
from socketserver import BaseRequestHandler,ThreadingTCPServer

ssl._create_default_https_context = ssl._create_unverified_context

class Cooolis_Server(BaseRequestHandler):
    def handle(self):
        print("Connected from: ", self.client_address)
        while True:
            recvData = self.request.recv(1024)
            if not recvData:
                break
            self.request.sendall(recvData)
        self.request.close()
        print("Disconnected from: ", self.client_address)

class Metasploit_RPC():
    def __init__(self,args,**kwargs):
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
        
    def start(self):
        srv = ThreadingTCPServer(("",self.listen),self)
        srv.serve_forever()

    def _get_token(self):
        options = ["auth.login",self.username,self.password]
        options = self.__pack(options)
        try:
            req  = requests.post(self.url,verify=False,headers=self.headers,data=options)
            result = self.__unpack(req.content)
            if b'error' in result:
                print("Error : %s" % str(result[b'error_message']),encoding = "utf8")
            else:
                self.token = str(result[b'token'],encoding = "utf8")
        except Exception as e:
            sys.stderr.write(str(e)+"\nRef:https://metasploit.help.rapid7.com/docs/standard-api-methods-referenc\n")

    def __pack(self,pack_str):
        return msgpack.packb(pack_str)

    def __unpack(self,pack_str):
        return msgpack.unpackb(pack_str)


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
    msf = Metasploit_RPC(parser)
    msf.start()
    
if __name__ == "__main__":
    main()
    