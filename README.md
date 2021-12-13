# Cooolis-ms

[Wiki说明](https://github.com/Rvn0xsy/Cooolis-ms/wiki)

--------

![README](./Pic/view-1.png)


`Cooolis-ms`是一个包含了Metasploit Payload Loader、Cobalt Strike External C2 Loader、Reflective DLL injection的代码执行工具，它的定位在于能够在静态查杀上规避一些我们将要执行且含有特征的代码，帮助红队人员更方便快捷的从Web容器环境切换到C2环境进一步进行工作。

### 如何下载它？

- 你可以从Github直接克隆仓库获取源代码：`git clone https://github.com/Rvn0xsy/Cooolis-ms`
- 你还可以通过[Release](https://github.com/Rvn0xsy/Cooolis-ms/releases)页面下载最新编译版本

### 基本说明

1. `Cooolis-ms`是参考了[Metasploit API 文档](https://docs.rapid7.com/metasploit/standard-api-methods-reference/)实现了RPC服务客户端的功能，使得`Cooolis-ms`的服务端能够发送任意载荷，让`Cooolis-ms`的灵活性得以提高。
2. `Cooolis-ms`是借鉴了[MemoryModule](https://github.com/fancycode/MemoryModule)实现了PE的加载，让`Cooolis-ms`的执行特征得以减少，查杀几率降低。
3. `Cooolis-ms`是借鉴了[ReflectiveDLLInjection](https://github.com/stephenfewer/ReflectiveDLLInjection)实现了反射DLL的加载执行和注入，让`Cooolis-ms`的执行特征得以减少，查杀几率降低。
4. `Cooolis-ms`是参考了[External C2 (Third-party Command and Control)](https://cobaltstrike.com/help-externalc2)实现了基本的External C2执行，让`Cooolis-ms`的执行特征得以减少，查杀几率降低。
5. `Cooolis-ms`还考虑到通过Aliyun OSS服务器上的文件作为执行代码，自动加载至内存运行，让`Cooolis-ms`的灵活性得以提高。

### 使用方法

目前`Cooolis-ms`拥有以下几个子命令：

```
[~\Documents\Cooolis-ms\Cooolis-ms-Loader\Release]> .\Cooolis-ms.exe -h
Version v1.2.6
Usage: C:\Users\Administrator\Documents\Cooolis-ms\Cooolis-ms-Loader\Release\Cooolis-ms.exe [OPTIONS] SUBCOMMAND

Options:
  -h,--help                   Print this help message and exit

Subcommands:
  metasploit                  Metasploit RPC Loader
  cobaltstrike                Cobalt Strike External C2 Loader
  reflective                  Reflective DLL injection
  shellcode                   Shellcode Loader
```

通过在子命令后添加`-h/--help`获取子命令对应的详细参数：

```
[~\Documents\Cooolis-ms\Cooolis-ms-Loader\Release]> .\Cooolis-ms.exe metasploit -h
Metasploit RPC Loader
Usage: C:\Users\Administrator\Documents\Cooolis-ms\Cooolis-ms-Loader\Release\Cooolis-ms.exe metasploit [OPTIONS]

Options:
  -h,--help                   Print this help message and exit
  -p,--payload TEXT=windows/meterpreter/reverse_tcp
                              Payload Name, e.g. windows/meterpreter/reverse_tcp
  -o,--options TEXT           Payload options, e.g. LHOST=1.1.1.1,LPORT=8866
  -P,--PORT UINT:INT in [1 - 65535]=8899 REQUIRED
                              RPC Server Port
  -H,--HOST TEXT:IPV4 REQUIRED
                              RPC Server Host
```

### 子命令使用详解

- [metasploit](https://github.com/Rvn0xsy/Cooolis-ms/wiki/module-metasploit)
- [cobaltstrike](https://github.com/Rvn0xsy/Cooolis-ms/wiki/module-cobaltstrike)
- [reflective](https://github.com/Rvn0xsy/Cooolis-ms/wiki/module-reflective)
- [shellcode](https://github.com/Rvn0xsy/Cooolis-ms/wiki/module-shellcode)


### 学习与扩展

你可以参考这里，写出自己的好项目

- [静态恶意代码逃逸（第一课）](https://payloads.online/archivers/2019-11-10/1)
- [静态恶意代码逃逸（第二课）](https://payloads.online/archivers/2019-11-10/2)
- [静态恶意代码逃逸（第三课）](https://payloads.online/archivers/2019-11-10/3)
- [静态恶意代码逃逸（第四课）](https://payloads.online/archivers/2019-11-10/4)
- [静态恶意代码逃逸（第五课）](https://payloads.online/archivers/2019-11-10/5)
- [静态恶意代码逃逸（第六课）](https://payloads.online/archivers/2020-01-02/1)
- [静态恶意代码逃逸（第七课）](https://payloads.online/archivers/2020-10-23/1)
- [静态恶意代码逃逸（第八课）](https://payloads.online/archivers/2020-11-29/1)
- [静态恶意代码逃逸（第九课）](https://payloads.online/archivers/2020-11-29/2)


## 关于其他

如果你觉得这个项目不错，请给我一个Star～


## issue

[我要提交建议或问题](https://github.com/Rvn0xsy/Cooolis-ms/issues)

## LICENSE

[GNU General Public License v3.0](https://github.com/Rvn0xsy/Cooolis-ms/blob/master/LICENSE)

