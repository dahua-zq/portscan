# TCP端口扫描

[TOC]



## 一、常见的TCP扫描类型有：

<u>TCP connect扫描</u>

全连接扫描，此扫描与每个TCP端口进行3次握手通信。成功建立连接，则证明端口开放，否则为关闭。准确度很高，但是容易被防火墙和IDS检测到，并且在目标主机日志会有记录。

 <u>TCP SYN扫描</u>

端口开放：client发送SYN，server端回复SYN/ACK，client发送RST断开

端口关闭：client发送SYN，server端回复RST

<u>秘密扫描</u>

秘密扫描是一种不被审计工具所检测的扫描技术。它通常用于在通过普通的防火墙或路由器的筛选时隐藏自己。秘密扫描能躲避IDS、防火墙、包过滤器和日志审计，从而获取目标端口的开放或关闭的信息。由于没有包含TCP3次协议的任何部分，所以无法被记录下来，比半连接扫描更为隐藏。但是这种扫描的缺点是扫描结果的不可靠性会增加，而且扫描主机也需要自己构造IP包。

<u>TCP FIN扫描</u>

端口开放：client发送FIN，server没有响应

端口关闭：client发送FIN，server回复RST

<u>TCP ACK扫描</u>

端口开放：client发送ACK，server回复RST数据包TTL<=64

端口关闭：client发送ACK，server回得RST数据包TTL>64

 <u>NULL扫描</u>

端口开放：client发送NULL，server没有响应

端口关闭：client发送NULL，server回复RST

 <u>TCP XMAS扫描</u>

端口开放：client发送USG/PSH/FIN，server没有响应

端口关闭：client发送USG/PSH/FIN，server回复RST

## 二、本文采用的为TCP connect（）扫描

### 1.TCP connect()扫描原理是：

扫描主机通过TCP/IP协议的三次握手与目标主机的指定端口建立一次完整的连接。连接由系统调用connect开始。如果端口开放，则连接将建立成功；否则，若返回-1则表示端口关闭。

### 2.设计一个程序做到：

​	（1）输入目的IP地址以及端口范围；
​    （2）设置获取的用户输入IP地址为远程IP地址；
​    （3）从开始端口到结束端口依次扫描，每扫描一个端口创建一个新的套接字；
​    （4）设置远程地址信息中的端口号为需要扫描的当前端口号；
​    （5）连接到当前端口号的目的地址；
​    （6）若连接成功（ connect（）函数返回0 ）则输出该端口为开启状态，否则输出该端口为关闭状态；
​    （7）关闭当前套接字。进阶1，采用半连接提高扫描效率。进阶2，使用多进程进行端口扫描，进一步提高效率。

## 三、函数说明

- [x] '''连接指定地址及指定端口，建立连接发送信息，以确定端口是否开放'''

```python
def Connect(host, port):
    Socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM) #建立套接字
    Socket.settimeout(1) #设置超时时间
    try:
        Socket.connect((host, port)) #连接目的地址和端口
        lock.acquire()
    except socket.timeout:
        pass
        # print("[-1]%d port is close" % port)  # 若连接超时，则端口关闭
    else:
        print("[0]%d port is open" % port)  # 若可以连接，则端口打开
        lock.release()
        Socket.close()
```



- [x] ''' 得到目的地址'''

```python
def Check_host(host):
    try:
        host = socket.gethostbyname(host)
        print("\n[**]The scan results for " + host + " is:")
        return(host)
    except:
        print(parser.usage)
        exit(0)
```



- [x] '''得到目的端口号'''

```python
def Check_port(port):
    try:
        pattern = re.compile(r'(\d+)-(\d+)')
        match = pattern.match(port) # 使用Pattern匹配文本，获得匹配结果，无法匹配时将返回None
        if match:
            startport = int(match.group(1))
            endport = int(match.group(2))
            return ([p for p in range(startport, endport + 1)])
        else:
            return ([int(p) for p in port.split(',')])
    except:
        print(parser.usage)
        exit(0)
```

## 四、实验结果

### 1.扫描本机（127.0.0.1）

```
D:\大三下学期\网络攻防\code>python portscan.py -H 127.0.0.1 -P 1-63335

[**]The scan results for 127.0.0.1 is:

[0]135 port is open
[0]443 port is open
[0]445 port is open
[0]902 port is open
[0]912 port is open
[0]4301 port is open
[0]5040 port is open
[0]6942 port is open
[0]7936 port is open
[0]8082 port is open
[0]8307 port is open
[0]10000 port is open
[0]21214 port is open
[0]21440 port is open
[0]21441 port is open
[0]23361 port is open
[0]34579 port is open
[0]48103 port is open
[0]49666 port is open
[0]49667 port is open
[0]49665 port is open
[0]49668 port is open
[0]49670 port is open
[0]49675 port is open
[0]50107 port is open
[0]54530 port is open
[0]61502 port is open
```



### 2.扫描百度（www.baidu.com）

```
D:\大三下学期\网络攻防\code>python portscan.py -H www.baidu.com -P 80,443

[**]The scan results for 39.156.66.14 is:
[0]80 port is open
[0]443 port is open
```

