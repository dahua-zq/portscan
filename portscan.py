import socket
import re
import optparse #处理命令行参数
import threading #线程模块

lock = threading.Lock()

'''连接指定地址及指定端口，建立连接发送信息，以确定端口是否开放'''
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


''' 得到目的地址'''
def Check_host(host):
    try:
        host = socket.gethostbyname(host)
        print("\n[**]The scan results for " + host + " is:")
        return(host)
    except:
        print(parser.usage)
        exit(0)

'''得到目的端口号'''
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

def Scan():
    parser = optparse.OptionParser('usage:%prog -h <目的IP> -p <目的端口>')
    parser.add_option('-H', dest='host', type='string',help='please input host address:')
    parser.add_option('-P', dest='port', type='string',help='please input port number:')
    (options, args) = parser.parse_args()
    if options.host == None or options.port == None:
        print(parser.usage)
        exit(0)
    else:
        host = options.host
        port = options.port

    host = Check_host(host)
    port = Check_port(port)

    for port in port:
        t = threading.Thread(target=Connect, args=(host, port))  # 多线程扫描端口
        t.start()

Scan()