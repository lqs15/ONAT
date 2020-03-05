''
response for every actual RPC interaction with switch
'''
from xmlrpc.client import ServerProxy

import config

server = ServerProxy("http://10.19.0.83:22222", allow_none = True)

def init(args):
    global server
    # server = ServerProxy(args.server_addr, allow_none = True)
    server = ServerProxy("http://10.19.0.83:22222", allow_none = True)
    print("successful connected")
    print(server.getCounter([0,1,2,3]))

def offload(buf:list):
    print("offload flows")
    return server.addEntry(buf)

def retrieve(indices:list):
    return server.getCounter(indices)

def deletetable(deletebuf:list):
    print("delete flows")
    return server.delEntry(deletebuf)
