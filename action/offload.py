'''
determine how to offload NAT to switch, basically defines the offload API
'''
import time
import logging
import os
import uuid
import fcntl
import config
from rpc import client


def offload_alarm():
    FILE = "offload.txt"
    offloadbuf = []
    data = []
    while True:
        #  time.sleep(config.offload_period)
        # sent message to switch only if there are some message await
        offloadbuf.clear()
        data.clear()
        if os.path.getsize(FILE)!=0:
            file = open(FILE, "r+")
            while True:
                try:
                    fcntl.flock(file.fileno(),fcntl.LOCK_EX|fcntl.LOCK_NB)
                except IOError:
                    print("Error")
                else:
                    print("seccussful")
                    data = file.readlines()
                    file.seek(0)
                    file.truncate()
                    file.close()
                    for i in range(0,int(len(data)/5)):
                        data[i*5] = data[i*5].strip('\n')
                        data[i*5+1] = int(data[i*5+1])
                        data[i*5+2] = data[i*5+2].strip('\n')
                        data[i*5+3] = int(data[i*5+3])
                        data[i*5+4] = int(data[i*5+4])
                        offloadbuf.append((data[i*5],data[i*5+1],data[i*5+2],data[i*5+3],data[i*5+4]))
                    config.serverlock.acquire()
                    recv_responses = client.offload(offloadbuf)
                    config.serverlock.release()
                    if not recv_responses:
                        logging.info("Switch failed to offload NAT ")
                    break
        time.sleep(0.5)

def delete_alarm():
    FILE = "delete.txt"
    deletebuf = []
    while True:
        #  time.sleep(config.offload_period)
        # sent message to switch only if there are some message await
        deletebuf.clear()
        if os.path.getsize(FILE)!=0:
            file = open(FILE, "r+")
            while True:
                try:
                    fcntl.flock(file.fileno(),fcntl.LOCK_EX|fcntl.LOCK_NB)
                except IOError:
                    print("Error")
                else:
                    print("seccussful")
                    deletebuf = file.readlines()
                    file.seek(0)
                    file.truncate()
                    file.close()
                    for i in range(0,int(len(deletebuf))):
                        deletebuf[i] = int(deletebuf[i])
                    config.serverlock.acquire()
                    recv_responses = client.deletetable(deletebuf)
                    config.serverlock.release()
                    if not recv_responses:
                        logging.info("Switch failed to delete NAT ")
                    break
        time.sleep(0.5)
        
