'''
determine how to retrieve NAT from switch, and also update local NAT mapping
'''

import time
import threading
import logging
import os
import fcntl
import uuid
import config

from rpc import client

'''
Usage:
    wrapper of retriever, which wake up the offloader with given period of time
Input:
    mapping: mutable, NAT mapping
    offloaded_flow: mutable, NAT flow hash values (int) which had been offloaded
                    you have to clean up those flow value retrieved back
    pre_offload_flow: sum of flow hash values await in buffer (not being send yet) and already be send
                      you have to clean up those flow value retrieved back
'''
def retrieve_alarm():
    # thread-scope variable
    # YOU SHOULD ALSO MAINTAIN A REVERSE MAPPING FROM INDEX TO FLOW HASH
    # IN ORDER TO UPDATE LOCAL NAT MAPPING
    # e.g. candidate_flow is a dict, with key = flow index, value = flow hash
    FILE1 = "retrieve.txt"
    FILE2 = "response_retrieve.txt"
    data = []
    recv_responses = []
    while True:
        data.clear()
        recv_responses.clear()
        if os.path.getsize(FILE1)!=0:
            file = open(FILE1, "r+")
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
                    for i in range(0,len(data)):
                        data[i] = int(data[i])
                    config.serverlock.acquire()
                    recv_responses = client.retrieve(data)
                    config.serverlock.release()
                    break
            while True:
                if os.path.getsize(FILE2)==0:
                    file = open(FILE2, "w")
                    while True:
                        try:
                            fcntl.flock(file.fileno(),fcntl.LOCK_EX|fcntl.LOCK_NB)
                        except IOError:
                            print("Error")
                        else:
                            for i in range(0,len(recv_responses)):
                                file.write(str(recv_responses[i]))
                                file.write("\n")
                            file.close()
                            break
                    break
