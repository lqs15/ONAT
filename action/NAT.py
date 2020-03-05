import threading
from scapy.all import *
import logging
import netaddr
import sys
import random as rd
from . import offload
from . import retrieve

import config

iface = "eth0"
threshold= 3


def init(args):
    global iface, threshold
    
    iface = args.iface
    
def start():
    
    retrieve_thread = threading.Thread(target=retrieve.retrieve_alarm)
    retrieve_thread.start()

    

    offload_thread = threading.Thread(target=offload.offload_alarm)
    offload_thread.start()

    delete_thread = threading.Thread(target=offload.delete_alarm)
    delete_thread.start()
