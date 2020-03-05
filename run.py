from argparse import ArgumentParser
import os
import config
from action import NAT
from rpc import client

'''
Usage:
    Help transfrom string to bool
    Most used in parsing user config input
'''
def str2bool(v):
    if isinstance(v, bool):
       return v
    if v.lower() in ('yes', 'true', 't', 'y', '1'):
        return True
    elif v.lower() in ('no', 'false', 'f', 'n', '0'):
        return False
    else:
        raise argparse.ArgumentTypeError('Boolean value expected.')

if __name__ == "__main__":
    # read user's configuration, and store it into config.py
    parser = ArgumentParser()
    parser.add_argument("-i", "--interface", help="Network interface you are going to used to catpure packet", dest="iface", default="wlp3s0")
    parser.add_argument("-d", "--debug", help="Print detailed debug messages", type=str2bool, nargs='?', const=True, default=False, dest="debug")
    parser.add_argument("-ss", "--switch-slot", help="Number of NAT rule the switch can afford", type=int, dest="switch_slot", default=65536)

    
    args = parser.parse_args()

    config.init(args)
    client.init(args)
    file = open("offload.txt","w+")
    file.close()
    file = open("delete.txt","w+")
    file.close()
    file = open("retrieve.txt","w+")
    file.close()
    file = open("response_retrieve.txt","w+")
    file.close()

    NAT.init(args)
    
    NAT.start()
