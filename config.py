'''
storing global configuration (while should be const) shared 
between different modules
'''
import logging
import threading
def init(args):
    global pseudo_eip, pseudo_eport
    global switch_slot
  
    global serverlock
    serverlock = threading.Lock()
    switch_slot = args.switch_slot
    # set logger triviality level
    if args.debug:
	    logging.basicConfig(level=logging.DEBUG)
    else:
	    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)

    # constants
    pseudo_eip = "41.177.0.1"
    pseudo_eport = 7676
