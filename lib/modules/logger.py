# Why needed this?
# Because redwarden only accepts the class name "logger, " an author defined.

import logging

class logger:
    
    def __init__(self):
        pass

    def dbg(msg):
        logging.debug(msg)

    def warn(msg):
        logging.warning(msg)

    def fatal(msg):
        logging.fatal(msg)

    def err(msg):
        logging.error(msg)