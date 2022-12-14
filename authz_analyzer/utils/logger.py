import logging
import sys


def get_logger(debug: bool):
    logger = logging.getLogger('authz-analyzer')
    level = logging.INFO if not debug else logging.DEBUG
    logger.setLevel(level)

    if logger.handlers:
       return logger
    
    ch = logging.StreamHandler()
    ch.setLevel(level)
    formatter = logging.Formatter('%(asctime)s - %(filename)s:%(lineno)d - %(levelname)s - %(message)s')
    ch.setFormatter(formatter)
    logger.addHandler(ch)
    return logger
