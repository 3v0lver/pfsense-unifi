# -*- coding: utf-8 -*-
import logging
import os.path
FORMAT = "%(asctime)-15s %(levelname)s\n Path: %(pathname)s Function: %(funcName)s  Line# %(lineno)d\n %(message)s"

def initialize_logger(output_dir, log_level):
    _levels={
        'DEBUG':logging.DEBUG,
        'INFO':logging.INFO,
        'WARN':logging.WARN,
        'ERROR':logging.ERROR,
        'FATAL':logging.FATAL,
        }
    level = _levels[log_level]
     
    logger = logging.getLogger()
    logger.setLevel(level)
     
    # create console handler and set level to info
    handler = logging.StreamHandler()
    handler.setLevel(level)
    formatter = logging.Formatter(FORMAT)
    handler.setFormatter(formatter)
    logger.addHandler(handler)
 
    # create error file handler and set level to error
    handler = logging.FileHandler(os.path.join(output_dir, "unifi.log"),"w", encoding=None, delay="true")
    handler.setLevel(logging.ERROR)
    formatter = logging.Formatter(FORMAT)
    handler.setFormatter(formatter)
    logger.addHandler(handler)
 
