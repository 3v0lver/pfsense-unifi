# -*- coding: utf-8 -*-
from loggerinitializer import *
import sys
import argparse
import logging.handlers
import time
import unifi.unifi_usg_pro
import unifi.utils
import unifi.pfsense_utils
CONFIG_FILE = 'conf/unifi-gateway.conf.json'


class UnifiConsole():

    def __init__(self, **kwargs):
        self.device = unifi.unifi_usg_pro.UnifiUSGPro(kwargs['config'])

    def run(self):
        while True:
            if (int(time.time()*1000)-self.device.delayStart)>=self.device.interval :
                self.device.delayStart = int(round(time.time()*1000))
                self.device.reload_config()
                logging.debug("new loop")
                self.device.sendinfo()
            time.sleep(0.1)
  

def processargs(args):

    initialize_logger('logs',args.loglevel)
    global console
    console = UnifiConsole(config=args.config)

def restart(args):
    processargs(args)
    console.restart()


def run(args):
    processargs(args)
    console.run()

def set_adopt(args):
    processargs(args)
    url, key = args.s, args.k
    console.set_adopt(url, key)


if __name__ == '__main__':
    abspath = os.path.abspath(__file__)
    dname = os.path.dirname(abspath)
    os.chdir(dname)
    unifi.pfsense_utils.getGatewaysPingerStatus()
    
    parser = argparse.ArgumentParser()

    parser.add_argument('--loglevel', default='WARN', const='WARN', nargs='?', choices=['DEBUG', 'INFO', 'WARN','ERROR','FATAL'] )
    parser.add_argument('--config', type=str, help='key',default=CONFIG_FILE )
    parser.set_defaults(func=processargs)
    subparsers = parser.add_subparsers()

    parser_adopt = subparsers.add_parser('run', help='start regular flow')
    parser_adopt.set_defaults(func=run)

    parser_adopt = subparsers.add_parser('set-adopt', help='send the adoption request to the controller')
    parser_adopt.add_argument('-s', type=str, help='controller url', required=True)
    parser_adopt.add_argument('-k', type=str, help='key', required=True)
    parser_adopt.set_defaults(func=set_adopt)
    args = parser.parse_args()

    args.func(args)
    
