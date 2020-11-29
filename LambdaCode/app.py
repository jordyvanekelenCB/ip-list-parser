import os
import configparser
import logging
from connection.aws_wafv2_connection import AWSWAFv2

# Setup logger
LOGGER = logging.getLogger()
LOGGER.setLevel(logging.INFO)

# Setup config parser
CONFIG = configparser.ConfigParser()
CONFIG.read(os.path.join(os.path.dirname(__file__), 'config', 'config.ini'))

from connection import HTTPGet
from ip_list_parser import IPListParser

def lambda_handler(event, context):


    ip_list_parser = IPListParser(CONFIG)
    ip_list_parser.parse_ip_lists()


    # list = []
    # import random
    # import struct
    # import socket
    #
    # for c in range(0, 1001):
    #     ip = socket.inet_ntoa(struct.pack('>I', random.randint(1, 0xffffffff)))
    #     list.append(ip + '/32')
    #
    # LOGGER.info(len(list))
    #
    # AWSWAFv2(CONFIG).update_ip_set([])


    # Create IP List parser object

    # Fetch IP lists, TODO: One class handle all, regex from https://github.com/awslabs/aws-waf-security-automations/blob/master/source/reputation_lists_parser/reputation-lists.py

    # parse all lists, cross check maybe?

    # Waf update with lists (get token there)



    pass
