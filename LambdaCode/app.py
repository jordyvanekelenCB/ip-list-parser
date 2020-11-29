""" Entry point file """

import os
import configparser
import logging

# Setup logger
LOGGER = logging.getLogger()
LOGGER.setLevel(logging.INFO)

# Setup config parser
CONFIG = configparser.ConfigParser()
CONFIG.read(os.path.join(os.path.dirname(__file__), 'config', 'config.ini'))

from ip_list_parser import IPListParser

def lambda_handler(event, context):
    """ Entry point of the application """

    # Activate IP reputation list parser module
    IPListParser(CONFIG).parse_ip_lists()

    # TODO print output
