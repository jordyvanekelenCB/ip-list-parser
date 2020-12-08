""" Entry point file """

import os
import configparser
import logging
from utilities import Diagnostics
from ip_list_parser import IPListParser

# Setup logger
LOGGER = logging.getLogger()
LOGGER.setLevel(logging.INFO)

# Setup config parser
CONFIG = configparser.ConfigParser()
CONFIG.read(os.path.join(os.path.dirname(__file__), 'config', 'config.ini'))


def lambda_handler(event, context):
    """ Entry point of the application """

    # Activate IP reputation list parser module
    ip_list_parser_results = IPListParser(CONFIG).parse_ip_lists()

    # Send results to diagnostics to print results
    Diagnostics.print_results({'ip_list_parser_results': ip_list_parser_results, 'config': CONFIG})
