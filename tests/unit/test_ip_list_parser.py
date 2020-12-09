""" Unit test containing tests for IP list parser class """

import sys
import os
import inspect
import configparser
import random
import struct
import socket
# pylint: disable=E0401
import pytest

# Fix module import form parent directory error.
# Reference: https://stackoverflow.com/questions/55933630/
# python-import-statement-modulenotfounderror-when-running-tests-and-referencing
CURRENT_DIR = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
PROJECT_ROOT = os.path.dirname(CURRENT_DIR)
PROJECT_ROOT_SRC = "%s/LambdaCode" % os.path.dirname(PROJECT_ROOT)

# Set up configuration path
CONFIG_PATH = os.path.join(os.path.dirname(PROJECT_ROOT_SRC + "/LambdaCode"), 'config', 'config.ini')

# Set up sys path
sys.path.insert(0, PROJECT_ROOT_SRC)

# Import project classes
# pylint: disable=C0413
from ip_list_parser import IPListParser

@pytest.fixture()
def setup_config():
    """ Fixture for setting up configuration parser """

    config = configparser.ConfigParser()
    config.read(CONFIG_PATH)

    return config

# pylint: disable=W0621
# pylint: disable=R0914
def test_compile_lists(setup_config):
    """ This method tests the filter_block_list_queue method """

    # !ARRANGE!
    ip_list_parser = IPListParser(setup_config)

    list_1 = []
    list_2 = []

    # pylint: disable=W0612
    # Add 400 addresses containing 4 unique IP addresses
    for i in range(0, 100):
        list_1.append('1.1.1.1')
        list_1.append('2.2.2.2')
        list_1.append('3.3.3.3')
        list_1.append('4.4.4.4')

    # Add 9997 randomly generated IP addresses
    for i in range(0, 9997):
        list_2.append(socket.inet_ntoa(struct.pack('>I', random.randint(1, 0xffffffff))))

    # Merge the lists
    master_list = [list_1, list_2]

    # !ACT!

    # Call compile_lists
    master_ip_list = ip_list_parser.compile_lists(master_list)

    # !ASSERT!

    # Assert the length of the list is equal to or lower than 10000 because of the AWS WAF threshold
    assert len(master_ip_list) <= 10000

    # Assert the correct IP addresses are in the list
    assert '1.1.1.1' in master_ip_list
    assert '2.2.2.2' in master_ip_list
    assert '3.3.3.3' in master_ip_list
    assert '4.4.4.4' in master_ip_list

    # Assert the count of the entries is one
    assert master_ip_list.count('1.1.1.1') == 1
    assert master_ip_list.count('2.2.2.2') == 1
    assert master_ip_list.count('3.3.3.3') == 1
    assert master_ip_list.count('4.4.4.4') == 1
