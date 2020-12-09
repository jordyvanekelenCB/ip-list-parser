""" Unit test for ALB Log parser class """

import os
import sys
import inspect
import time
# pylint: disable=E0401
import pytest

# Fix module import form parent directory error.
# Reference: https://stackoverflow.com/questions/55933630/
# python-import-statement-modulenotfounderror-when-running-tests-and-referencing
CURRENT_DIR = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
PROJECT_ROOT = os.path.dirname(CURRENT_DIR)
PROJECT_ROOT_SRC = "%s/LambdaCode" % os.path.dirname(PROJECT_ROOT)

# Set up sys path
sys.path.insert(0, PROJECT_ROOT_SRC)

# Import project classes
# pylint: disable=C0413
# pylint: disable=W0621
from LambdaCode import app
from LambdaCode.ip_list_parser import IPListParser
from LambdaCode.connection.aws_wafv2_connection import AWSWAFv2Connection

@pytest.fixture
def get_mock_config():
    """ Return the mocked config parser with arbitrary values of the components to be tested """

    # Create HTTP Flood config section
    config_section_ip_list_parser = {
        'MALWARE_IP_LIST_PROVIDERS':
            'https://rules.emergingthreats.net/blockrules/compromised-ips.txt,'
            'http://feodotracker.abuse.ch/downloads/ipblocklist.csv,'
            'https://sslbl.abuse.ch/blacklist/sslipblacklist_aggressive.csv,'
            'https://www.binarydefense.com/banlist.txt,'
            'http://cinsscore.com/list/ci-badguys.txt,'
            'https://iplists.firehol.org/files/xforce_bccs.ipset,'
            'https://www.urlvir.com/,'
            'http://vxvault.net/ViriList.php?s=0&m=100'
        ,
        'ATTACKERS_IP_LIST_PROVIDERS':
            'https://www.spamhaus.org/drop/drop.txt,'
            'https://www.spamhaus.org/drop/edrop.txt,'
            'https://isc.sans.edu/api/sources/attacks/1000/30?text,'
            'http://lists.blocklist.de/lists/all.txt,'
            'https://blocklist.greensnow.co/greensnow.txt'
            'https://www.myip.ms/files/blacklist/general/latest_blacklist.txt,'
            'https://reputation.alienvault.com/reputation.generic,'
            'https://iplists.firehol.org/files/normshield_all_attack.ipset'
    }

    # Create AWS WAF Config section
    config_section_aws_waf = {
        'IP_SET_REPUTATION_SCOPE': 'REGIONAL',
        'IP_SET_REPUTATION_ATTACKERS_BLOCKED_NAME': 'ip_set_reputation_attackers_blocked_test',
        'IP_SET_REPUTATION_MALWARE_BLOCKED_NAME': 'ip_set_reputation_malware_blocked_test'
    }

    # Mock Config parser
    mock_config = {
        'IP_LIST_PARSER': config_section_ip_list_parser,
        'AWS_WAF': config_section_aws_waf,
    }

    return mock_config


@pytest.fixture(autouse=True)
def cleanup_wafv2(get_mock_config):
    """ Cleans up WAFv2 IP set before each system test """

    # Update malware IP set with empty list
    AWSWAFv2Connection(get_mock_config, IPListParser.IPReputationListType.ip_reputation_list_type_malware)\
        .update_ip_set([])

    # Update attacker IP set with empty list
    AWSWAFv2Connection(get_mock_config, IPListParser.IPReputationListType.ip_reputation_list_type_attackers) \
        .update_ip_set([])


# pylint: disable=R0914
def test_system(get_mock_config):
    """ Run integration test to make sure all AWS components are working together accordingly. """

    # !ARRANGE!
    app.CONFIG = get_mock_config

    # !ACT!

    start_time = time.time()  # Record starting time
    app.lambda_handler(None, None)  # Execute entry point

    # !ASSERT!

    # Check if IP SET 'ip_set_reputation_attackers_blocked_test' contains plausible entries
    wafv2_ip_set_reputation_attackers_blocked_test_response = AWSWAFv2Connection\
        (get_mock_config, IPListParser.IPReputationListType.ip_reputation_list_type_attackers).retrieve_ip_set()

    wafv2_ip_set_reputation_malware_blocked_test_response = AWSWAFv2Connection \
        (get_mock_config, IPListParser.IPReputationListType.ip_reputation_list_type_malware).retrieve_ip_set()

    ip_set_reputation_attackers_blocked_test = wafv2_ip_set_reputation_attackers_blocked_test_response["IPSet"]["Addresses"]
    ip_set_reputation_malware_blocked_test = wafv2_ip_set_reputation_malware_blocked_test_response["IPSet"]["Addresses"]

    # Assert IP sets contain minimum entries
    assert len(ip_set_reputation_malware_blocked_test) > 300
    assert len(ip_set_reputation_attackers_blocked_test) > 1000

    # Assert system test was completed within allotted timeframe (performance)
    total_duration_in_ms = ((time.time() - start_time) * 1000)
    assert total_duration_in_ms < 20000
