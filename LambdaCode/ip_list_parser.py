""" This file contains the IPListParser class """

import logging
from connection import HTTPGet
from utilities import IPParser
from connection import AWSWAFv2Connection
from enum import Enum

# Setup logger
LOGGER = logging.getLogger()
LOGGER.setLevel(logging.INFO)


class IPListParser:
    """ This class is responsible for the IPListParser component logic. It gathers IP lists from different sources and
        compiles them into a single list to update the WAF IP set with.
     """

    config_section_ip_list_parser = 'IP_LIST_PARSER'

    def __init__(self, config):
        self.config = config

    def parse_ip_lists(self):
        """ Entry point """

        # Get and compile malware lists from malware ip block list providers
        malware_lists = self.get_lists('MALWARE_IP_LIST_PROVIDERS')
        malware_ip_list_compiled = self.compile_lists(malware_lists)

        # Get and compile attacker lists from attacker ip block list providers
        attacker_lists = self.get_lists('ATTACKERS_IP_LIST_PROVIDERS')
        attacker_ip_list_compiled = self.compile_lists(attacker_lists)

        # Update IP set with malware list
        AWSWAFv2Connection(self.config, self.IPReputationListType.ip_reputation_list_type_malware)\
            .update_ip_set(malware_ip_list_compiled)

        # Update IP set with attackers list
        AWSWAFv2Connection(self.config, self.IPReputationListType.ip_reputation_list_type_attackers) \
            .update_ip_set(attacker_ip_list_compiled)

        return {'malware_ip_list_compiled':  malware_ip_list_compiled, 'attacker_ip_list_compiled': attacker_ip_list_compiled}

    def get_lists(self, key):
        """ Get the lists from provider """

        block_list_providers_lists = []

        # Get malware provider URL string from config parser
        url_list_string = self.config[self.config_section_ip_list_parser][key]

        # Explode malware URL string to list
        url_list = str(url_list_string).split(',')

        for url in url_list:
            list_contents = HTTPGet.http_get_contents(url)

            # Check if request was valid or gave error
            if list_contents is None:
                continue

            ip_list_parsed = IPParser.find_ips(list_contents)

            block_list_providers_lists.append(ip_list_parsed)

        return block_list_providers_lists

    def compile_lists(self, ip_lists):
        """ Cross checks lists and return single list of ip addresses with count more than configured threshold """

        master_ip_dict = {}
        master_ip_list = []

        # For each list in all lists of any category (attackers/malware) add to dictionary to count each unique entry
        for ip_list in ip_lists:

            for ip in ip_list:

                if ip not in master_ip_dict:
                    master_ip_dict[ip] = 1
                else:
                    master_ip_dict[ip] += 1

        # For each unique key in the master IP list add to master ip list
        for key in master_ip_dict.keys():

            if master_ip_dict[key] > 1 or '/32' not in key:  # Whitelist IP blocks due to single occurrence

                # Append to master list depending in frequency across multiple lists (quality check)
                master_ip_list.append(key)

        # Force list to have maximum of 10000 IP's associated with it because of the WAFv2 IP set limitation
        if len(master_ip_list) >= 10000:
            master_ip_list = master_ip_list[:10000]

        return master_ip_list

    class IPReputationListType(Enum):
        """ Subclass enum for HTTPFloodLevel """
        ip_reputation_list_type_malware = 'ip_reputation_list_type_malware'
        ip_reputation_list_type_attackers = 'ip_reputation_list_type_attackers'