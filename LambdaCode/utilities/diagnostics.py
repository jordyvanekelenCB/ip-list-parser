""" This module holds the Diagnostics class """

import logging

# Setup logger
LOGGER = logging.getLogger()
LOGGER.setLevel(logging.INFO)


class Diagnostics:
    """ This class is responsible for printing diagnostic results """

    def __str__(self):
        return self.__class__.__name__

    @staticmethod
    def print_results(diagnostic_results) -> None:
        """ Prints HTTP Flood clean results to screen """

        ip_list_parser_results = diagnostic_results['ip_list_parser_results']
        config = diagnostic_results['config']

        number_of_attacker_reputation_lists = str(config['IP_LIST_PARSER']['ATTACKERS_IP_LIST_PROVIDERS']).split(',')
        number_of_malware_reputation_lists = str(config['IP_LIST_PARSER']['MALWARE_IP_LIST_PROVIDERS']).split(',')

        malware_ip_list_compiled = ip_list_parser_results['malware_ip_list_compiled']
        attacker_ip_list_compiled = ip_list_parser_results['attacker_ip_list_compiled']


        LOGGER.info('================================ IP list parser results ================================')

        # pylint: disable=W1202
        LOGGER.info("Total number of attacker IPs in {0} block lists: {1}."
                    .format(len(number_of_attacker_reputation_lists), len(attacker_ip_list_compiled)))
        LOGGER.info("Total number of malware IPs in {0} block lists: {1}."
                    .format(len(number_of_malware_reputation_lists), len(malware_ip_list_compiled)))

        LOGGER.info("Actions taken: Updated attackers IP set with {0} new entries. "
                    "Updated malware IP set with {1} new entries."
                    .format(len(attacker_ip_list_compiled), len(malware_ip_list_compiled)))
