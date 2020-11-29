""" File containing IPParser class """

import re
import logging

# Setup logger
LOGGER = logging.getLogger()
LOGGER.setLevel(logging.INFO)


class IPParser:
    """ This class is responsible for parsing and extracting IPs """
# s*((?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9][0-9]|[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9][0-9]|[0-9])(?:\/(?:3[0-2]|[1-2][0-9]|[0-9]))?)
# s*((?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9][0-9]|[0-9]).){3}(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9][0-9]|[0-9])(?:\/(?:3[0-2]|[1-2][0-9]|[0-9]))?)

# [^,;]+
    # ip_addresses = re.findall( r'[0-9]+(?:\.[0-9]+){3}', content)


    @staticmethod
    def find_ips(content):
        """ Find IP's in a string and return a list of IP addresses including their range """

        ip_addresses_single = []

        # Get ip addresses OR blocks
        ip_addresses = re.findall(r's*((?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9][0-9]|[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9][0-9]|[0-9])(?:\/(?:3[0-2]|[1-2][0-9]|[0-9]))?)', content)

        # Deduplicate list
        ip_addresses = list(set(ip_addresses))

        # LOGGER.info(ip_addresses[0])

        # Check if list is blocks or list is IP adresses
        if ip_addresses:
            if '/' not in ip_addresses[0]:
                for ip in ip_addresses:

                    # Add /32 for single host
                    ip_addresses_single.append(ip + '/32')

                # Return single IP addresses
                return ip_addresses_single

        # Return IP blocks
        return ip_addresses

