""" This file contains the HTTPGet class """

import requests
import logging

# Setup logger
LOGGER = logging.getLogger()
LOGGER.setLevel(logging.INFO)


class HTTPGet:
    """ This class is responsible for making requests to the IP list parser provider URL's and returning the result. """

    @staticmethod
    def http_get_contents(url):

        try:

            http_response = requests.get(url)

            if http_response.status_code == 200:
                return http_response.content.decode('utf-8')
            else:
                return None

        except Exception as e:
            LOGGER.error('Error. Could not connect to: {0}. Error message: {1}'.format(url, e))
            return None
