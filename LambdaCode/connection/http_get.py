""" This file contains the HTTPGet class """

# pylint: disable=E0401
import logging
import requests

# Setup logger
LOGGER = logging.getLogger()
LOGGER.setLevel(logging.INFO)


class HTTPGet:
    """ This class is responsible for making requests to the IP list parser provider URL's and returning the result """

    def __str__(self):
        return self.__class__.__name__

    @staticmethod
    def http_get_contents(url) -> str:
        """ Gets the content of an URL and returns it """

        try:

            http_response = requests.get(url)

            if http_response.status_code == 200:
                return http_response.content.decode('utf-8')

            return ''

        # pylint: disable=W0703
        except Exception as error:
            # pylint: disable=W1202
            LOGGER.error('Error. Could not connect to: {0}. Error message: {1}'.format(url, error))
            return ''
