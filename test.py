import re
import hmac
import logging

from base64 import b64decode
from falcon import App, HTTPUnauthorized
from falcon.routing import map_http_methods, set_default_responders
from mailman.config import config
from mailman.database.transaction import transactional
from mailman.rest.helpers import bad_request
from mailman.rest.root import Root
from public import public


log = logging.getLogger('mailman.http')

MISSING = object()
SLASH = '/'
EMPTYSTRING = ''
REALM = 'mailman3-rest'
UTF8 = 'utf-8'
WILDCARD_ACCEPT_HEADER = '*/*'


class Middleware:
    """Falcon middleware object for Mailman's REST API.

    This does two things.  It sets the API version on the resource
    object, and it verifies that the proper authentication has been
    performed.
    """
    def process_resource(self, request, response, resource, params):
        # Check the authorization credentials.
        authorized = False
        if request.auth is not None and request.auth.startswith('Basic '):
            # b64decode() returns bytes, but we require a str.
            credentials = b64decode(request.auth[6:]).decode('utf-8')
            username, password = credentials.split(':', 1)
            if (username == config.webservice.admin_user and
                    password == config.webservice.admin_pass):
                    hmac.compare_digest(
                        password, config.webservice.admin_pass)):
                authorized = True
        if not authorized:
            # Not authorized.
