# -*- coding: utf-8 -*-
# Copyright 2016 
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from twisted.internet import defer, threads
from keycloak import KeycloakOpenID
from keycloak.exceptions import KeycloakAuthenticationError


import logging
import synapse
import json

from pkg_resources import parse_version


__version__ = "0.0.1"



logger = logging.getLogger(__name__)

class KeycloakAuthProvider(object):
    __version__ = "0.0.1"

    def __init__(self, config, account_handler):
        self.account_handler = account_handler

        self.url = config.url
        self.client_id = config.client_id
        self.realm_name = config.realm_name
        self.secret_key = config.secret_key
        self.public_key = config.public_key
        self.algorithm = config.algorithm
        self.profile_attrs = config.profile_attrs


    @defer.inlineCallbacks
    def check_password(self, user_id, password):
        """ Attempt to authenticate a user against an Keycloak Server
            and register an account if none exists.

            Returns:
                True if authentication against Keycloak was successful
        """
        if not password:
            defer.returnValue(False)

        localpart = user_id.split(":", 1)[0][1:]
        logger.info("! %s", localpart)
        # login = localpart.split("@")[1]
        # logger.info("! %s", login)

        keycloak_openid = KeycloakOpenID(server_url=self.url,
                    client_id=self.client_id,
                    realm_name=self.realm_name,
                    client_secret_key=self.secret_key)
        logger.debug("Attempting Keycloak connection with %s", self.url)

        try:
            token = yield keycloak_openid.token(localpart, password)
        except KeycloakAuthenticationError as e:
            logger.info("Failed login attempt %s error: %s", localpart, e)
            defer.returnValue(False)

        logger.info("User %s authenticated", user_id)
        options = {"verify_signature": True, "verify_aud": True, "exp": True}

        key = self.public_key
        if self.algorithm == 'RS256':
            key = '-----BEGIN PUBLIC KEY-----\n' + key + '\n-----END PUBLIC KEY-----'
        token_info = keycloak_openid.decode_token(token['access_token'], key=key, algorithms=[self.algorithm], options=options)

        if not (yield self.account_handler.check_user_exists(user_id)):
            logger.info("User %s does not exist yet, creating...", user_id)
            if localpart != localpart.lower() and self.regLower:
                 logger.info('User %s was cannot be created due to username lowercase policy', localpart)
                 defer.returnValue(False)
            user_id, access_token = (yield self.account_handler.register(localpart=localpart))
            registration = True
            logger.info("Registration based on REST data was successful for %s", user_id)
        else:
            logger.info("User %s already exists, registration skipped", user_id)

        if bool(self.profile_attrs):
            store = yield self.account_handler.hs.get_profile_handler().store
            profile = {}
            for key, alias in self.profile_attrs.items():
                if alias in token_info:
                    profile[key] = token_info[ alias ]

            display_name = profile.pop('display_name', None)
            if display_name:
                logger.info("Setting display name to '%s' based on profile data", display_name)
                yield store.set_profile_displayname(localpart, display_name)
            # TODO 3pids
        else:
            logger.info("No profile data")

        defer.returnValue(True)


    @defer.inlineCallbacks
    def on_logged_out(self, user_id, device_id, access_token):
        """Close session on keycloak server

        """

    @staticmethod
    def parse_config(config):
        _require_keys(config, [
		"url", "client_id", "realm_name", "secret_key",
                "public_key", "algorithm"
	])

        class _KeyCloakConfig(object):
            url = ''
            client_id = ''
            realm_name = ''
            secret_key = ''
            public_key = ''
            algorithm = 'RS256'
            profile_attrs = {}

        keycloak_config = _KeyCloakConfig()
        keycloak_config.url = config["url"]
        keycloak_config.client_id = config["client_id"]
        keycloak_config.realm_name = config["realm_name"]
        keycloak_config.secret_key = config["secret_key"]
        keycloak_config.public_key= config["public_key"]
        keycloak_config.algorithm = config["algorithm"]

        keycloak_config.profile_attrs = config.get("profile_attrs", {})

        return keycloak_config

def _require_keys(config, required):
    missing = [key for key in required if key not in config]
    if missing:
        raise Exception(
            "Keycloak Auth enabled but missing required config values: {}".format(
                ", ".join(missing)
            )
        )
