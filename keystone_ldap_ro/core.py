# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 Spanish National Research Council
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import uuid

from keystone.common import logging
from keystone.common import wsgi
from keystone import exception
from keystone import identity
from keystone.identity.backends import ldap
import keystone.middleware

from oslo.config import cfg

LOG = logging.getLogger(__name__)

CONF = cfg.CONF
opts = [
    cfg.BoolOpt("autocreate_users",
                    default=False,
                    help="If enabled, users will be created automatically "
                    "in the local Identity backend (default False)."),
]
CONF.register_opts(opts, group="ldap_ro")

PARAMS_ENV = keystone.middleware.PARAMS_ENV
CONTEXT_ENV = keystone.middleware.CONTEXT_ENV


class LDAPAuthROMiddleware(wsgi.Middleware):
    def __init__(self, *args, **kwargs):
        self.identity_api = identity.Manager()
        try:
            self.config_file = kwargs.pop("config_file")
        except KeyError:
            raise exception.PasteConfigNotFound(config_file="(no config file "
                                                            "defined)")

        self.domain = CONF.identity.default_domain_id or "default"

        super(LDAPAuthROMiddleware, self).__init__(*args, **kwargs)

    @classmethod
    def factory(cls, global_config, **local_config):
        # NOTE(aloga): This can be removed once the following bug is fixed
        # https://bugs.launchpad.net/keystone/+bug/1190978
        def _factory(app):
            conf = global_config.copy()
            conf.update(local_config)
            return cls(app, **local_config)
        return _factory

    def _do_ldap_lookup(self, username, password):
        """Do the ldap user authentication."""
        # NOTE(aloga): This might be an ugly hack so as to have several LDAP
        # servers with different configurations. but it works pretty well. We
        # load the LDAp configuration for our backend, make the lookup and then
        # we restore the configuration to the original one.
        oldcfgfiles = CONF.config_file
        CONF(project="keystone", default_config_files=[self.config_file])

        self.ldap_identity = ldap.Identity()
        try:
            auth = self.ldap_identity.authenticate(user_id=username,
                                                   password=password)
        finally:
            CONF(project="keystone", default_config_files=oldcfgfiles)

        return auth

    def is_applicable(self, request):
        """Check if the request is applicable for this handler or not"""
        params = request.environ.get(PARAMS_ENV, {})
        auth = params.get("auth", {})
        if "passwordCredentials" in auth:
            if (auth["passwordCredentials"]["username"] and
                auth["passwordCredentials"]["password"]):
                return True
            else:
                raise exception.ValidationError("Error in JSON")
        return False

    def process_request(self, request):
        if request.environ.get('REMOTE_USER', None) is not None:
            # authenticated upstream
            return self.application

        if not self.is_applicable(request):
            return self.application

        params = request.environ.get(PARAMS_ENV)

        username = params["auth"]["passwordCredentials"]["username"]
        password = params["auth"]["passwordCredentials"]["password"]
        tenant   = params["auth"]["passwordCredentials"].get("tenantName",
                                                             None)

        try:
            # Authenticate user on LDAP
            auth = self._do_ldap_lookup(username, password)
        except AssertionError:
            # The user is not on LDAp, or auth has failed.
            return self.application

        user_ref = auth[0]
        user_name = user_ref["name"]
        try:
            self.identity_api.get_user_by_name(
                self.identity_api,
                user_name,
                self.domain)
        except exception.UserNotFound:
            if CONF.ldap_ro.autocreate_users:
                user_id = uuid.uuid4().hex
                LOG.info(_("Autocreating REMOTE_USER %s with id %s") %
                        (user_id, user_name))
                user = {
                    "id": user_id,
                    "name": user_name,
                    "enabled": True,
                    "domain_id": self.domain,
                }
                self.identity_api.create_user(self.identity_api,
                                              user_id,
                                              user)

        request.environ['REMOTE_USER'] = user_name
