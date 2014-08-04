# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2013 Spanish National Research Council
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

from ldap import LDAPError
import uuid

from keystone.common import logging
from keystone.common import wsgi
from keystone import exception
from keystone import identity
from keystone.identity.backends import ldap as keystone_ldap
import keystone.middleware
from keystone.openstack.common.gettextutils import _

from oslo.config import cfg

LOG = logging.getLogger(__name__)

CONF = cfg.CONF
opts = [
    cfg.BoolOpt("autocreate_users",
                default=False,
                help="If enabled, users will be created automatically "
                     "in the local Identity backend (default False)."),
    cfg.StrOpt("default_tenant",
                default="",
                help="If specified users will be automatically "
                     "added to this tenant."),
]
CONF.register_opts(opts, group="ldap_ro")

PARAMS_ENV = keystone.middleware.PARAMS_ENV


class LDAPConfigNotFound(exception.UnexpectedError):
     """The Keystone LDAP-ro configuration file %(config_file)s could not be
     found.
     """


class LDAPAuthROMiddleware(wsgi.Middleware):
    def __init__(self, *args, **kwargs):
        self.identity_api = identity.Manager()
        try:
            self.config_file = kwargs.pop("config_file")
        except KeyError:
            raise LDAPConfigNotFound(config_file="(no config file defined)")

        self.domain = CONF.identity.default_domain_id or "default"

        super(LDAPAuthROMiddleware, self).__init__(*args, **kwargs)

    def _do_ldap_lookup(self, username, password):
        """Do the ldap user authentication."""
        # NOTE(aloga): This might be an ugly hack so as to have several LDAP
        # servers with different configurations. but it works pretty well. We
        # load the LDAp configuration for our backend, make the lookup and then
        # we restore the configuration to the original one.
        oldcfgfiles = CONF.config_file
        CONF(project="keystone", default_config_files=[self.config_file])

        self.ldap_identity = keystone_ldap.Identity()
        try:
            auth = self.ldap_identity.authenticate(user_id=username,
                                                   password=password)
        finally:
            CONF(project="keystone", default_config_files=oldcfgfiles)

        return auth

    def _do_create_user(self, user_ref):
        user_name = user_ref["name"]
        user_id = uuid.uuid4().hex
        LOG.info(_("Autocreating REMOTE_USER %s with id %s") %
                  (user_name, user_id))
        user = {
            "id": user_id,
            "name": user_name,
            "enabled": True,
            "domain_id": self.domain,
            "email": user_ref.get("email", "noemail"),
        }
        self.identity_api.create_user(user_id,
                                      user)
        if CONF.ldap_ro.default_tenant:
            try:
                tenant_ref = self.identity_api.get_project_by_name(
                    CONF.ldap_ro.default_tenant,
                    self.domain)
            except exception.ProjectNotFound:
                raise
            user_tenants = self.identity_api.list_projects_for_user(user_id)
            if tenant_ref["id"] not in user_tenants:
                LOG.info(_("Automatically adding user %s to tenant %s") %
                        (user_name, tenant_ref["name"]))
                self.identity_api.add_user_to_project(tenant_ref["id"],
                                                      user_id)

    def is_applicable(self, request):
        """Check if the request is applicable for this handler or not"""
        params = request.environ.get(PARAMS_ENV, {})
        auth = params.get("auth", {})
        if "passwordCredentials" in auth:
            if (auth["passwordCredentials"]["username"] and
                auth["passwordCredentials"]["password"]):
                return True
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

        try:
            # Authenticate user on LDAP
            auth = self._do_ldap_lookup(username, password)
        except AssertionError:
            # The user is not on LDAp, or auth has failed.
            return self.application
        except LDAPError as e:
            LOG.error(_("Unable to contact to LDAP server"))
            LOG.exception(e)
            return self.application

        user_ref = auth[0]
        user_name = user_ref["name"]
        try:
            self.identity_api.get_user_by_name(user_name, self.domain)
        except exception.UserNotFound:
            if CONF.ldap_ro.autocreate_users:
                self._do_create_user(user_ref)

        request.environ['REMOTE_USER'] = user_name
