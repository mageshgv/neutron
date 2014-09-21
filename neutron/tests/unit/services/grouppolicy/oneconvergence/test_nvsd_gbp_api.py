# Copyright 2014 OneConvergence, Inc. All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
#

import mock

from neutron.openstack.common import jsonutils
from neutron.services.grouppolicy import config
from neutron.services.grouppolicy.drivers.oneconvergence import nvsd_gbp_api
from neutron.tests import base

NVSD_ENDPOINT = "/nvsd_connectivity_port"
NVSD_ENDPOINT_GROUP = "/nvsd_connectivity_portgroup"
NVSD_CONTRACT = "/nvsd_connectivity_contract"
NVSD_POLICY = "/nvsd_connectivity_policy"
NVSD_POLICY_ACTION = "/nvsd_connectivity_action"
NVSD_POLICY_CLASSIFIER = "/nvsd_connectivity_classifier"
NVSD_POLICY_RULE = "/nvsd_connectivity_rule"

ADMIN_URL = "&is_admin=true"
API_TENANT_USER = "?tenant_id=%s&user_id=%s"

TEST_TENANT = 'test-tenant'
TEST_USER = 'test-user'


class Context(object):
    def __init__(self, is_admin=False, user=TEST_USER, tenant_id=TEST_TENANT):
        self.is_admin = is_admin
        self.user = user
        self.tenant_id = tenant_id


class TestNVSDServiceApi(base.BaseTestCase):
    """Unit tests for One Convergence NVSD Group Policy API.

    This class tests that Openstack Group Policy API requests are mapped
    to proper One Convergence NVSD API requests. It also validates that
    the request body is transformed appropriately to match the One Convergence
    NVSD Service API
    """

    def setUp(self):
        config.cfg.CONF.set_override('policy_drivers',
                                     ['implicit_policy',
                                      'oneconvergence_nvsd_gbp_driver'],
                                     group='group_policy')
        config.cfg.CONF.set_override('service_controller_ip',
                                     '127.0.0.1',
                                     group='NVSD_SERVICE_CONTROLLER')
        config.cfg.CONF.set_override('service_controller_port',
                                     '5432',
                                     group='NVSD_SERVICE_CONTROLLER')
        config.cfg.CONF.set_override('request_retries', 0,
                                     group='NVSD_SERVICE_CONTROLLER')
        config.cfg.CONF.set_override('request_timeout', 10,
                                     group='NVSD_SERVICE_CONTROLLER')
        super(TestNVSDServiceApi, self).setUp()
        self.nvsd_service_api = nvsd_gbp_api.NVSDServiceApi()
        self.nvsd_service_controller = nvsd_gbp_api.NVSDServiceController()

    def mockNvsdApiRequestMethod(self, method, uri, context, body="",
                           content_type="application/json"):
        """Mock patch for the request() method in NVSDServiceController

        Default mock cannot be used in this case because the argument 'body' is
        json.dumps(dict). When the order of keys is different, the validation
        assert_called_once_with fails because dictionary is converted to string
        """
        self.method = method
        self.body = body
        self.uri = uri
        return mock.Mock()

    def test_create_endpoint(self):
        endpoint = {
            "name": 'test-ep',
            "tenant_id": TEST_TENANT,
            "description": 'Test Endpoint',
            "endpoint_group_id": 'epg_id'
        }
        context = Context()
        with mock.patch.object(self.nvsd_service_api.nvsd_service_controller,
                              'request', new=self.mockNvsdApiRequestMethod):
            uri = NVSD_ENDPOINT + "?tenant_id=%s&user_id=%s" % (TEST_TENANT,
                                                                context.user)
            self.nvsd_service_api.create_endpoint(context, endpoint)
            endpoint["connectivity_portgroup_id"] = "epg_id"
            self.assertEqual(jsonutils.loads(self.body), endpoint)
            self.assertEqual(self.uri, uri)
            self.assertEqual(self.method, 'POST')

    def test_update_endpoint(self):
        endpoint = {
            "name": 'test-ep2',
            "tenant_id": TEST_TENANT,
            "endpoint_group_id": 'epg_id',
            "id": 'ep_id'
        }
        context = Context()
        with mock.patch.object(self.nvsd_service_api.nvsd_service_controller,
                               'request', new=self.mockNvsdApiRequestMethod):
            uri = (NVSD_ENDPOINT + "/ep_id" + "?tenant_id=%s&user_id=%s" %
                   (TEST_TENANT, context.user))
            self.nvsd_service_api.update_endpoint(context, endpoint)
            endpoint.update({"connectivity_portgroup_id": "epg_id"})
            self.assertEqual(jsonutils.loads(self.body), endpoint)
            self.assertEqual(self.uri, uri)
            self.assertEqual(self.method, 'PUT')

    def test_delete_endpoint(self):
        endpoint_id = 'ep_id'
        context = Context()
        with mock.patch.object(self.nvsd_service_api.nvsd_service_controller,
                               'request', new=self.mockNvsdApiRequestMethod):
            uri = (NVSD_ENDPOINT + "/ep_id" + "?tenant_id=%s&user_id=%s" %
                   (TEST_TENANT, context.user))
            self.nvsd_service_api.delete_endpoint(context, endpoint_id)
            self.assertEqual(self.body, '')
            self.assertEqual(self.uri, uri)
            self.assertEqual(self.method, 'DELETE')

    def test_create_endpointgroup(self):
        endpointgroup = {
            "name": 'test-epg',
            "tenant_id": TEST_TENANT,
            "description": 'Test Endpoint Group',
            "l2_policy_id": 'l2_policy_id',
            "provided_contracts": {},
            "consumed_contracts": {}
        }
        context = Context()
        with mock.patch.object(self.nvsd_service_api.nvsd_service_controller,
                               'request', new=self.mockNvsdApiRequestMethod):
            uri = (NVSD_ENDPOINT_GROUP + "?tenant_id=%s&user_id=%s" %
                   (TEST_TENANT, context.user))
            self.nvsd_service_api.create_endpointgroup(context,
                                                       endpointgroup)
            self.assertEqual(jsonutils.loads(self.body), endpointgroup)
            self.assertEqual(self.uri, uri)
            self.assertEqual(self.method, 'POST')

    def test_update_endpointgroup(self):
        endpointgroup = {
            "name": 'test-epg2',
            "tenant_id": TEST_TENANT,
            "id": 'epg_id',
            "provided_contracts": {},
            "consumed_contracts": {}
        }
        context = Context()
        with mock.patch.object(self.nvsd_service_api.nvsd_service_controller,
                               'request', new=self.mockNvsdApiRequestMethod):
            uri = (NVSD_ENDPOINT_GROUP + "/epg_id" + "?tenant_id=%s"
                   "&user_id=%s" % (TEST_TENANT, context.user))
            self.nvsd_service_api.update_endpointgroup(context, endpointgroup)
            self.assertEqual(jsonutils.loads(self.body), endpointgroup)
            self.assertEqual(self.uri, uri)
            self.assertEqual(self.method, 'PUT')

    def test_delete_endpointgroup(self):
        endpointgroup_id = 'epg_id'
        context = Context()
        with mock.patch.object(self.nvsd_service_api.nvsd_service_controller,
                               'request', new=self.mockNvsdApiRequestMethod):
            uri = (NVSD_ENDPOINT_GROUP + "/epg_id" + "?tenant_id=%s"
                   "&user_id=%s" % (TEST_TENANT, context.user))
            self.nvsd_service_api.delete_endpointgroup(context,
                                                       endpointgroup_id)
            self.assertEqual(self.body, '')
            self.assertEqual(self.uri, uri)
            self.assertEqual(self.method, 'DELETE')

    def test_create_contract(self):
        contract = {
            "name": 'test-contract',
            "tenant_id": TEST_TENANT,
            "description": 'Test Contract',
            "child_contracts": [],
            "policy_rules": []
        }
        context = Context()
        with mock.patch.object(self.nvsd_service_api.nvsd_service_controller,
                               'request', new=self.mockNvsdApiRequestMethod):
            uri = NVSD_CONTRACT + "?tenant_id=%s&user_id=%s" % (TEST_TENANT,
                                                                context.user)
            self.nvsd_service_api.create_contract(context, contract)
            self.assertEqual(jsonutils.loads(self.body), contract)
            self.assertEqual(self.uri, uri)
            self.assertEqual(self.method, 'POST')

    def test_update_contract(self):
        contract = {
            "name": 'test-contract2',
            "tenant_id": TEST_TENANT,
            "id": 'contract_id'
        }
        context = Context()
        with mock.patch.object(self.nvsd_service_api.nvsd_service_controller,
                               'request', new=self.mockNvsdApiRequestMethod):
            uri = (NVSD_CONTRACT + "/contract_id" + "?tenant_id=%s"
                   "&user_id=%s" % (TEST_TENANT, context.user))
            self.nvsd_service_api.update_contract(context, contract)
            self.assertEqual(jsonutils.loads(self.body), contract)
            self.assertEqual(self.uri, uri)
            self.assertEqual(self.method, 'PUT')

    def test_delete_contract(self):
        contract_id = 'contract_id'
        context = Context()
        with mock.patch.object(self.nvsd_service_api.nvsd_service_controller,
                               'request', new=self.mockNvsdApiRequestMethod):
            uri = (NVSD_CONTRACT + "/contract_id" + "?tenant_id=%s"
                   "&user_id=%s" % (TEST_TENANT, context.user))
            self.nvsd_service_api.delete_contract(context, contract_id)
            self.assertEqual(self.body, '')
            self.assertEqual(self.uri, uri)
            self.assertEqual(self.method, 'DELETE')

    def test_create_policy_action(self):
        policy_action = {
            "name": 'test-policy-action',
            "tenant_id": TEST_TENANT,
            "description": 'Test Policy Action',
            "action_type": 'allow',
            "action_value": '1234'
        }
        context = Context()
        with mock.patch.object(self.nvsd_service_api.nvsd_service_controller,
                               'request', new=self.mockNvsdApiRequestMethod):
            uri = (NVSD_POLICY_ACTION + "?tenant_id=%s&user_id=%s" %
                   (TEST_TENANT, context.user))
            self.nvsd_service_api.create_policy_action(context, policy_action)
            policy_action.update({'action_value': [{'service': '1234'}]})
            self.assertEqual(jsonutils.loads(self.body), policy_action)
            self.assertEqual(self.uri, uri)
            self.assertEqual(self.method, 'POST')

    def test_update_policy_action(self):
        policy_action = {
            "name": 'test-policy-action2',
            "tenant_id": TEST_TENANT,
            "description": 'Test Policy Action',
            "action_type": 'allow',
            "action_value": '1234',
            "id": "policy_action_id"
        }
        context = Context()
        with mock.patch.object(self.nvsd_service_api.nvsd_service_controller,
                               'request', new=self.mockNvsdApiRequestMethod):
            uri = (NVSD_POLICY_ACTION + "/policy_action_id" + "?tenant_id=%s"
                   "&user_id=%s" % (TEST_TENANT, context.user))
            self.nvsd_service_api.update_policy_action(context, policy_action)
            policy_action.update({'action_value': [{'service': '1234'}]})
            self.assertEqual(jsonutils.loads(self.body), policy_action)
            self.assertEqual(self.uri, uri)
            self.assertEqual(self.method, 'PUT')

    def test_delete_policy_action(self):
        policy_action_id = 'policy_action_id'
        context = Context()
        with mock.patch.object(self.nvsd_service_api.nvsd_service_controller,
                               'request', new=self.mockNvsdApiRequestMethod):
            uri = (NVSD_POLICY_ACTION + "/policy_action_id" + "?tenant_id=%s"
                   "&user_id=%s" % (TEST_TENANT, context.user))
            self.nvsd_service_api.delete_policy_action(context,
                                                       policy_action_id)
            self.assertEqual(self.body, '')
            self.assertEqual(self.uri, uri)
            self.assertEqual(self.method, 'DELETE')

    def test_create_policy_classifier(self):
        policy_classifier = {
            "name": 'test-ep',
            "tenant_id": TEST_TENANT,
            "description": 'Test Endpoint',
            "protocol": 'tcp',
            "port_range": '80',
            "direction": "bi"
        }
        context = Context()
        with mock.patch.object(self.nvsd_service_api.nvsd_service_controller,
                               'request', new=self.mockNvsdApiRequestMethod):
            uri = (NVSD_POLICY_CLASSIFIER + "?tenant_id=%s&user_id=%s" %
                   (TEST_TENANT, context.user))
            self.nvsd_service_api.create_policy_classifier(
                                        context, policy_classifier)
            policy_classifier.update({"port": "80"})
            self.assertEqual(jsonutils.loads(self.body), policy_classifier)
            self.assertEqual(self.uri, uri)
            self.assertEqual(self.method, 'POST')

    def test_update_policy_classifier(self):
        policy_classifier = {
            "name": 'test-ep2',
            "tenant_id": TEST_TENANT,
            "protocol": 'tcp',
            "port_range": '90',
            "direction": "bi",
            "id": 'policy_classifier_id'
        }
        context = Context()
        with mock.patch.object(self.nvsd_service_api.nvsd_service_controller,
                               'request', new=self.mockNvsdApiRequestMethod):
            uri = (NVSD_POLICY_CLASSIFIER + "/policy_classifier_id" + "?"
                   "tenant_id=%s&user_id=%s" % (TEST_TENANT, context.user))
            self.nvsd_service_api.update_policy_classifier(context,
                                                           policy_classifier)
            policy_classifier.update({"port": "90"})
            self.assertEqual(jsonutils.loads(self.body), policy_classifier)
            self.assertEqual(self.uri, uri)
            self.assertEqual(self.method, 'PUT')

    def test_delete_policy_classifier(self):
        policy_classifier_id = 'policy_classifier_id'
        context = Context()
        with mock.patch.object(self.nvsd_service_api.nvsd_service_controller,
                               'request', new=self.mockNvsdApiRequestMethod):
            uri = (NVSD_POLICY_CLASSIFIER + "/policy_classifier_id" + "?"
                   "tenant_id=%s&user_id=%s" % (TEST_TENANT, context.user))
            self.nvsd_service_api.delete_policy_classifier(
                                                context, policy_classifier_id)
            self.assertEqual(self.body, '')
            self.assertEqual(self.uri, uri)
            self.assertEqual(self.method, 'DELETE')

    def test_create_policy_rule(self):
        policy_rule = {
            "name": 'test-ep',
            "tenant_id": TEST_TENANT,
            "description": 'Test Endpoint',
            "enabled": True,
            "policy_classifier_id": '1234',
            "policy_actions": []
        }
        context = Context()
        with mock.patch.object(self.nvsd_service_api.nvsd_service_controller,
                               'request', new=self.mockNvsdApiRequestMethod):
            uri = (NVSD_POLICY_RULE + "?tenant_id=%s&user_id=%s" %
                   (TEST_TENANT, context.user))
            self.nvsd_service_api.create_policy_rule(context, policy_rule)
            policy_rule.update(
                    {'classifier': policy_rule.get('policy_classifier_id'),
                     'actions': policy_rule.get('policy_actions', []),
                     'policies_attached': []})
            self.assertEqual(jsonutils.loads(self.body), policy_rule)
            self.assertEqual(self.uri, uri)
            self.assertEqual(self.method, 'POST')

    def test_update_policy_rule(self):
        policy_rule = {
            "name": 'test-ep2',
            "tenant_id": TEST_TENANT,
            "enabled": True,
            "policy_classifier_id": '1234',
            "policy_actions": [],
            "id": 'policy_rule_id'
        }
        context = Context()
        with mock.patch.object(self.nvsd_service_api.nvsd_service_controller,
                               'request', new=self.mockNvsdApiRequestMethod):
            uri = (NVSD_POLICY_RULE + "/policy_rule_id" + "?tenant_id=%s"
                   "&user_id=%s" % (TEST_TENANT, context.user))
            self.nvsd_service_api.update_policy_rule(context, policy_rule)
            policy_rule.update(
                    {'classifier': policy_rule.get('policy_classifier_id'),
                     'actions': policy_rule.get('policy_actions', [])})
            self.assertEqual(jsonutils.loads(self.body), policy_rule)
            self.assertEqual(self.uri, uri)
            self.assertEqual(self.method, 'PUT')

    def test_delete_policy_rule(self):
        policy_rule_id = 'policy_rule_id'
        context = Context()
        with mock.patch.object(self.nvsd_service_api.nvsd_service_controller,
                               'request', new=self.mockNvsdApiRequestMethod):
            uri = (NVSD_POLICY_RULE + "/policy_rule_id" + "?tenant_id=%s"
                   "&user_id=%s" % (TEST_TENANT, context.user))
            self.nvsd_service_api.delete_policy_rule(context, policy_rule_id)
            self.assertEqual(self.body, '')
            self.assertEqual(self.uri, uri)
            self.assertEqual(self.method, 'DELETE')
