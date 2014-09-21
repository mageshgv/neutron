# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import mock
import webob.exc

from neutron.services.grouppolicy import config
from neutron.services.grouppolicy.drivers.oneconvergence import nvsd_gbp_api
from neutron.tests.unit.services.grouppolicy import test_grouppolicy_plugin

CORE_PLUGIN = 'neutron.tests.unit.test_l3_plugin.TestNoL3NatPlugin'


class NvsdGbpDriverTestCase(test_grouppolicy_plugin.GroupPolicyPluginTestCase):
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
        super(NvsdGbpDriverTestCase, self).setUp(core_plugin=CORE_PLUGIN)


class TestEndpointGroup(NvsdGbpDriverTestCase):

    def test_implicit_subnet_lifecycle(self):
        self._tenant_id = '1234'
        with self.network() as network:
            network_id = network['network']['id']
            l2p = self.create_l2_policy(network_id=network_id)
            l2p_id = l2p['l2_policy']['id']
            network_id = l2p['l2_policy']['network_id']

            # Create endpoint group with implicit subnet.
            resp = mock.Mock()
            resp.json.return_value = {'id': 'uuid'}
            with mock.patch.object(nvsd_gbp_api.NVSDServiceApi,
                                   'create_endpointgroup',
                                   return_value=resp):
                epg = self.create_endpoint_group(name="epg1",
                                                 l2_policy_id=l2p_id)
                epg_id = epg['endpoint_group']['id']
            subnets = epg['endpoint_group']['subnets']
            self.assertIsNotNone(subnets)
            self.assertEqual(len(subnets), 1)
            subnet_id = subnets[0]

            # Verify deleting endpoint group cleans up subnet.
            with mock.patch.object(nvsd_gbp_api.NVSDServiceApi,
                                   'delete_endpointgroup'):
                req = self.new_delete_request('endpoint_groups', epg_id)
                res = req.get_response(self.ext_api)
                self.assertEqual(res.status_int, webob.exc.HTTPNoContent.code)
            req = self.new_show_request('subnets', subnet_id, fmt=self.fmt)
            res = req.get_response(self.api)
            self.assertEqual(res.status_int, webob.exc.HTTPNotFound.code)
            req = self.new_delete_request('l2_policies', l2p_id)
            res = req.get_response(self.ext_api)

    def test_explicit_subnet_lifecycle(self):
        self._tenant_id = '1234'
        # Create L2 policy.
        with self.network() as network:
            network_id = network['network']['id']
            l2p = self.create_l2_policy(network_id=network_id)
            l2p_id = l2p['l2_policy']['id']
            network_id = l2p['l2_policy']['network_id']

        # Create endpoint group with explicit subnet.
        with self.subnet(network=network, cidr='10.10.1.0/24') as subnet:
            subnet_id = subnet['subnet']['id']
            resp = mock.Mock()
            resp.json.return_value = {'id': 'uuid'}
            with mock.patch.object(nvsd_gbp_api.NVSDServiceApi,
                                   'create_endpointgroup',
                                   return_value=resp):
                epg = self.create_endpoint_group(name="epg1",
                                                 l2_policy_id=l2p_id,
                                                 subnets=[subnet_id])
                epg_id = epg['endpoint_group']['id']
            subnets = epg['endpoint_group']['subnets']
            self.assertIsNotNone(subnets)
            self.assertEqual(len(subnets), 1)
            self.assertEqual(subnet_id, subnets[0])

            # Verify deleting endpoint group does not cleanup subnet.
            with mock.patch.object(nvsd_gbp_api.NVSDServiceApi,
                                   'delete_endpointgroup'):
                req = self.new_delete_request('endpoint_groups', epg_id)
                res = req.get_response(self.ext_api)
                self.assertEqual(res.status_int, webob.exc.HTTPNoContent.code)
            req = self.new_show_request('subnets', subnet_id, fmt=self.fmt)
            res = req.get_response(self.api)
            self.assertEqual(res.status_int, webob.exc.HTTPOk.code)


class TestL2Policy(NvsdGbpDriverTestCase):

    def test_implicit_network_rejected(self):
        # Create L2 policy with implicit network.
        l2p = self.create_l2_policy(name="l2p1", expected_res_status=400)
        self.assertIn("NeutronError", l2p)
        self.assertEqual(l2p["NeutronError"].get('type'),
                         "L2PolicyRequiresNetwork")

    def test_explicit_network_lifecycle(self):
        # Create L2 policy with explicit network.
        with self.network() as network:
            network_id = network['network']['id']
            l2p = self.create_l2_policy(name="l2p1", network_id=network_id)
            l2p_id = l2p['l2_policy']['id']
            self.assertEqual(network_id, l2p['l2_policy']['network_id'])

            # Verify deleting L2 policy does not cleanup network.
            req = self.new_delete_request('l2_policies', l2p_id)
            res = req.get_response(self.ext_api)
            self.assertEqual(res.status_int, webob.exc.HTTPNoContent.code)
            req = self.new_show_request('networks', network_id, fmt=self.fmt)
            res = req.get_response(self.api)
            self.assertEqual(res.status_int, webob.exc.HTTPOk.code)
