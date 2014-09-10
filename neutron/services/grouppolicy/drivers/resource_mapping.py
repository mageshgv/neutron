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

import netaddr

from oslo.config import cfg
import sqlalchemy as sa

from neutron.api.rpc.agentnotifiers import dhcp_rpc_agent_api
from neutron.api.v2 import attributes
from neutron.common import constants as const
from neutron.common import log
from neutron.db import model_base
from neutron.extensions import securitygroup as ext_sg
from neutron import manager
from neutron.notifiers import nova
from neutron.openstack.common import log as logging
from neutron.plugins.common import constants as pconst
from neutron.services.grouppolicy.common import constants as gconst
from neutron.services.grouppolicy.common import exceptions as exc
from neutron.services.grouppolicy import group_policy_driver_api as api


LOG = logging.getLogger(__name__)


class OwnedPort(model_base.BASEV2):
    """A Port owned by the resource_mapping driver."""

    __tablename__ = 'gpm_owned_ports'
    port_id = sa.Column(sa.String(36),
                        sa.ForeignKey('ports.id', ondelete='CASCADE'),
                        nullable=False, primary_key=True)


class OwnedSubnet(model_base.BASEV2):
    """A Subnet owned by the resource_mapping driver."""

    __tablename__ = 'gpm_owned_subnets'
    subnet_id = sa.Column(sa.String(36),
                          sa.ForeignKey('subnets.id', ondelete='CASCADE'),
                          nullable=False, primary_key=True)


class OwnedNetwork(model_base.BASEV2):
    """A Network owned by the resource_mapping driver."""

    __tablename__ = 'gpm_owned_networks'
    network_id = sa.Column(sa.String(36),
                           sa.ForeignKey('networks.id', ondelete='CASCADE'),
                           nullable=False, primary_key=True)


class OwnedRouter(model_base.BASEV2):
    """A Router owned by the resource_mapping driver."""

    __tablename__ = 'gpm_owned_routers'
    router_id = sa.Column(sa.String(36),
                          sa.ForeignKey('routers.id', ondelete='CASCADE'),
                          nullable=False, primary_key=True)


class ContractSGsMapping(model_base.BASEV2):
    """Contract to SGs mapping DB."""

    __tablename__ = 'gpm_contract_sg_mapping'
    contract_id = sa.Column(sa.String(36),
                          sa.ForeignKey('gp_contracts.id', ondelete='CASCADE'),
                            nullable=False, primary_key=True)
    provided_sg_id = sa.Column(sa.String(36),
                               sa.ForeignKey('securitygroups.id'))
    consumed_sg_id = sa.Column(sa.String(36),
                               sa.ForeignKey('securitygroups.id'))


class ResourceMappingDriver(api.PolicyDriver):
    """Resource Mapping driver for Group Policy plugin.

    This driver implements group policy semantics by mapping group
    policy resources to various other neutron resources.
    """

    @log.log
    def initialize(self):
        self._cached_agent_notifier = None
        self._nova_notifier = nova.Notifier()

    @log.log
    def create_endpoint_precommit(self, context):
        if not context.current['endpoint_group_id']:
            raise exc.EndpointRequiresEndpointGroup()

    @log.log
    def create_endpoint_postcommit(self, context):
        # TODO(rkukura): Validate explicit port belongs to subnet of
        # EPG.
        if not context.current['port_id']:
            self._use_implicit_port(context)
        self._assoc_epg_sg_to_ep(context, context.current['id'],
                                 context.current['endpoint_group_id'])

    @log.log
    def update_endpoint_precommit(self, context):
        pass

    @log.log
    def update_endpoint_postcommit(self, context):
        # TODO(s3wong): if port mapping change, disassociate port
        # from contract-default-sg, and bind updated port to it
        # Also, if EP->EPG mapping changes, need to disassociate
        # corresponding SGs, and re-associate with the new contract ones
        orig_epg_id = context.original['endpoint_group_id']
        curr_epg_id = context.current['endpoint_group_id']
        if (orig_epg_id != curr_epg_id):
            ep_id = context.current['id']
            self._disassoc_epg_sg_from_ep(context, ep_id, orig_epg_id)
            self._assoc_epg_sg_to_ep(context, ep_id, curr_epg_id)

    @log.log
    def delete_endpoint_precommit(self, context):
        self._disassoc_epg_sg_from_ep(context,
                                      context.current['id'],
                                      context.current['endpoint_group_id'])
        pass

    @log.log
    def delete_endpoint_postcommit(self, context):
        # TODO(s3wong): disassociate contract-default-sg from port
        port_id = context.current['port_id']
        self._cleanup_port(context, port_id)

    @log.log
    def create_endpoint_group_precommit(self, context):
        pass

    @log.log
    def create_endpoint_group_postcommit(self, context):
        # TODO(rkukura): Validate explicit subnet belongs to L2P's
        # network.
        subnets = context.current['subnets']
        if subnets:
            l2p_id = context.current['l2_policy_id']
            l2p = context._plugin.get_l2_policy(context._plugin_context,
                                                l2p_id)
            l3p_id = l2p['l3_policy_id']
            l3p = context._plugin.get_l3_policy(context._plugin_context,
                                                l3p_id)
            router_id = l3p['routers'][0]
            for subnet_id in subnets:
                self._use_explicit_subnet(context, subnet_id, router_id)
        else:
            self._use_implicit_subnet(context)
        self._handle_contracts(context)

    @log.log
    def update_endpoint_group_precommit(self, context):
        if set(context.original['subnets']) - set(context.current['subnets']):
            raise exc.EndpointGroupSubnetRemovalNotSupported()

    @log.log
    def update_endpoint_group_postcommit(self, context):
        # Three conditions where SG association needs to be changed
        # (a) list of endpoints change
        # (b) provided_contracts change
        # (c) consumed_contracts change
        epg_id = context.current['id']
        new_endpoints = list(set(context.current['endpoints']) -
                             set(context.original['endpoints']))
        if (len(new_endpoints) > 0):
            self._update_sgs_on_ep_with_epg(context, epg_id,
                                            new_endpoints, "ASSOCIATE")
        removed_endpoints = list(set(context.original['endpoints']) -
                                 set(context.current['endpoints']))
        if (len(removed_endpoints) > 0):
            self._update_sgs_on_ep_with_epg(context, epg_id,
                                            new_endpoints, "DISASSOCIATE")
        # generate a list of contracts (SGs) to update on the EPG
        orig_provided_contracts = context.original['provided_contracts']
        curr_provided_contracts = context.current['provided_contracts']
        new_provided_contracts = list(set(curr_provided_contracts) -
                                      set(orig_provided_contracts))
        orig_consumed_contracts = context.original['consumed_contracts']
        curr_consumed_contracts = context.current['consumed_contracts']
        new_consumed_contracts = list(set(curr_consumed_contracts) -
                                      set(orig_consumed_contracts))
        # if EPG associated contracts are updated, we need to update
        # the policy rules, then assoicate SGs to ports
        if (len(new_provided_contracts) > 0):
            subnets = context.current['subnets']
            self._assoc_sg_to_epg(context, subnets, new_provided_contracts)
        if (len(new_provided_contracts) > 0 or
            len(new_consumed_contracts) > 0):
            self._update_sgs_on_epg(context, epg_id,
                                    new_provided_contracts,
                                    new_consumed_contracts, "ASSOCIATE")

        # generate the list of contracts (SGs) to remove from current ports
        removed_provided_contracts = list(set(orig_provided_contracts) -
                                          set(curr_provided_contracts))
        removed_consumed_contracts = list(set(orig_consumed_contracts) -
                                          set(curr_consumed_contracts))
        # TODO(s3wong): need to remove existing SGs consumed by other EPG
        # need to add additional mappings (a contract back pointer to
        # EPGs that consume such contract)
        if (len(removed_provided_contracts) > 0 or
            len(removed_consumed_contracts) > 0):
            self._update_sgs_on_epg(context, epg_id,
                                    removed_provided_contracts,
                                    removed_consumed_contracts, "DISASSOCIATE")

    @log.log
    def delete_endpoint_group_precommit(self, context):
        pass

    @log.log
    def delete_endpoint_group_postcommit(self, context):
        l2p_id = context.current['l2_policy_id']
        l2p = context._plugin.get_l2_policy(context._plugin_context, l2p_id)
        l3p_id = l2p['l3_policy_id']
        l3p = context._plugin.get_l3_policy(context._plugin_context, l3p_id)
        router_id = l3p['routers'][0]
        for subnet_id in context.current['subnets']:
            self._cleanup_subnet(context, subnet_id, router_id)

    @log.log
    def create_l2_policy_precommit(self, context):
        pass

    @log.log
    def create_l2_policy_postcommit(self, context):
        if not context.current['network_id']:
            self._use_implicit_network(context)

    @log.log
    def update_l2_policy_precommit(self, context):
        pass

    @log.log
    def update_l2_policy_postcommit(self, context):
        pass

    @log.log
    def delete_l2_policy_precommit(self, context):
        pass

    @log.log
    def delete_l2_policy_postcommit(self, context):
        network_id = context.current['network_id']
        self._cleanup_network(context, network_id)

    @log.log
    def create_l3_policy_precommit(self, context):
        if len(context.current['routers']) > 1:
            raise exc.L3PolicyMultipleRoutersNotSupported()

    @log.log
    def create_l3_policy_postcommit(self, context):
        if not context.current['routers']:
            self._use_implicit_router(context)

    @log.log
    def update_l3_policy_precommit(self, context):
        if context.current['routers'] != context.original['routers']:
            raise exc.L3PolicyRoutersUpdateNotSupported()

    @log.log
    def update_l3_policy_postcommit(self, context):
        pass

    @log.log
    def delete_l3_policy_precommit(self, context):
        pass

    @log.log
    def delete_l3_policy_postcommit(self, context):
        for router_id in context.current['routers']:
            self._cleanup_router(context, router_id)

    @log.log
    def create_policy_classifier_precommit(self, context):
        pass

    @log.log
    def create_policy_classifier_postcommit(self, context):
        pass

    @log.log
    def update_policy_classifier_precommit(self, context):
        pass

    @log.log
    def update_policy_classifier_postcommit(self, context):
        pass

    @log.log
    def delete_policy_classifier_precommit(self, context):
        pass

    @log.log
    def delete_policy_classifier_postcommit(self, context):
        pass

    @log.log
    def create_policy_action_precommit(self, context):
        pass

    @log.log
    def create_policy_action_postcommit(self, context):
        pass

    @log.log
    def update_policy_action_precommit(self, context):
        pass

    @log.log
    def update_policy_action_postcommit(self, context):
        pass

    @log.log
    def delete_policy_action_precommit(self, context):
        pass

    @log.log
    def delete_policy_action_postcommit(self, context):
        pass

    @log.log
    def create_policy_rule_precommit(self, context):
        pass

    @log.log
    def create_policy_rule_postcommit(self, context):
        pass

    @log.log
    def update_policy_rule_precommit(self, context):
        pass

    @log.log
    def update_policy_rule_postcommit(self, context):
        pass

    @log.log
    def delete_policy_rule_precommit(self, context):
        pass

    @log.log
    def delete_policy_rule_postcommit(self, context):
        pass

    @log.log
    def create_contract_precommit(self, context):
        pass

    @log.log
    def create_contract_postcommit(self, context):
        # creating SGs
        contract_id = context.current['id']
        consumed_sg = self._create_contract_sg(context, 'consumed')
        provided_sg = self._create_contract_sg(context, 'provided')
        consumed_sg_id = consumed_sg['id']
        provided_sg_id = provided_sg['id']
        self._set_contract_sg_mapping(context._plugin_context.session,
                                      contract_id, consumed_sg_id,
                                      provided_sg_id)

    @log.log
    def update_contract_precommit(self, context):
        pass

    @log.log
    def update_contract_postcommit(self, context):
        pass

    @log.log
    def delete_contract_precommit(self, context):
        pass

    @log.log
    def delete_contract_postcommit(self, context):
        pass

    def _use_implicit_port(self, context):
        epg_id = context.current['endpoint_group_id']
        epg = context._plugin.get_endpoint_group(context._plugin_context,
                                                 epg_id)
        l2p_id = epg['l2_policy_id']
        l2p = context._plugin.get_l2_policy(context._plugin_context, l2p_id)
        attrs = {'tenant_id': context.current['tenant_id'],
                 'name': 'ep_' + context.current['name'],
                 'network_id': l2p['network_id'],
                 'mac_address': attributes.ATTR_NOT_SPECIFIED,
                 'fixed_ips': attributes.ATTR_NOT_SPECIFIED,
                 'device_id': '',
                 'device_owner': '',
                 'admin_state_up': True}
        port = self._create_port(context, attrs)
        port_id = port['id']
        self._mark_port_owned(context._plugin_context.session, port_id)
        context.set_port_id(port_id)

    def _cleanup_port(self, context, port_id):
        if self._port_is_owned(context._plugin_context.session, port_id):
            self._delete_port(context, port_id)

    def _use_implicit_subnet(self, context):
        # REVISIT(rkukura): This is a temporary allocation algorithm
        # that depends on an exception being raised when the subnet
        # being created is already in use. A DB allocation table for
        # the pool of subnets, or at least a more efficient way to
        # test if a subnet is in-use, may be needed.
        l2p_id = context.current['l2_policy_id']
        l2p = context._plugin.get_l2_policy(context._plugin_context, l2p_id)
        l3p_id = l2p['l3_policy_id']
        l3p = context._plugin.get_l3_policy(context._plugin_context, l3p_id)
        pool = netaddr.IPNetwork(l3p['ip_pool'])
        for cidr in pool.subnet(l3p['subnet_prefix_length']):
            try:
                attrs = {'tenant_id': context.current['tenant_id'],
                         'name': 'epg_' + context.current['name'],
                         'network_id': l2p['network_id'],
                         'ip_version': l3p['ip_version'],
                         'cidr': cidr.__str__(),
                         'enable_dhcp': True,
                         'gateway_ip': attributes.ATTR_NOT_SPECIFIED,
                         'allocation_pools': attributes.ATTR_NOT_SPECIFIED,
                         'dns_nameservers': attributes.ATTR_NOT_SPECIFIED,
                         'host_routes': attributes.ATTR_NOT_SPECIFIED}
                subnet = self._create_subnet(context, attrs)
                subnet_id = subnet['id']
                try:
                    router_id = l3p['routers'][0]
                    interface_info = {'subnet_id': subnet_id}
                    self._add_router_interface(context, router_id,
                                               interface_info)
                    self._mark_subnet_owned(context._plugin_context.session,
                                            subnet_id)
                    context.add_subnet(subnet_id)
                    return
                except Exception:
                    LOG.exception(_("add_subnet failed"))
                    self._delete_subnet(context, subnet['id'])
            except Exception:
                LOG.exception(_("create_subnet failed"))
        raise exc.NoSubnetAvailable()

    def _use_explicit_subnet(self, context, subnet_id, router_id):
        interface_info = {'subnet_id': subnet_id}
        self._add_router_interface(context, router_id, interface_info)

    def _cleanup_subnet(self, context, subnet_id, router_id):
        interface_info = {'subnet_id': subnet_id}
        self._remove_router_interface(context, router_id, interface_info)
        if self._subnet_is_owned(context._plugin_context.session, subnet_id):
            self._delete_subnet(context, subnet_id)

    def _use_implicit_network(self, context):
        attrs = {'tenant_id': context.current['tenant_id'],
                 'name': 'l2p_' + context.current['name'],
                 'admin_state_up': True,
                 'shared': False}
        network = self._create_network(context, attrs)
        network_id = network['id']
        self._mark_network_owned(context._plugin_context.session, network_id)
        context.set_network_id(network_id)

    def _cleanup_network(self, context, network_id):
        if self._network_is_owned(context._plugin_context.session, network_id):
            self._delete_network(context, network_id)

    def _use_implicit_router(self, context):
        attrs = {'tenant_id': context.current['tenant_id'],
                 'name': 'l3p_' + context.current['name'],
                 'external_gateway_info': None,
                 'admin_state_up': True}
        router = self._create_router(context, attrs)
        router_id = router['id']
        self._mark_router_owned(context._plugin_context.session, router_id)
        context.add_router(router_id)

    def _cleanup_router(self, context, router_id):
        if self._router_is_owned(context._plugin_context.session, router_id):
            self._delete_router(context, router_id)

    def _create_contract_sg(self, context, sg_name_prefix):
        # This method sets up the attributes of security group
        attrs = {'tenant_id': context.current['tenant_id'],
                 'name': sg_name_prefix + '_' + context.current['name'],
                 'description': '',
                 'security_group_rules': ''}
        return self._create_sg(context, attrs)

    def _handle_contracts(self, context):
        # This method handles contract => SG mapping
        # context is EPG context

        # for all consumed contracts, simply associate
        # each EP's port from the EPG
        # rules are expected to be filled out already
        consumed_contracts = context.current['consumed_contracts']
        provided_contracts = context.current['provided_contracts']
        subnets = context.current['subnets']
        epg_id = context.current['id']
        self._assoc_sg_to_epg(context, subnets, provided_contracts)
        self._update_sgs_on_epg(context, epg_id, provided_contracts,
                                consumed_contracts, "ASSOCIATE")

    # The following methods perform the necessary subset of
    # functionality from neutron.api.v2.base.Controller.
    #
    # REVISIT(rkukura): Can we just use the WSGI Controller?  Using
    # neutronclient is also a possibility, but presents significant
    # issues to unit testing as well as overhead and failure modes.

    def _create_port(self, context, attrs):
        return self._create_resource(self._core_plugin,
                                     context._plugin_context,
                                     'port', attrs)

    def _update_port(self, context, port_id, attrs):
        return self._update_resource(self._core_plugin,
                                     context._plugin_context,
                                     'port', port_id, attrs)

    def _delete_port(self, context, port_id):
        self._delete_resource(self._core_plugin,
                              context._plugin_context,
                              'port', port_id)

    def _create_subnet(self, context, attrs):
        return self._create_resource(self._core_plugin,
                                     context._plugin_context,
                                     'subnet', attrs)

    def _delete_subnet(self, context, subnet_id):
        self._delete_resource(self._core_plugin,
                              context._plugin_context,
                              'subnet', subnet_id)

    def _create_network(self, context, attrs):
        return self._create_resource(self._core_plugin,
                                     context._plugin_context,
                                     'network', attrs)

    def _delete_network(self, context, network_id):
        self._delete_resource(self._core_plugin,
                              context._plugin_context,
                              'network', network_id)

    def _create_router(self, context, attrs):
        return self._create_resource(self._l3_plugin,
                                     context._plugin_context,
                                     'router', attrs)

    def _add_router_interface(self, context, router_id, interface_info):
        self._l3_plugin.add_router_interface(context._plugin_context,
                                             router_id, interface_info)

    def _remove_router_interface(self, context, router_id, interface_info):
        self._l3_plugin.remove_router_interface(context._plugin_context,
                                                router_id, interface_info)

    def _delete_router(self, context, router_id):
        self._delete_resource(self._l3_plugin,
                              context._plugin_context,
                              'router', router_id)

    def _create_sg(self, context, attrs):
        return self._create_resource(self._core_plugin,
                                     context._plugin_context,
                                     'security_group', attrs)

    def _update_sg(self, context, sg_id, attrs):
        return self._update_resouce(self._core_plugin,
                                    context._plugin_context,
                                    'security_group', sg_id, attrs)

    def _delete_sg(self, context, sg_id):
        self._delete_resource(self._core_plugin,
                              context._plugin_context,
                              'security_group', sg_id)

    def _create_sg_rule(self, context, attrs):
        return self._create_resource(self._core_plugin,
                                     context._plugin_context,
                                     'security_group_rule', attrs)

    def _update_sg_rule(self, context, sg_rule_id, attrs):
        return self._update_resource(self._core_plugin,
                                     context._plugin_context,
                                     'security_group_rule', sg_rule_id,
                                     attrs)

    def _delete_sg_rule(self, context, sg_rule_id):
        self._delete_resource(self._core_plugin,
                              context._plugin_context,
                              'security_group_rule', sg_rule_id)

    def _create_resource(self, plugin, context, resource, attrs):
        # REVISIT(rkukura): Do create.start notification?
        # REVISIT(rkukura): Check authorization?
        # REVISIT(rkukura): Do quota?
        action = 'create_' + resource
        obj_creator = getattr(plugin, action)
        obj = obj_creator(context, {resource: attrs})
        self._nova_notifier.send_network_change(action, {}, {resource: obj})
        # REVISIT(rkukura): Do create.end notification?
        if cfg.CONF.dhcp_agent_notification:
            self._dhcp_agent_notifier.notify(context,
                                             {resource: obj},
                                             resource + '.create.end')
        return obj

    def _update_resource(self, plugin, context, resource, resource_id, attrs):
        # REVISIT(rkukura): Do update.start notification?
        # REVISIT(rkukura): Check authorization?
        obj_getter = getattr(plugin, 'get_' + resource)
        orig_obj = obj_getter(context, resource_id)
        action = 'update_' + resource
        obj_updater = getattr(plugin, action)
        obj = obj_updater(context, resource_id, {resource: attrs})
        self._nova_notifier.send_network_change(action, orig_obj,
                                                {resource: obj})
        # REVISIT(rkukura): Do update.end notification?
        if cfg.CONF.dhcp_agent_notification:
            self._dhcp_agent_notifier.notify(context,
                                             {resource: obj},
                                             resource + '.update.end')
        return obj

    def _delete_resource(self, plugin, context, resource, resource_id):
        # REVISIT(rkukura): Do delete.start notification?
        # REVISIT(rkukura): Check authorization?
        obj_getter = getattr(plugin, 'get_' + resource)
        obj = obj_getter(context, resource_id)
        action = 'delete_' + resource
        obj_deleter = getattr(plugin, action)
        obj_deleter(context, resource_id)
        self._nova_notifier.send_network_change(action, {}, {resource: obj})
        # REVISIT(rkukura): Do delete.end notification?
        if cfg.CONF.dhcp_agent_notification:
            self._dhcp_agent_notifier.notify(context,
                                             {resource: obj},
                                             resource + '.delete.end')

    @property
    def _core_plugin(self):
        # REVISIT(rkukura): Need initialization method after all
        # plugins are loaded to grab and store plugin.
        return manager.NeutronManager.get_plugin()

    @property
    def _l3_plugin(self):
        # REVISIT(rkukura): Need initialization method after all
        # plugins are loaded to grab and store plugin.
        plugins = manager.NeutronManager.get_service_plugins()
        l3_plugin = plugins.get(pconst.L3_ROUTER_NAT)
        if not l3_plugin:
            LOG.error(_("No L3 router service plugin found."))
            raise exc.GroupPolicyDeploymentError()
        return l3_plugin

    @property
    def _dhcp_agent_notifier(self):
        # REVISIT(rkukura): Need initialization method after all
        # plugins are loaded to grab and store notifier.
        if not self._cached_agent_notifier:
            agent_notifiers = getattr(self._core_plugin, 'agent_notifiers', {})
            self._cached_agent_notifier = (
                agent_notifiers.get(const.AGENT_TYPE_DHCP) or
                dhcp_rpc_agent_api.DhcpAgentNotifyAPI())
        return self._cached_agent_notifier

    def _mark_port_owned(self, session, port_id):
        with session.begin(subtransactions=True):
            owned = OwnedPort(port_id=port_id)
            session.add(owned)

    def _port_is_owned(self, session, port_id):
        with session.begin(subtransactions=True):
            return (session.query(OwnedPort).
                    filter_by(port_id=port_id).
                    first() is not None)

    def _mark_subnet_owned(self, session, subnet_id):
        with session.begin(subtransactions=True):
            owned = OwnedSubnet(subnet_id=subnet_id)
            session.add(owned)

    def _subnet_is_owned(self, session, subnet_id):
        with session.begin(subtransactions=True):
            return (session.query(OwnedSubnet).
                    filter_by(subnet_id=subnet_id).
                    first() is not None)

    def _mark_network_owned(self, session, network_id):
        with session.begin(subtransactions=True):
            owned = OwnedNetwork(network_id=network_id)
            session.add(owned)

    def _network_is_owned(self, session, network_id):
        with session.begin(subtransactions=True):
            return (session.query(OwnedNetwork).
                    filter_by(network_id=network_id).
                    first() is not None)

    def _mark_router_owned(self, session, router_id):
        with session.begin(subtransactions=True):
            owned = OwnedRouter(router_id=router_id)
            session.add(owned)

    def _router_is_owned(self, session, router_id):
        with session.begin(subtransactions=True):
            return (session.query(OwnedRouter).
                    filter_by(router_id=router_id).
                    first() is not None)

    def _set_contract_sg_mapping(self, session, contract_id,
                                 consumed_sg_id, provided_sg_id):
        with session.begin(subtransactions=True):
            mapping = ContractSGsMapping(contract_id=contract_id,
                                         consumed_sg_id=consumed_sg_id,
                                         provided_sg_id=provided_sg_id)
            session.add(mapping)

    def _get_contract_sg_mapping(self, session, contract_id):
        with session.begin(subtransactions=True):
            return (session.query(ContractSGsMapping).
                    filter_by(contract_id=contract_id).one())

    # This is an exact replica of method in group_policy_db
    def _get_min_max_ports_from_range(self, port_range):
        if not port_range:
            return [None, None]
        min_port, sep, max_port = port_range.partition(":")
        if not max_port:
            max_port = min_port
        return [int(min_port), int(max_port)]

    def _set_sg_rule(self, context, sg_id, protocol, port_range, ip_prefix):
        port_min, port_max = self._get_min_max_ports_from_range(port_range)
        attrs = {'tenant_id': context.current['tenant_id'],
                 'name': 'gp_mapped_rule_' + context.current['name'],
                 'security_group_id': sg_id,
                 'direction': 'egress',
                 'ethertype': const.IPv4,
                 'protocol': protocol,
                 'port_range_min': port_min,
                 'port_range_max': port_max,
                 'remote_ip_prefix': ip_prefix,
                 'remote_group_id': None}
        return (self._create_sg_rule(context, attrs))

    def _assoc_sgs_to_ep(self, context, ep_id, sg_list):
        ep = context._plugin.get_endpoint(context._plugin_context, ep_id)
        port_id = ep['port_id']
        port = self._core_plugin.get_port(context._plugin_context, port_id)
        cur_sg_list = port[ext_sg.SECURITYGROUPS]
        new_sg_list = cur_sg_list + sg_list
        port[ext_sg.SECURITYGROUPS] = new_sg_list
        self._update_port(context, port_id, port)

    def _disassoc_sgs_from_ep(self, context, ep_id, sg_list):
        ep = context._plugin.get_endpoint(context._plugin_context, ep_id)
        port_id = ep['port_id']
        port = self._core_plugin.get_port(context._plugin_context, port_id)
        cur_sg_list = port[ext_sg.SECURITYGROUPS]
        new_sg_list = list(set(cur_sg_list) - set(sg_list))
        port[ext_sg.SECURITYGROUPS] = new_sg_list
        self._update_port(context, port_id, port)

    def _generate_list_of_sg_from_epg(self, context, epg_id):
        epg = context._plugin.get_endpoint_group(context._plugin_context,
                                                 epg_id)
        provided_contracts = epg['provided_contracts']
        consumed_contracts = epg['consumed_contracts']
        return(self._generate_list_sg_from_contract_list(context,
                                                         provided_contracts,
                                                         consumed_contracts))

    def _generate_list_sg_from_contract_list(self, context,
                                             provided_contracts,
                                             consumed_contracts):
        ret_list = []
        for contract_id in provided_contracts:
            contract_sg_mappings = self._get_contract_sg_mapping(
                                    context._plugin_context.session,
                                    contract_id)
            provided_sg_id = contract_sg_mappings['provided_sg_id']
            ret_list.append(provided_sg_id)

        for contract_id in consumed_contracts:
            contract_sg_mappings = self._get_contract_sg_mapping(
                                    context._plugin_context.session,
                                    contract_id)
            consumed_sg_id = contract_sg_mappings['consumed_sg_id']
            ret_list.append(consumed_sg_id)
        return ret_list

    def _assoc_epg_sg_to_ep(self, context, ep_id, epg_id):
        sg_list = self._generate_list_of_sg_from_epg(context, epg_id)
        self._assoc_sgs_to_ep(context, ep_id, sg_list)

    def _disassoc_epg_sg_from_ep(self, context, ep_id, epg_id):
        sg_list = self._generate_list_of_sg_from_epg(context, epg_id)
        self._disassoc_sgs_from_ep(context, ep_id, sg_list)

    def _update_sgs_on_ep_with_epg(self, context, epg_id, new_ep_list, op):
        sg_list = self._generate_list_of_sg_from_epg(context, epg_id)
        for ep_id in new_ep_list:
            if (op == "ASSOCIATE"):
                self._assoc_sgs_to_ep(context, ep_id, sg_list)
            else:
                self._disassoc_sgs_from_ep(context, ep_id, sg_list)

    def _update_sgs_on_epg(self, context, epg_id,
                           provided_contracts, consumed_contracts, op):
        sg_list = self._generate_list_sg_from_contract_list(context,
                                                            provided_contracts,
                                                            consumed_contracts)
        epg = context._plugin.get_endpoint_group(context._plugin_context,
                                                 epg_id)
        endpoint_list = epg['endpoints']
        for ep_id in endpoint_list:
            if (op == "ASSOCIATE"):
                self._assoc_sgs_to_ep(context, ep_id, sg_list)
            else:
                self._disassoc_sgs_from_ep(context, ep_id, sg_list)

    # context should be EPG
    def _assoc_sg_to_epg(self, context, subnets, provided_contracts):
        for contract_id in provided_contracts:
            contract = context._plugin.get_contract(context._plugin_context,
                                                    contract_id)
            contract_sg_mappings = self._get_contract_sg_mapping(
                                    context._plugin_context.session,
                                    contract_id)
            consumed_sg_id = contract_sg_mappings['consumed_sg_id']
            provided_sg_id = contract_sg_mappings['provided_sg_id']
            cidr_list = []
            for subnet_id in subnets:
                subnet = self._core_plugin.get_subnet(context._plugin_context,
                                                    subnet_id)
                cidr = subnet['cidr']
                cidr_list.append(cidr)

            policy_rules = contract['policy_rules']
            for policy_rule_id in policy_rules:
                policy_rule = context._plugin.get_policy_rule(
                                                context._plugin_context,
                                                policy_rule_id)
                classifier_id = policy_rule['policy_classifier_id']
                classifier = context._plugin.get_policy_classifier(
                                                    context._plugin_context,
                                                    classifier_id)
                classifier_dir = classifier['direction']
                protocol = classifier['protocol']
                port_range = classifier['port_range']

                # if contract is provided by EPG, we do the following:
                # If classifier direction is OUT or BI, set the rules
                # in provided_sg, then associate it to the port
                # if the classifier direction is IN or BI, the EPG's
                # group of subnets need to be set up on rules for
                # the consumed_sg
                if classifier_dir == gconst.GP_DIRECTION_BI:
                    self._set_sg_rule(context, provided_sg_id,
                                      protocol, port_range, '0.0.0.0/0')
                    for cidr in cidr_list:
                        self._set_sg_rule(context, consumed_sg_id,
                                          protocol, port_range, cidr)
                elif classifier_dir == gconst.GP_DIRECTION_IN:
                    for cidr in cidr_list:
                        self._set_sg_rule(context, consumed_sg_id,
                                          protocol, port_range, cidr)
                else:
                    self._set_sg_rule(context, provided_sg_id,
                                      protocol, port_range, '0.0.0.0/0')
