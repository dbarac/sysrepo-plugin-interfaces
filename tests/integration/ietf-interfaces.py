#
# telekom / sysrepo-plugin-system
#
# This program is made available under the terms of the
# BSD 3-Clause license which is available at
# https://opensource.org/licenses/BSD-3-Clause
#
# SPDX-FileCopyrightText: 2021 Deutsche Telekom AG
# SPDX-FileContributor: Sartura Ltd.
#
# SPDX-License-Identifier: BSD-3-Clause
#

import unittest
import sysrepo
import os
import subprocess
import signal
import time
import json
import operator
import re


class InterfacesTestCase(unittest.TestCase):
    def setUp(self):
        plugin_path = os.environ.get('SYSREPO_INTERFACES_PLUGIN_PATH')
        if plugin_path is None:
            self.fail(
                "SYSREPO_INTERFACES_PLUGIN_PATH has to point to interfaces plugin executable")

        self.plugin = subprocess.Popen(
            [plugin_path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL)
        self.conn = sysrepo.SysrepoConnection()
        self.session = self.conn.start_session("running")
        time.sleep(2)

        self.initial_data = self.session.get_data_ly(
            '/ietf-interfaces:interfaces')

    def tearDown(self):
        self.session.stop()
        self.conn.disconnect()
        self.plugin.send_signal(signal.SIGINT)
        self.plugin.wait()

    def load_initial_data(self, path):
        ctx = self.conn.get_ly_ctx()

        self.session.replace_config_ly(None, "ietf-interfaces")
        with open(path, "r") as f:
            data = f.read()
            data = ctx.parse_data_mem(data, "xml", config=True, strict=True)
            self.session.replace_config_ly(data, "ietf-interfaces")

    def edit_config(self, path):
        ctx = self.conn.get_ly_ctx()

        with open(path, "r") as f:
            data = f.read()
            data = ctx.parse_data_mem(data, "xml", config=True, strict=True)
            self.session.edit_batch_ly(data)
            data.free()

        self.session.apply_changes()

    def edit_config_direct(self, xml, config=True, strict=True, **parser_flags):
        ctx = self.conn.get_ly_ctx()

        data = xml
        data = ctx.parse_data_mem(data, "xml", config=config, strict=strict, **parser_flags)
        self.session.edit_batch_ly(data)
        data.free()

        self.session.apply_changes()

    def assertEqual(self, first, second, msg=None):
        try:
            super().assertEqual(first, second, msg)
        except AssertionError as e:
            self.session.replace_config_ly(
                self.initial_data, 'ietf-interfaces')
            raise

    def assertIn(self, member, container, msg=None):
        try:
            super().assertIn(member, container, msg)
        except AssertionError as e:
            self.session.replace_config_ly(
                self.initial_data, 'ietf-interfaces')
            raise

    def assertTrue(self, expr, msg=None):
        try:
            super().assertTrue(expr, msg)
        except AssertionError as e:
            self.session.replace_config_ly(
                self.initial_data, 'ietf-interfaces')
            raise


class InterfaceTestCase(InterfacesTestCase):
    def test_interface_name_get(self):
        """ Check if datastore names match system network interface names """
        data = self.session.get_data_ly('/ietf-interfaces:interfaces')
        interfaces = set(map(operator.itemgetter('name'), json.loads(
            data.print_mem("json"))['ietf-interfaces:interfaces']['interface']))

        real_interfaces = set(os.listdir('/sys/class/net'))

        self.assertEqual(real_interfaces, interfaces,
                         "plugin and system interface list differ")

        data.free()

    def test_interface_description(self):
        """ Check if descriptions are empty """
        data = self.session.get_data_ly('/ietf-interfaces:interfaces')
        interfaces = list(map(operator.itemgetter('description'), json.loads(
            data.print_mem("json"))['ietf-interfaces:interfaces']['interface']))

        for i in interfaces:
            self.assertEqual(
                i, "", "non empty interface description at startup")

        data.free()

    def test_interface_supported_types(self):
        """ Check if only supported types are present """

        data = self.session.get_data_ly('/ietf-interfaces:interfaces')
        interface = json.loads(data.print_mem('json'))[
            'ietf-interfaces:interfaces']['interface']

        types = map(operator.itemgetter('type'), interface)
        types = set(typ.split(':')[-1] for typ in types)

        supported_types = {
            'softwareLoopback',
            'ethernetCsmacd',
            'l2vlan',
            'other',
        }

        self.assertTrue(types.issubset(supported_types),
                        'type not based on the supported iana-if-type model')

        data.free()

    def test_interface_status(self):
        """ Check status of interfaces """

        data = self.session.get_data_ly('/ietf-interfaces:interfaces')
        interface = json.loads(data.print_mem('json'))[
            'ietf-interfaces:interfaces']['interface']

        names = map(operator.itemgetter('name'), interface)
        names = tuple(names)
        enabled = map(operator.itemgetter('enabled'), interface)

        states = dict(zip(names, enabled))

        for name, enabled in states.items():
            with open(f'/sys/class/net/{name}/operstate') as f:
                real_enabled = True if f.read().strip() == 'up' else False
                self.assertEqual(real_enabled, enabled,
                                 'plugin and system interface state differ')

        data.free()

    def test_interface_lo_enable(self):
        """ Attempt to enable loopback interface """

        self.edit_config('data/loopback_enabled.xml')

        expected_lo_enabled = \
            '<interfaces xmlns="urn:ietf:params:xml:ns:yang:ietf-interfaces"><interface>' \
            '<name>lo</name><enabled>true</enabled>' \
            '</interface></interfaces>'

        data = self.session.get_data_ly(
            '/ietf-interfaces:interfaces/interface[name="lo"]/enabled')
        lo_enabled = data.print_mem('xml')

        self.assertEqual(expected_lo_enabled, lo_enabled,
                         'loopback interface status not enabled (up)')

        with open('/sys/class/net/lo/operstate') as f:
            state = f.read().strip()
            self.assertEqual(state, 'up', 'system interface state unchanged')

        data.free()
        self.session.replace_config_ly(self.initial_data, 'ietf-interfaces')

    def test_interface_lo_description(self):
        """ Attempt to change loopback interface description """

        self.edit_config('data/loopback_description.xml')

        expected_lo_description = \
            '<interfaces xmlns="urn:ietf:params:xml:ns:yang:ietf-interfaces"><interface>' \
            '<name>lo</name><description>test</description>' \
            '</interface></interfaces>'

        data = self.session.get_data_ly(
            '/ietf-interfaces:interfaces/interface[name="lo"]/description')
        lo_description = data.print_mem('xml')

        self.assertEqual(expected_lo_description, lo_description,
                         'loopback interface description unchanged')

        data.free()
        self.session.replace_config_ly(self.initial_data, 'ietf-interfaces')

    def test_interface_dummy(self):
        """ Attempt to add a dummy interface """

        self.edit_config('data/dummy.xml')

        expected_dummy = \
            '<interfaces xmlns="urn:ietf:params:xml:ns:yang:ietf-interfaces"><interface>' \
            '<name>dummy</name><type xmlns:ianaift="urn:ietf:params:xml:ns:yang:iana-if-type">' \
            'ianaift:other</type><enabled>true</enabled></interface></interfaces>'

        data = self.session.get_data_ly(
            '/ietf-interfaces:interfaces/interface[name="dummy"]')
        dummy = data.print_mem('xml')

        self.assertEqual(expected_dummy, dummy,
                         'dummy interface not added')

        real_interfaces = set(os.listdir('/sys/class/net'))
        self.assertIn('dummy', real_interfaces)

        with open('/sys/class/net/dummy/operstate') as f:
            operstate = f.read().strip()
            self.assertEqual(operstate, 'up')

        data.free()
        self.session.replace_config_ly(self.initial_data, 'ietf-interfaces')

    def test_interface_lo_rename(self):
        """Make sure that attempts to rename the loopback interface fail."""

        try:
            with self.assertRaises(sysrepo.errors.SysrepoCallbackFailedError, msg="loopback renaming did not fail"):
                self.edit_config("data/loopback_rename.xml")
        finally:
            self.session.replace_config_ly(self.initial_data, "ietf-interfaces")

    def test_interface_lo_change_type(self):
        """Make sure that attempts to change the loopback interface type fail."""

        try:
            with self.assertRaises(sysrepo.errors.SysrepoCallbackFailedError, msg="loopback type change did not fail"):
                self.edit_config("data/loopback_change_type.xml")
        finally:
            self.session.replace_config_ly(self.initial_data, "ietf-interfaces")


class IpTestCase(InterfacesTestCase):
    def test_ip_addr_prefix_ipv4(self):
        """ Attempt to set loopback interface IPv4 address and subnet via prefix """

        self.edit_config('data/loopback_addr_prefix_ipv4.xml')

        expected_ip_address = \
            '<interfaces xmlns="urn:ietf:params:xml:ns:yang:ietf-interfaces"><interface>' \
            '<name>lo</name><ipv4 xmlns="urn:ietf:params:xml:ns:yang:ietf-ip">' \
            '<address><ip>127.0.0.0</ip><prefix-length>8</prefix-length></address></ipv4></interface></interfaces>'

        data = self.session.get_data_ly(
            '/ietf-interfaces:interfaces/interface[name="lo"]/ietf-ip:ipv4/address[ip="127.0.0.0"]')
        ip_address = data.print_mem('xml')

        self.assertEqual(expected_ip_address, ip_address)

        p = subprocess.run(['ip', 'addr', 'show', 'lo'],
                           capture_output=True, encoding="ascii")

        real_ips = re.findall('(?<=inet\s)[^\s]+', p.stdout)

        self.assertIn('127.0.0.1/8', real_ips,
                      'ipv4 loopback address not found')

        data.free()
        self.session.replace_config_ly(self.initial_data, 'ietf-interfaces')

    def test_ip_addr_netmask_ipv4(self):
        """ Attempt to set loopback interface IPv4 address and subnet via netmask """

        self.edit_config('data/loopback_addr_netmask_ipv4.xml')

        expected_ip_address = \
            '<interfaces xmlns="urn:ietf:params:xml:ns:yang:ietf-interfaces"><interface>' \
            '<name>lo</name><ipv4 xmlns="urn:ietf:params:xml:ns:yang:ietf-ip">' \
            '<address><ip>127.0.0.0</ip><netmask>255.0.0.0</netmask></address></ipv4></interface></interfaces>'

        data = self.session.get_data_ly(
            '/ietf-interfaces:interfaces/interface[name="lo"]/ietf-ip:ipv4/address[ip="127.0.0.0"]')
        ip_address = data.print_mem('xml')

        self.assertEqual(expected_ip_address, ip_address)

        p = subprocess.run(['ip', 'addr', 'show', 'lo'],
                           capture_output=True, encoding="ascii")

        real_ips = re.findall('(?<=inet\s)[^\s]+', p.stdout)

        self.assertIn('127.0.0.1/8', real_ips,
                      'ipv4 loopback address not found')

        data.free()
        self.session.replace_config_ly(self.initial_data, 'ietf-interfaces')

    def test_ip_addr_sub_ipv6(self):
        """ Attempt to set loopback interface IPv6 address and subnet via prefix """

        self.edit_config('data/loopback_addr_prefix_ipv6.xml')

        data = self.session.get_data_ly(
            '/ietf-interfaces:interfaces/interface[name="lo"]/ietf-ip:ipv6/address')
        ip_address = data.print_mem('xml')

        expected_ip_address = \
            '<interfaces xmlns="urn:ietf:params:xml:ns:yang:ietf-interfaces"><interface>' \
            '<name>lo</name><ipv6 xmlns="urn:ietf:params:xml:ns:yang:ietf-ip">' \
            '<address><ip>::1</ip><prefix-length>128</prefix-length></address></ipv6></interface></interfaces>'

        self.assertEqual(expected_ip_address, ip_address)

        p = subprocess.run(['ip', 'addr', 'show', 'lo'],
                           capture_output=True, encoding="ascii")

        real_ips = re.findall('(?<=inet6\s)[^\s]+', p.stdout)

        self.assertIn('::1/128', real_ips, 'ipv6 loopback address not found')

        data.free()
        self.session.replace_config_ly(self.initial_data, 'ietf-interfaces')

    def test_ip_neighbor_ipv4(self):
        """ Attempt to add neighbor ipv4 address """

        # choose an interface other than lo
        interfaces = list(os.listdir('/sys/class/net'))
        interfaces.remove('lo')

        chosen = interfaces[0]
        chosen_data = self.session.get_data_ly(
            f'/ietf-interfaces:interfaces/interface[name="{chosen}"]/type')
        chosen_interface = json.loads(chosen_data.print_mem('json'))[
            'ietf-interfaces:interfaces']['interface']

        chosen_type = ''.join(map(operator.itemgetter(
            'type'), chosen_interface)).split(':')[-1]

        neigh_xml = \
            '<interfaces xmlns="urn:ietf:params:xml:ns:yang:ietf-interfaces"><interface>' \
            f'<name>{chosen}</name><type xmlns:ianaift="urn:ietf:params:xml:ns:yang:iana-if-type">' \
            f'ianaift:{chosen_type}</type><ipv4 xmlns="urn:ietf:params:xml:ns:yang:ietf-ip"><neighbor>' \
            '<ip>192.0.2.2</ip><link-layer-address>00:00:5e:00:53:ab</link-layer-address>' \
            '</neighbor></ipv4></interface></interfaces>'

        self.edit_config_direct(neigh_xml)

        data = self.session.get_data_ly(
            f'/ietf-interfaces:interfaces/interface[name="{chosen}"]/ietf-ip:ipv4/neighbor')
        neigh = data.print_mem('xml')

        self.assertIn(
            '<ip>192.0.2.2</ip><link-layer-address>00:00:5e:00:53:ab</link-layer-address>', neigh)

        p = subprocess.run(['ip', 'neigh', 'show', 'dev', chosen],
                           capture_output=True, encoding="ascii")

        self.assertIn('192.0.2.2 lladdr 00:00:5e:00:53:ab', p.stdout)

        chosen_data.free()
        data.free()
        self.session.replace_config_ly(self.initial_data, 'ietf-interfaces')

    def test_ip_neighbor_ipv6(self):
        """ Attempt to add neighbor ipv6 address """

        # choose an interface other than lo
        interfaces = list(os.listdir('/sys/class/net'))
        interfaces.remove('lo')

        chosen = interfaces[0]
        chosen_data = self.session.get_data_ly(
            f'/ietf-interfaces:interfaces/interface[name="{chosen}"]/type')
        chosen_interface = json.loads(chosen_data.print_mem('json'))[
            'ietf-interfaces:interfaces']['interface']

        chosen_type = ''.join(map(operator.itemgetter(
            'type'), chosen_interface)).split(':')[-1]

        neigh_xml = '<interfaces xmlns="urn:ietf:params:xml:ns:yang:ietf-interfaces"><interface>' \
            f'<name>{chosen}</name><type xmlns:ianaift="urn:ietf:params:xml:ns:yang:iana-if-type">' \
            f'ianaift:{chosen_type}</type><ipv6 xmlns="urn:ietf:params:xml:ns:yang:ietf-ip"><neighbor>' \
            '<ip>::ffff:c000:203</ip><link-layer-address>00:00:5e:00:53:ab</link-layer-address>' \
            '</neighbor></ipv6></interface></interfaces>'

        self.edit_config_direct(neigh_xml)

        data = self.session.get_data_ly(
            f'/ietf-interfaces:interfaces/interface[name="{chosen}"]/ietf-ip:ipv6/neighbor')
        neigh = data.print_mem('xml')

        self.assertIn(
            '<ip>::ffff:192.0.2.3</ip><link-layer-address>00:00:5e:00:53:ab</link-layer-address>', neigh)

        p = subprocess.run(['ip', 'neigh', 'show', 'dev', chosen],
                           capture_output=True, encoding="ascii")

        self.assertIn('::ffff:192.0.2.3 lladdr 00:00:5e:00:53:ab', p.stdout)

        chosen_data.free()
        data.free()
        self.session.replace_config_ly(self.initial_data, 'ietf-interfaces')

    def test_interface_mtu(self):
        """Attempt to change loopback interface mtu."""
        self.edit_config("data/loopback_mtu.xml")

        expected_mtu = \
        '<interfaces xmlns="urn:ietf:params:xml:ns:yang:ietf-interfaces">' \
        '<interface><name>lo</name><ipv4 xmlns="urn:ietf:params:xml:ns:yang:ietf-ip">' \
        '<mtu>12345</mtu></ipv4></interface></interfaces>'

        data = self.session.get_data_ly('/ietf-interfaces:interfaces/interface[name="lo"]/ietf-ip:ipv4/mtu')
        mtu = data.print_mem("xml")
        self.assertEqual(mtu, expected_mtu, "loopback MTU data is wrong")
        with open('/sys/class/net/lo/mtu') as f:
            mtu_value = f.read().strip()
            self.assertEqual(mtu_value, '12345', 'plugin and system ipv4 MTU values differ.')

        data.free()
        self.session.replace_config_ly(self.initial_data, "ietf-interfaces")

    def test_interface_ipv6_mtu(self):
        """Attempt to change loopback interface ipv6 mtu."""
        self.edit_config("data/loopback_ipv6_mtu.xml")

        expected_mtu = \
        '<interfaces xmlns="urn:ietf:params:xml:ns:yang:ietf-interfaces">' \
        '<interface><name>lo</name><ipv6 xmlns="urn:ietf:params:xml:ns:yang:ietf-ip">' \
        '<mtu>1300</mtu></ipv6></interface></interfaces>'

        data = self.session.get_data_ly('/ietf-interfaces:interfaces/interface[name="lo"]/ietf-ip:ipv6/mtu')
        mtu = data.print_mem("xml")
        self.assertEqual(mtu, expected_mtu, "loopback ipv6 MTU data is wrong")

        with open('/proc/sys/net/ipv6/conf/lo/mtu') as f:
            mtu_value = f.read().strip()
            self.assertEqual(mtu_value, '1300', 'plugin and system ipv6 MTU values differ.')

        data.free()
        self.session.replace_config_ly(self.initial_data, "ietf-interfaces")

    def test_interface_ipv4_forwarding(self):
        """Attempt to enable loopback ipv4 address forwarding."""
        self.edit_config("data/loopback_ipv4_forwarding.xml")

        expected_forwarding = \
        '<interfaces xmlns="urn:ietf:params:xml:ns:yang:ietf-interfaces">' \
        '<interface><name>lo</name><ipv4 xmlns="urn:ietf:params:xml:ns:yang:ietf-ip">' \
        '<forwarding>true</forwarding></ipv4></interface></interfaces>'

        data = self.session.get_data_ly('/ietf-interfaces:interfaces/interface[name="lo"]/ietf-ip:ipv4/forwarding')
        forwarding = data.print_mem("xml")
        self.assertEqual(forwarding, expected_forwarding, "loopback ipv4 forwarding data is wrong")

        with open('/proc/sys/net/ipv4/conf/lo/forwarding') as f:
            forwarding_configuration = f.read().strip()
            self.assertEqual(
                forwarding_configuration, '1',
                'plugin and system interface state differ, forwarding is not enabled for loopback'
            )

        data.free()
        self.session.replace_config_ly(self.initial_data, "ietf-interfaces")

    def test_interface_ipv6_forwarding(self):
        """Attempt to enable loopback ipv6 address forwarding."""
        self.edit_config("data/loopback_ipv6_forwarding.xml")

        expected_forwarding = \
        '<interfaces xmlns="urn:ietf:params:xml:ns:yang:ietf-interfaces">' \
        '<interface><name>lo</name><ipv6 xmlns="urn:ietf:params:xml:ns:yang:ietf-ip">' \
        '<forwarding>true</forwarding></ipv6></interface></interfaces>'

        data = self.session.get_data_ly('/ietf-interfaces:interfaces/interface[name="lo"]/ietf-ip:ipv6/forwarding')
        forwarding = data.print_mem("xml")
        self.assertEqual(forwarding, expected_forwarding, "loopback ipv6 forwarding data is wrong")

        with open('/proc/sys/net/ipv6/conf/lo/forwarding') as f:
            forwarding_configuration = f.read().strip()
            self.assertEqual(
                forwarding_configuration, '1',
                'plugin and system interface state differ, forwarding is not enabled for loopback'
            )

        data.free()
        self.session.replace_config_ly(self.initial_data, "ietf-interfaces")

    def test_subinterface(self):
        """
        Attempt to create a subinterface.

        The `sub-interfaces` feature of the `ietf-if-extensions` yang module should be
        enabled before running this test.
        """

        # select a parent interface
        all_interfaces = set(os.listdir('/sys/class/net/'))
        parent_interface = None
        for interface in all_interfaces:
            p = subprocess.run(['ip', 'link', 'show', interface], capture_output=True, encoding="ascii")
            if "link/ether" in p.stdout:
                parent_interface = interface
                break
        self.assertIsNotNone(parent_interface, "no ethernet interfaces are available")

        with open("data/subinterface.xml", "r") as f:
            data = f.read()
            data = data.format(PARENT_INTERFACE=parent_interface)
            self.edit_config_direct(data, config=False, edit=True)

        expected_subinterface = \
        '<interfaces xmlns="urn:ietf:params:xml:ns:yang:ietf-interfaces"><interface>' \
        '<name>{PARENT_INTERFACE}.sub1</name>' \
        '<type xmlns:ianaift="urn:ietf:params:xml:ns:yang:iana-if-type">ianaift:l2vlan</type>' \
        '<encapsulation xmlns="urn:ietf:params:xml:ns:yang:ietf-if-extensions">' \
        '<dot1q-vlan xmlns="urn:ietf:params:xml:ns:yang:ietf-if-vlan-encapsulation">' \
        '<outer-tag><tag-type xmlns:dot1q-types="urn:ieee:std:802.1Q:yang:ieee802-dot1q-types">' \
        'dot1q-types:s-vlan</tag-type><vlan-id>10</vlan-id></outer-tag><second-tag>' \
        '<tag-type xmlns:dot1q-types="urn:ieee:std:802.1Q:yang:ieee802-dot1q-types">' \
        'dot1q-types:c-vlan</tag-type><vlan-id>20</vlan-id></second-tag></dot1q-vlan></encapsulation>' \
        '<ipv6 xmlns="urn:ietf:params:xml:ns:yang:ietf-ip"><address><ip>2001:db8:10::1</ip>' \
        '<prefix-length>48</prefix-length></address>' \
        '<dup-addr-detect-transmits>0</dup-addr-detect-transmits></ipv6>' \
        '<parent-interface xmlns="urn:ietf:params:xml:ns:yang:ietf-if-extensions">' \
        '{PARENT_INTERFACE}</parent-interface>' \
        '</interface></interfaces>'.format(PARENT_INTERFACE=parent_interface)

        path = '/ietf-interfaces:interfaces/interface[name="{PARENT_INTERFACE}.sub1"]'
        data = self.session.get_data_ly(path.format(PARENT_INTERFACE=parent_interface))
        subinterface_data = data.print_mem("xml")

        self.assertEqual(subinterface_data, expected_subinterface, "subinterface data is wrong")

        subinterface_name = parent_interface + ".sub1"
        all_interfaces = set(os.listdir('/sys/class/net/'))
        self.assertTrue(subinterface_name in all_interfaces)

        # check ipv6 address and prefix-length
        p = subprocess.run(
            ['ip', 'addr', 'show', 'dev', subinterface_name], capture_output=True, encoding="ascii"
        )
        self.assertTrue("inet6 2001:db8:10::1/48" in p.stdout)

        # check vlan
        p = subprocess.run(
            ['ip', '-d', 'link', 'show', subinterface_name], capture_output=True, encoding="ascii"
        )
        self.assertTrue("vlan protocol 802.1ad id 10" in p.stdout)

        data.free()
        self.session.replace_config_ly(self.initial_data, "ietf-interfaces")

        # make sure the subinterface is deleted after replacing the configuration with initial data
        all_interfaces = set(os.listdir('/sys/class/net/'))
        self.assertTrue(subinterface_name not in all_interfaces)


if __name__ == '__main__':
    unittest.main()
