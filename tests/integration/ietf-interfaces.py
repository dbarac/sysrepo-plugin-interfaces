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

        self.initial_data = self.session.get_data_ly("/ietf-interfaces:interfaces")

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

    def edit_config(self, path, config=True, strict=True, **kwargs):
        ctx = self.conn.get_ly_ctx()

        with open(path, "r") as f:
            data = f.read()
            data = ctx.parse_data_mem(data, "xml", config=config, strict=strict, **kwargs)
            self.session.edit_batch_ly(data)
            data.free()

        self.session.apply_changes()

class InterfaceTestCase(InterfacesTestCase):
    def test_interface_name_get(self):
        data = self.session.get_data_ly('/ietf-interfaces:interfaces')
        interfaces = set(map(operator.itemgetter('name'), json.loads(data.print_mem("json"))['ietf-interfaces:interfaces']['interface']))

        real_interfaces = set(os.listdir('/sys/class/net'))

        self.assertEqual(real_interfaces, interfaces, "plugin and system interface list differ")

        data.free()

    def test_interface_description(self):
        data = self.session.get_data_ly('/ietf-interfaces:interfaces')
        interfaces = list(map(operator.itemgetter('description'), json.loads(data.print_mem("json"))['ietf-interfaces:interfaces']['interface']))

        for i in interfaces:
            self.assertEqual(i, "", "non empty interface description at startup")

        data.free()

    def test_interface_lo_rename(self):
        """Make sure that attempts to rename the loopback interface fail."""

        with self.assertRaises(sysrepo.errors.SysrepoCallbackFailedError, msg="loopback renaming did not fail"):
            self.edit_config("data/loopback_rename.xml")

        self.session.replace_config_ly(self.initial_data, "ietf-interfaces")

    def test_interface_lo_change_type(self):
        """Make sure that attempts to change the loopback interface type fail."""

        with self.assertRaises(sysrepo.errors.SysrepoCallbackFailedError, msg="loopback type change did not fail"):
            self.edit_config("data/loopback_change_type.xml")

        self.session.replace_config_ly(self.initial_data, "ietf-interfaces")


class IpTestCase(InterfacesTestCase):
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
        '<mtu>54321</mtu></ipv6></interface></interfaces>'

        data = self.session.get_data_ly('/ietf-interfaces:interfaces/interface[name="lo"]/ietf-ip:ipv6/mtu')
        mtu = data.print_mem("xml")
        self.assertEqual(mtu, expected_mtu, "loopback ipv6 MTU data is wrong")

        with open('/proc/sys/net/ipv6/conf/lo/mtu') as f:
            mtu_value = f.read().strip()
            self.assertEqual(mtu_value, '54321', 'plugin and system ipv6 MTU values differ.')

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

        parent_interface = os.environ.get('SYSREPO_PLUGIN_INTERFACES_PARENT_INTERFACE')
        if parent_interface is None:
            self.fail("SYSREPO_PLUGIN_INTERFACES_PARENT_INTERFACE has to be set to create a subinterface")

        # substitute parent interface environment variable in the sample xml configuration
        ret = os.system("envsubst < data/subinterface.xml.in > data/subinterface.xml")
        self.assertTrue(ret == 0)

        self.edit_config("data/subinterface.xml", config=False, edit=True)

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
