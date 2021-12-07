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

    def edit_config(self, path):
        ctx = self.conn.get_ly_ctx()

        with open(path, "r") as f:
            data = f.read()
            data = ctx.parse_data_mem(data, "xml", config=True, strict=True)
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


    def test_interface_ipv6_forwarding(self):
        """Attempt to enable loopback ipv6 address forwarding."""
        self.edit_config("data/loopback_forwarding.xml")

        expected_forwarding = \
        '<interfaces xmlns="urn:ietf:params:xml:ns:yang:ietf-interfaces">' \
        '<interface><name>lo</name><ipv6 xmlns="urn:ietf:params:xml:ns:yang:ietf-ip">' \
        '<forwarding>true</forwarding></ipv6></interface></interfaces>'

        data = self.session.get_data_ly('/ietf-interfaces:interfaces/interface[name="lo"]/ietf-ip:ipv6/forwarding')
        forwarding = data.print_mem("xml")
        self.assertEqual(forwarding, expected_forwarding, "loopback forwarding data is wrong")

        with open('/proc/sys/net/ipv6/conf/lo/forwarding') as f:
            forwarding_configuration = f.read().strip()
            self.assertEqual(
                forwarding_configuration, '1',
                'plugin and system interface state differ, forwarding is not enabled for loopback'
            )

        data.free()
        self.session.replace_config_ly(self.initial_data, "ietf-interfaces")


if __name__ == '__main__':
    unittest.main()
