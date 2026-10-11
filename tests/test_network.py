"""Synthetic host records: fixed local reads only, never network traffic."""
import json
import socket
import subprocess
import unittest
from unittest.mock import patch

from i3enet.network import (
    LOCAL_COMMANDS, DiscoveryNetwork, GatewayNetwork, NetworkPreflightError,
    _parse_route_flags, _run_local, discovery_preflight, doctor, identity_preflight,
)

SELECTED_IFCONFIG = """en9: flags=8863<UP,BROADCAST,RUNNING> mtu 1500
    ether 02:00:00:00:00:99
    inet6 fe80::1%en9 prefixlen 64
    inet 169.254.20.3 netmask 0xffff0000 broadcast 169.254.255.255
    status: active
"""
SELECTED_HARDWARE = """Hardware Port: Apple USB Ethernet Adapter
Device: en9
Ethernet Address: 02:00:00:00:00:99
"""
SCOPED_ROUTE = """route to: 169.254.255.255
destination: 169.254.0.0
mask: 255.255.0.0
interface: en9
flags: <UP,DONE,CLONING,STATIC,IFSCOPE>
"""


class NetworkTests(unittest.TestCase):
    def setUp(self):
        self.reset()
        for name in ('socket', 'getaddrinfo', 'gethostbyname'):
            guard = patch.object(socket, name, side_effect=AssertionError('network forbidden'))
            guard.start(); self.addCleanup(guard.stop)

    def reset(self, mode='discovery'):
        self.mode = mode; self.commands = []
        self.ifconfig = SELECTED_IFCONFIG; self.hardware = SELECTED_HARDWARE
        self.destination = '169.254.255.255' if mode == 'discovery' else '169.254.20.9'
        self.route = SCOPED_ROUTE.replace('169.254.255.255', self.destination)

    def runner(self, command):
        self.commands.append(command)
        outputs = {('/sbin/ifconfig', 'en9'): self.ifconfig, LOCAL_COMMANDS[1]: self.hardware,
                   ('/sbin/route', '-n', 'get', '-ifscope', 'en9', self.destination): self.route}
        self.assertIn(command, outputs)
        return subprocess.CompletedProcess(command, 0, outputs[command], '')

    def preflight(self, interface='en9', source='169.254.20.3', gateway='169.254.20.9', **kwargs):
        options = dict(system='Darwin', runner=self.runner, index_lookup=lambda _: 12)
        options.update(kwargs)
        if self.mode == 'discovery':
            return discovery_preflight(interface, source, **options)
        return identity_preflight(interface, source, gateway, **options)

    def rejected(self, reason):
        with self.assertRaisesRegex(NetworkPreflightError, '^' + reason + '$'):
            self.preflight()

    def test_doctor_is_private_local_inspection_even_when_host_reads_fail(self):
        def runner(command):
            self.assertIn(command, LOCAL_COMMANDS)
            return subprocess.CompletedProcess(command, 0,
                SELECTED_IFCONFIG if command == LOCAL_COMMANDS[0] else SELECTED_HARDWARE, '')
        report = doctor(system='Darwin', runner=runner)
        self.assertEqual(report['interfaces'], [dict(name='en9', up=True, link_status='active',
            hardware_port='Apple USB Ethernet Adapter', ipv4=['169.254.20.3'])])
        self.assertEqual(report['vehicle_packets_sent'], 0)
        for key in ('route_verified', 'vehicle_contacted', 'writes_supported'):
            self.assertFalse(report[key])
        for private in ('02:00:00', 'fe80'):
            self.assertNotIn(private, json.dumps(report))

    def test_subnet_and_host_routes_use_only_the_exact_three_local_reads(self):
        for mode in ('discovery', 'identity'):
            for host, mask in ((False, True), (True, False), (True, True)):
                with self.subTest(mode=mode, host=host, mask=mask):
                    self.reset(mode)
                    if host:
                        flags = 'UP,HOST,DONE,LLINFO,b016,WASCLONED,' + ('BROADCAST' if mode == 'discovery' else 'IFSCOPE')
                        self.route = f'route to: {self.destination}\ndestination: {self.destination}\ninterface: en9\nflags: <{flags}>\n'
                        if mask: self.route += 'mask: 255.255.255.255\n'
                    result = self.preflight()
                    expected = (DiscoveryNetwork('en9', '169.254.20.3', self.destination, 12,
                                                 '255.255.0.0', 'Apple USB Ethernet Adapter') if mode == 'discovery'
                                else GatewayNetwork('en9', '169.254.20.3', self.destination, 12,
                                                    '255.255.0.0', 'Apple USB Ethernet Adapter'))
                    self.assertEqual(result, expected)
                    self.assertEqual(self.commands, [('/sbin/ifconfig', 'en9'), LOCAL_COMMANDS[1],
                        ('/sbin/route', '-n', 'get', '-ifscope', 'en9', self.destination)])
            self.reset(mode)
            self.ifconfig = SELECTED_IFCONFIG.replace('0xffff0000', '255.255.0.0')
            self.assertEqual(self.preflight().netmask, '255.255.0.0')
        self.reset(); self.ifconfig = SELECTED_IFCONFIG.replace(' broadcast 169.254.255.255', '')
        self.assertEqual(self.preflight().broadcast_address, '169.254.255.255')

    def test_endpoint_link_mask_hardware_and_index_fail_before_unsafe_progress(self):
        self.reset('identity')
        for interface, source, gateway in (
            ('utun4', '169.254.20.3', '169.254.20.9'), ('en9; touch marker', '169.254.20.3', '169.254.20.9'),
            ('en9', 'example.org', '169.254.20.9'), ('en9', '169.254.0.0', '169.254.20.9'),
            ('en9', '169.254.255.255', '169.254.20.9'), ('en9', '169.254.20.3', 'gateway.local'),
            ('en9', '169.254.20.3', '169.254.20.3'), ('en9', '169.254.20.3', '169.254.255.255')):
            with self.subTest(interface=interface, source=source, gateway=gateway), self.assertRaises(NetworkPreflightError):
                self.preflight(interface, source, gateway)
        self.assertEqual(self.commands, [])
        # Both clients share _observe_ethernet; exercise its host contract once.
        changes = [('169.254.20.3', '169.254.20.4'), ('UP,BROADCAST,RUNNING', 'BROADCAST,RUNNING'),
            ('status: active', 'status: inactive'), ('status: active', 'status: inactive\n status: active'),
            (' netmask 0xffff0000', ''), ('0xffff0000', '0xff00ff00'), ('0xffff0000', '0xffffff00'),
            ('broadcast 169.254.255.255', 'broadcast 169.254.20.255'), ('en9:', 'en8:')]
        for before, after in changes:
            with self.subTest(host_change=after), self.assertRaises(NetworkPreflightError):
                self.ifconfig = SELECTED_IFCONFIG.replace(before, after); self.preflight()
        self.ifconfig = SELECTED_IFCONFIG
        for label in ('Wi-Fi', 'Virtual Ethernet', 'Ethernet VPN', 'Unlabelled Adapter'):
            with self.subTest(hardware=label), self.assertRaises(NetworkPreflightError):
                self.hardware = SELECTED_HARDWARE.replace('Apple USB Ethernet Adapter', label); self.preflight()
        self.hardware = SELECTED_HARDWARE
        for index in (0, True, 0x80000000):
            with self.subTest(index=index), self.assertRaisesRegex(NetworkPreflightError, 'interface_index_invalid'):
                self.preflight(index_lookup=lambda _: index)
        self.commands.clear()
        self.ifconfig += ' inet 169.254.20.9 netmask 0xffff0000\n'
        self.rejected('gateway_is_local_interface_address'); self.assertEqual(len(self.commands), 2)


    def test_route_geometry_and_numeric_flag_normalization_fail_closed(self):
        aliases = {'GATEWAY':'b002', 'REJECT':'b004', 'BLACKHOLE':'b015', 'LOCAL':'b026', 'MULTICAST':'b030',
                   'CONDEMNED':'b032', 'ROUTER':'b035', 'PROXY':'b034', 'XRESOLVE':'b012', 'DEAD':'b036', 'GLOBAL':'b037'}
        for token, name in {'b001':'UP', 'b003':'HOST', 'b007':'DONE', 'b011':'CLONING', 'b014':'STATIC',
                            'b016':'NOIFREF', 'b022':'WASCLONED', 'b027':'BROADCAST', 'b031':'IFSCOPE'}.items():
            self.assertEqual(_parse_route_flags(f'<{token}>'), frozenset({name}))
        for mode in ('discovery', 'identity'):
            self.reset(mode); original = self.route
            changes = [('route to: '+self.destination, 'route to: 10.0.0.9'), ('interface: en9', 'interface: en0'),
                ('destination: 169.254.0.0', 'destination: default'), ('mask: 255.255.0.0', 'mask: 255.0.0.0'),
                ('<UP,DONE', '<UP,HOST,DONE'), ('<UP,DONE', '<DONE')]
            flags = [token for pair in aliases.items() for token in pair] + ['FUTURE', 'b024', 'b040', 'b008', 'up', 'UP,b001']
            if mode == 'identity': flags += ['BROADCAST', 'b027']
            changes += [('<UP,DONE', f'<UP,{token},DONE') for token in flags]
            for before, after in changes:
                with self.subTest(mode=mode, route_change=after), self.assertRaises(NetworkPreflightError):
                    self.route = original.replace(before, after); self.preflight()
            for extra in ('gateway: 10.0.0.1\n', 'interface: en9\n'):
                self.route = original + extra
                with self.assertRaises(NetworkPreflightError): self.preflight()
        self.reset('identity')
        self.route = self.route.replace('destination: 169.254.0.0', 'destination: 169.254.20.9').replace('mask: 255.255.0.0\n', '')
        self.rejected('route_scope_mismatch')


    def test_fixed_local_runner_and_deadlines_bound_every_host_read(self):
        invalid = [('/sbin/ifconfig', 'en9', 'up'), ('/sbin/route', 'add', 'default', '10.0.0.1'),
            ('/sbin/route', '-n', 'get', '169.254.255.255'),
            ('/sbin/route', '-n', 'get', '-ifscope', 'en9', 'example.org'),
            ('/sbin/route', '-n', 'get', '-ifscope', 'utun4', '169.254.255.255')]
        with patch('i3enet.network.subprocess.run', side_effect=AssertionError('unreviewed command')):
            for command in invalid:
                with self.subTest(command=command), self.assertRaises(ValueError): _run_local(command)
        self.reset('identity')
        for deadline in (True, 'tomorrow', float('nan'), float('inf')):
            with self.subTest(deadline=deadline), self.assertRaisesRegex(NetworkPreflightError, 'deadline_invalid'):
                self.preflight(deadline=deadline)
        with patch('i3enet.network.time.monotonic', return_value=100.0):
            for deadline in (99.0, 100.0):
                with self.assertRaisesRegex(NetworkPreflightError, 'deadline_exhausted'): self.preflight(deadline=deadline)
        self.assertEqual(self.commands, [])
        with patch('i3enet.network.time.monotonic', side_effect=[100.0, 102.0]), self.assertRaisesRegex(NetworkPreflightError, 'deadline_exhausted'):
            self.preflight(deadline=101.0)
        self.assertEqual(self.commands, [('/sbin/ifconfig', 'en9')])
        def completed(command, **kwargs): return self.runner(command)
        with patch('i3enet.network.subprocess.run', side_effect=completed) as mocked, \
             patch('i3enet.network.time.monotonic', side_effect=[100.,101.,102.,102.5,103.,104.]):
            self.preflight(runner=_run_local, deadline=105.5)
        self.assertEqual([call.kwargs['timeout'] for call in mocked.call_args_list], [5.,3.5,2.5])
        for call in mocked.call_args_list:
            self.assertNotIn('shell', call.kwargs); self.assertEqual(call.kwargs['env']['LC_ALL'], 'C')
