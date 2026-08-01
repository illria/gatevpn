import socket
import unittest
from unittest import mock

import proxy_server


def socks5_udp_header(address_type, address, port, data=b""):
    if address_type == 1:
        address_bytes = socket.inet_pton(socket.AF_INET, address)
        address_part = address_bytes
    elif address_type == 3:
        address_bytes = address.encode("idna")
        address_part = bytes([len(address_bytes)]) + address_bytes
    else:
        raise AssertionError("test helper only supports IPv4 and domain names")
    return b"\x00\x00\x00" + bytes([address_type]) + address_part + port.to_bytes(2, "big") + data


class FakeUDPSocket:
    def __init__(self, name, local_address):
        self.name = name
        self.local_address = local_address
        self.bound = None
        self.sent = []
        self.closed = False
        self.incoming = []

    def bind(self, address):
        self.bound = address

    def getsockname(self):
        return self.local_address

    def recvfrom(self, _size):
        return self.incoming.pop(0)

    def sendto(self, data, address):
        self.sent.append((data, address))

    def close(self):
        self.closed = True

    def fileno(self):
        return 100 if self.name == "relay" else 101


class FakeControlSocket:
    def __init__(self, peer=("127.0.0.1", 50000)):
        self.peer = peer
        self.sent = []
        self.recv_results = []
        self.closed = False

    def getpeername(self):
        return self.peer

    def sendall(self, data):
        self.sent.append(data)

    def recv(self, _size, _flags=0):
        return self.recv_results.pop(0)

    def close(self):
        self.closed = True


class UDPHeaderTests(unittest.TestCase):
    def test_ipv4_udp_header_parse_and_response_encode(self):
        request = proxy_server.parse_udp_request(
            socks5_udp_header(1, "192.0.2.10", 19302, b"payload")
        )
        self.assertEqual((request.address_type, request.host, request.port, request.data), (1, "192.0.2.10", 19302, b"payload"))

        encoded = proxy_server.encode_udp_response(("198.51.100.4", 5353), b"answer")
        self.assertEqual(encoded[:4], b"\x00\x00\x00\x01")
        self.assertEqual(socket.inet_ntop(socket.AF_INET, encoded[4:8]), "198.51.100.4")
        self.assertEqual(int.from_bytes(encoded[8:10], "big"), 5353)
        self.assertEqual(encoded[10:], b"answer")

    def test_domain_udp_header_parse(self):
        request = proxy_server.parse_udp_request(socks5_udp_header(3, "stun.example", 19302))
        self.assertEqual(request.address_type, 3)
        self.assertEqual(request.host, "stun.example")
        self.assertEqual(request.port, 19302)

    def test_nonzero_frag_is_rejected(self):
        packet = socks5_udp_header(1, "192.0.2.10", 53)
        with self.assertRaises(proxy_server.UDPHeaderError):
            proxy_server.parse_udp_request(packet[:2] + b"\x01" + packet[3:])

    def test_unsupported_atyp_is_rejected(self):
        with self.assertRaises(proxy_server.UnsupportedUDPAddressType):
            proxy_server.parse_udp_request(b"\x00\x00\x00\x04" + b"\x00" * 16 + b"\x00\x35")


class SOCKS5Tests(unittest.TestCase):
    def test_socks5_connect_still_works(self):
        client, peer = socket.socketpair()
        upstream = mock.Mock()
        try:
            peer.sendall(b"\x01\x00" + b"\x05\x01\x00\x01" + socket.inet_aton("192.0.2.20") + b"\x01\xbb")
            with mock.patch.object(proxy_server, "create_connection", return_value=upstream), mock.patch.object(proxy_server, "relay"):
                proxy_server.socks5_client(client, b"\x05", ("127.0.0.1", 50000))
            self.assertEqual(peer.recv(2), b"\x05\x00")
            self.assertEqual(peer.recv(10), b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
            upstream.close.assert_called_once()
        finally:
            peer.close()

    def test_unsupported_socks5_command_is_explicitly_rejected(self):
        client, peer = socket.socketpair()
        try:
            peer.sendall(b"\x01\x00" + b"\x05\x02\x00\x01" + b"\x00" * 6)
            with mock.patch.object(proxy_server, "relay"):
                proxy_server.socks5_client(client, b"\x05", ("127.0.0.1", 50000))
            self.assertEqual(peer.recv(2), b"\x05\x00")
            self.assertEqual(peer.recv(10), b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
        finally:
            peer.close()

    def test_http_connect_still_works(self):
        client, peer = socket.socketpair()
        upstream = mock.Mock()
        try:
            peer.sendall(b"ONNECT 192.0.2.30:443 HTTP/1.1\r\nHost: 192.0.2.30\r\n\r\n")
            with mock.patch.object(proxy_server, "create_connection", return_value=upstream), mock.patch.object(proxy_server, "relay"):
                proxy_server.http_client(client, b"C")
            expected = b"HTTP/1.1 200 Connection Established\r\n\r\n"
            self.assertEqual(peer.recv(len(expected)), expected)
            upstream.close.assert_called_once()
        finally:
            peer.close()

    def test_udp_associate_returns_relay_and_cleans_up_on_control_close(self):
        control = FakeControlSocket()
        control.recv_results = [b""]
        relay = FakeUDPSocket("relay", ("127.0.0.1", 45678))
        upstream = FakeUDPSocket("upstream", ("0.0.0.0", 40000))
        sockets = iter((relay, upstream))
        with mock.patch.object(proxy_server, "bind_socket_to_interface") as bind, mock.patch.object(
            proxy_server.select, "select", return_value=([control], [], [])
        ):
            proxy_server.udp_associate(control, ("127.0.0.1", 50000), interface="tun0", socket_factory=lambda *_: next(sockets))

        self.assertEqual(control.sent, [b"\x05\x00\x00\x01\x7f\x00\x00\x01\xb2\x6e"])
        bind.assert_called_once_with(upstream, "tun0")
        self.assertTrue(relay.closed)
        self.assertTrue(upstream.closed)

    def test_udp_associate_binds_upstream_before_send(self):
        control = FakeControlSocket()
        control.recv_results = [b""]
        relay = FakeUDPSocket("relay", ("127.0.0.1", 45678))
        relay.incoming = [(socks5_udp_header(1, "192.0.2.10", 19302, b"stun"), ("127.0.0.1", 50001))]
        upstream = FakeUDPSocket("upstream", ("0.0.0.0", 40000))
        sockets = iter((relay, upstream))
        select_results = [([relay], [], []), ([control], [], [])]
        with mock.patch.object(proxy_server, "bind_socket_to_interface") as bind, mock.patch.object(
            proxy_server.select, "select", side_effect=select_results
        ):
            proxy_server.udp_associate(control, ("127.0.0.1", 50000), socket_factory=lambda *_: next(sockets))

        bind.assert_called_once_with(upstream, "tun0")
        self.assertEqual(upstream.sent, [(b"stun", ("192.0.2.10", 19302))])

    def test_domain_udp_destination_uses_tunnel_dns(self):
        control = FakeControlSocket()
        control.recv_results = [b""]
        relay = FakeUDPSocket("relay", ("127.0.0.1", 45678))
        relay.incoming = [(socks5_udp_header(3, "stun.example", 19302, b"stun"), ("127.0.0.1", 50001))]
        upstream = FakeUDPSocket("upstream", ("0.0.0.0", 40000))
        sockets = iter((relay, upstream))
        with mock.patch.object(proxy_server, "bind_socket_to_interface"), mock.patch.object(
            proxy_server, "resolve_dns_over_tun0", return_value="192.0.2.11"
        ) as resolve, mock.patch.object(proxy_server.select, "select", side_effect=[([relay], [], []), ([control], [], [])]):
            proxy_server.udp_associate(control, ("127.0.0.1", 50000), socket_factory=lambda *_: next(sockets))
        resolve.assert_called_once_with("stun.example", interface="tun0")
        self.assertEqual(upstream.sent, [(b"stun", ("192.0.2.11", 19302))])

    def test_failed_tunnel_dns_does_not_use_system_dns(self):
        with mock.patch.object(proxy_server, "resolve_dns_over_tun0", return_value=None), mock.patch.object(
            proxy_server.socket, "getaddrinfo"
        ) as getaddrinfo:
            with self.assertRaises(OSError):
                proxy_server.create_connection(("stun.example", 19302))
        getaddrinfo.assert_not_called()

    def test_bind_failure_does_not_send(self):
        control = FakeControlSocket()
        relay = FakeUDPSocket("relay", ("127.0.0.1", 45678))
        upstream = FakeUDPSocket("upstream", ("0.0.0.0", 40000))
        sockets = iter((relay, upstream))
        with mock.patch.object(proxy_server, "bind_socket_to_interface", side_effect=OSError("tun0 missing")):
            proxy_server.udp_associate(control, ("127.0.0.1", 50000), socket_factory=lambda *_: next(sockets))
        self.assertFalse(upstream.sent)
        self.assertTrue(relay.closed)
        self.assertTrue(upstream.closed)
        self.assertEqual(control.sent[0][:2], b"\x05\x01")

    def test_unentitled_udp_source_is_dropped(self):
        control = FakeControlSocket()
        control.recv_results = [b""]
        relay = FakeUDPSocket("relay", ("127.0.0.1", 45678))
        relay.incoming = [(socks5_udp_header(1, "192.0.2.10", 19302, b"data"), ("127.0.0.2", 50001))]
        upstream = FakeUDPSocket("upstream", ("0.0.0.0", 40000))
        sockets = iter((relay, upstream))
        with mock.patch.object(proxy_server, "bind_socket_to_interface"), mock.patch.object(
            proxy_server.select, "select", side_effect=[([relay], [], []), ([control], [], [])]
        ):
            proxy_server.udp_associate(control, ("127.0.0.1", 50000), socket_factory=lambda *_: next(sockets))
        self.assertFalse(upstream.sent)


if __name__ == "__main__":
    unittest.main()
