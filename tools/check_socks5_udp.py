#!/usr/bin/env python3
"""Check that SOCKS5 UDP traffic reaches a STUN server through the proxy."""

from __future__ import annotations

import argparse
import secrets
import socket
import struct
import sys


def recv_exact(sock: socket.socket, size: int) -> bytes:
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise RuntimeError("SOCKS5 control connection closed unexpectedly")
        data += chunk
    return data


def read_socks5_address(sock: socket.socket) -> tuple[str, int]:
    address_type = recv_exact(sock, 1)[0]
    if address_type == 1:
        host = socket.inet_ntop(socket.AF_INET, recv_exact(sock, 4))
    elif address_type == 3:
        length = recv_exact(sock, 1)[0]
        host = recv_exact(sock, length).decode("idna")
    elif address_type == 4:
        host = socket.inet_ntop(socket.AF_INET6, recv_exact(sock, 16))
    else:
        raise RuntimeError(f"Unknown SOCKS5 relay address type: {address_type}")
    return host, int.from_bytes(recv_exact(sock, 2), "big")


def parse_socks5_udp_response(packet: bytes) -> tuple[tuple[str, int], bytes]:
    """Remove the RFC 1928 UDP response header and return source plus payload."""

    if len(packet) < 4:
        raise RuntimeError("Truncated SOCKS5 UDP response header")
    if packet[:2] != b"\x00\x00":
        raise RuntimeError("SOCKS5 UDP response RSV must be zero")
    if packet[2] != 0:
        raise RuntimeError("SOCKS5 UDP response fragmentation is not supported")
    if packet[3] != 1:
        raise RuntimeError("SOCKS5 UDP response source must use IPv4 ATYP")
    if len(packet) < 10:
        raise RuntimeError("Truncated SOCKS5 UDP IPv4 response header")
    source = (socket.inet_ntop(socket.AF_INET, packet[4:8]), int.from_bytes(packet[8:10], "big"))
    return source, packet[10:]


def build_stun_binding_request() -> tuple[bytes, bytes]:
    transaction_id = secrets.token_bytes(12)
    # Binding Request, zero attributes, RFC 5389 magic cookie.
    return b"\x00\x01\x00\x00\x21\x12\xa4\x42" + transaction_id, transaction_id


def parse_xor_mapped_address(packet: bytes, transaction_id: bytes) -> tuple[str, int]:
    if len(packet) < 20 or packet[:2] != b"\x01\x01" or packet[4:8] != b"\x21\x12\xa4\x42" or packet[8:20] != transaction_id:
        raise RuntimeError("Invalid STUN Binding Success Response")
    message_length = int.from_bytes(packet[2:4], "big")
    end = min(len(packet), 20 + message_length)
    offset = 20
    cookie = 0x2112A442
    while offset + 4 <= end:
        attribute_type, attribute_length = struct.unpack("!HH", packet[offset : offset + 4])
        value_start = offset + 4
        value_end = value_start + attribute_length
        if value_end > end:
            raise RuntimeError("Truncated STUN attribute")
        if attribute_type == 0x0020 and attribute_length >= 8:
            value = packet[value_start:value_end]
            if value[1] != 0x01:
                raise RuntimeError("STUN returned an IPv6 XOR-MAPPED-ADDRESS; IPv4 only")
            port = int.from_bytes(value[2:4], "big") ^ (cookie >> 16)
            address_bytes = bytes(value[4 + index] ^ ((cookie >> (24 - 8 * index)) & 0xFF) for index in range(4))
            return socket.inet_ntop(socket.AF_INET, address_bytes), port
        offset = value_end + ((4 - attribute_length % 4) % 4)
    raise RuntimeError("STUN response did not contain XOR-MAPPED-ADDRESS")


def run(args: argparse.Namespace) -> int:
    control = None
    udp = None
    try:
        control = socket.create_connection((args.proxy_host, args.proxy_port), timeout=args.timeout)
        control.sendall(b"\x05\x01\x00")
        if recv_exact(control, 2) != b"\x05\x00":
            raise RuntimeError("SOCKS5 proxy does not accept unauthenticated negotiation")

        control.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
        response = recv_exact(control, 4)
        if response[0] != 5 or response[1] != 0:
            raise RuntimeError(f"UDP ASSOCIATE failed with SOCKS5 reply code 0x{response[1]:02x}")
        relay_host, relay_port = read_socks5_address(control)
        if relay_host in {"0.0.0.0", "::"}:
            relay_host = args.proxy_host

        stun_request, transaction_id = build_stun_binding_request()
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp.settimeout(args.timeout)
        domain_bytes = args.stun_host.encode("idna")
        packet = b"\x00\x00\x00\x03" + bytes([len(domain_bytes)]) + domain_bytes + args.stun_port.to_bytes(2, "big") + stun_request
        udp.sendto(packet, (relay_host, relay_port))
        response, _ = udp.recvfrom(65535)
        _remote_source, stun_payload = parse_socks5_udp_response(response)
        public_ip, public_port = parse_xor_mapped_address(stun_payload, transaction_id)
        print(f"Detected public UDP endpoint: {public_ip}:{public_port}")
        print("Compare this IP with the current OpenVPN/tun0 egress IP.")
        return 0
    except (OSError, RuntimeError, UnicodeError, ValueError) as exc:
        print(f"SOCKS5 UDP check failed: {exc}", file=sys.stderr)
        print("Check that gatevpn is running, tun0 is available, and the STUN server is reachable.", file=sys.stderr)
        return 1
    finally:
        for sock in (udp, control):
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--proxy-host", default="127.0.0.1")
    parser.add_argument("--proxy-port", type=int, default=7928)
    parser.add_argument("--stun-host", default="stun.l.google.com")
    parser.add_argument("--stun-port", type=int, default=19302)
    parser.add_argument("--timeout", type=float, default=5.0, help="Per-operation timeout in seconds")
    return parser.parse_args()


if __name__ == "__main__":
    raise SystemExit(run(parse_args()))
