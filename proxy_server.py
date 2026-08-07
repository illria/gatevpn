#!/usr/bin/env python3
from __future__ import annotations

import logging
import os
import random
import select
import socket
import threading
import time
import urllib.parse
from dataclasses import dataclass
from typing import Any, Callable


LOG = logging.getLogger(__name__)
TUN_INTERFACE = os.environ.get("GATEVPN_TUN_INTERFACE", "tun0")
_TUN_INTERFACE_LOCK = threading.RLock()
UDP_ASSOCIATE_IDLE_TIMEOUT = 120.0
UDP_RELAY_SELECT_INTERVAL = 1.0


def get_tun_interface() -> str:
    with _TUN_INTERFACE_LOCK:
        return TUN_INTERFACE


def set_tun_interface(interface: str) -> None:
    """Change the interface used by newly created outbound proxy sockets.

    Existing TCP/UDP relays keep the interface captured when they were created.
    That lets the manager drain the old tunnel while new connections use the
    promoted tunnel during an optional dual-tunnel switch.
    """

    value = str(interface or "").strip()
    if not value or len(value) > 15 or any(char not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-" for char in value):
        raise ValueError("invalid tunnel interface name")
    with _TUN_INTERFACE_LOCK:
        global TUN_INTERFACE
        TUN_INTERFACE = value


def parse_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def recv_exact(sock: socket.socket, size: int) -> bytes:
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise ConnectionError("Unexpected disconnect.")
        data += chunk
    return data


def bind_socket_to_interface(sock: socket.socket, interface: str | None = None) -> None:
    """Bind a socket to an interface, or raise without permitting fallback.

    SO_BINDTODEVICE is Linux-specific.  Keeping this operation in one function
    makes the fail-closed policy explicit and makes it straightforward to mock
    in environments where tun0 or the capability is unavailable.
    """

    interface = interface or get_tun_interface()
    bind_option = getattr(socket, "SO_BINDTODEVICE", None)
    if bind_option is None:
        raise OSError("SO_BINDTODEVICE is not available on this platform")
    if not interface:
        raise OSError("The tunnel interface name is empty")
    sock.setsockopt(socket.SOL_SOCKET, bind_option, interface.encode("ascii"))


def _encode_dns_name(host: str) -> bytes:
    labels = host.rstrip(".").split(".")
    encoded = b""
    for label in labels:
        if not label:
            continue
        label_bytes = label.encode("idna")
        if len(label_bytes) > 63:
            raise ValueError("DNS label is too long")
        encoded += bytes([len(label_bytes)]) + label_bytes
    return encoded + b"\x00"


def _skip_dns_name(packet: bytes, offset: int) -> int | None:
    while offset < len(packet):
        length = packet[offset]
        if length == 0:
            return offset + 1
        if (length & 0xC0) == 0xC0:
            return offset + 2 if offset + 1 < len(packet) else None
        if length & 0xC0:
            return None
        offset += 1 + length
    return None


def resolve_dns_over_tun0(
    host: str,
    dns_server: str = "8.8.8.8",
    timeout: float = 3.0,
    interface: str | None = None,
) -> str | None:
    """Resolve an A record through the tunnel only; never use system DNS."""

    interface = interface or get_tun_interface()

    try:
        return socket.inet_pton(socket.AF_INET, host) and host
    except OSError:
        pass

    try:
        tx_id = random.getrandbits(16).to_bytes(2, "big")
        packet = (
            tx_id
            + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
            + _encode_dns_name(host)
            + b"\x00\x01\x00\x01"
        )
    except (UnicodeError, ValueError):
        LOG.debug("Invalid DNS name: %s", host)
        return None

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.settimeout(timeout)
        bind_socket_to_interface(sock, interface)
        sock.sendto(packet, (dns_server, 53))
        response, _ = sock.recvfrom(4096)
    except OSError as exc:
        LOG.debug("DNS over %s failed for %s: %s", interface, host, exc)
        return None
    finally:
        sock.close()

    if len(response) < 12 or response[:2] != tx_id:
        return None
    if response[3] & 0x0F:
        return None

    offset = _skip_dns_name(response, 12)
    if offset is None or offset + 4 > len(response):
        return None
    offset += 4
    answers_count = int.from_bytes(response[6:8], "big")
    for _ in range(answers_count):
        offset = _skip_dns_name(response, offset)
        if offset is None or offset + 10 > len(response):
            return None
        record_type = int.from_bytes(response[offset : offset + 2], "big")
        record_class = int.from_bytes(response[offset + 2 : offset + 4], "big")
        record_length = int.from_bytes(response[offset + 8 : offset + 10], "big")
        offset += 10
        if offset + record_length > len(response):
            return None
        if record_type == 1 and record_class == 1 and record_length == 4:
            return socket.inet_ntop(socket.AF_INET, response[offset : offset + 4])
        offset += record_length
    return None


def create_connection(
    address: tuple[str, int],
    timeout: float = 20,
    interface: str | None = None,
) -> socket.socket:
    interface = interface or get_tun_interface()
    host, port = address
    resolved_ip = resolve_dns_over_tun0(host, interface=interface)
    if resolved_ip:
        host = resolved_ip
    else:
        # Do not let getaddrinfo perform an implicit system-DNS lookup after
        # the tunnel-only resolver failed.  Literal IPv6 remains usable for
        # the existing TCP CONNECT path, but hostnames fail closed.
        try:
            socket.inet_pton(socket.AF_INET, host)
        except OSError:
            try:
                socket.inet_pton(socket.AF_INET6, host)
            except OSError as exc:
                raise OSError(f"DNS resolution over {interface} failed for {host}") from exc

    err = None
    for res in socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM):
        af, socktype, proto, _canonname, sockaddr = res
        sock = None
        try:
            sock = socket.socket(af, socktype, proto)
            sock.settimeout(timeout)
            bind_socket_to_interface(sock, interface)
            sock.connect(sockaddr)
            return sock
        except OSError as exc:
            err = exc
            if sock is not None:
                sock.close()
    if err is not None:
        raise err
    raise OSError("getaddrinfo returns empty list")


def relay(left: socket.socket, right: socket.socket) -> None:
    sockets = [left, right]
    while True:
        readable, _, errored = select.select(sockets, [], sockets, 120)
        if errored:
            return
        for source in readable:
            target = right if source is left else left
            data = source.recv(65536)
            if not data:
                return
            target.sendall(data)


def _socks5_reply(
    reply: int,
    address_type: int = 1,
    address: str = "0.0.0.0",
    port: int = 0,
) -> bytes:
    if address_type == 1:
        address_bytes = socket.inet_pton(socket.AF_INET, address)
    elif address_type == 4:
        address_bytes = socket.inet_pton(socket.AF_INET6, address)
    else:
        raise ValueError("SOCKS5 replies only use IPv4 or IPv6 addresses")
    return b"\x05" + bytes([reply, 0, address_type]) + address_bytes + port.to_bytes(2, "big")


@dataclass(frozen=True)
class SOCKS5Address:
    address_type: int
    host: str
    port: int


class SOCKS5RequestError(ValueError):
    def __init__(self, reply_code: int, message: str):
        super().__init__(message)
        self.reply_code = reply_code


def read_socks5_address(client: socket.socket, address_type: int) -> SOCKS5Address:
    """Consume an RFC 1928 address and port from a SOCKS5 control stream."""

    try:
        if address_type == 1:
            host = socket.inet_ntop(socket.AF_INET, recv_exact(client, 4))
        elif address_type == 3:
            name_length = recv_exact(client, 1)[0]
            if name_length == 0:
                raise SOCKS5RequestError(8, "SOCKS5 domain name is empty")
            host = recv_exact(client, name_length).decode("idna")
        elif address_type == 4:
            host = socket.inet_ntop(socket.AF_INET6, recv_exact(client, 16))
        else:
            raise SOCKS5RequestError(8, f"Unsupported SOCKS5 address type: {address_type}")
        port = int.from_bytes(recv_exact(client, 2), "big")
    except UnicodeError as exc:
        raise SOCKS5RequestError(8, "Invalid SOCKS5 domain name") from exc
    except ConnectionError:
        raise
    except OSError as exc:
        raise SOCKS5RequestError(8, "Invalid SOCKS5 address") from exc
    return SOCKS5Address(address_type, host, port)


@dataclass(frozen=True)
class UDPRequest:
    address_type: int
    host: str
    port: int
    data: bytes


class UDPHeaderError(ValueError):
    pass


class UnsupportedUDPAddressType(UDPHeaderError):
    pass


def parse_udp_request(packet: bytes) -> UDPRequest:
    """Parse an RFC 1928 UDP request without resolving its destination."""

    if len(packet) < 4:
        raise UDPHeaderError("UDP request is shorter than the SOCKS5 header")
    if packet[:2] != b"\x00\x00":
        raise UDPHeaderError("SOCKS5 UDP RSV must be zero")
    if packet[2] != 0:
        raise UDPHeaderError("SOCKS5 UDP fragmentation is not supported")

    address_type = packet[3]
    offset = 4
    if address_type == 1:
        if len(packet) < offset + 4:
            raise UDPHeaderError("Truncated IPv4 destination")
        host = socket.inet_ntop(socket.AF_INET, packet[offset : offset + 4])
        offset += 4
    elif address_type == 3:
        if len(packet) < offset + 1:
            raise UDPHeaderError("Truncated domain destination length")
        name_length = packet[offset]
        offset += 1
        if name_length == 0 or len(packet) < offset + name_length:
            raise UDPHeaderError("Truncated domain destination")
        try:
            host = packet[offset : offset + name_length].decode("idna")
        except UnicodeError as exc:
            raise UDPHeaderError("Invalid domain destination") from exc
        offset += name_length
    elif address_type == 4:
        raise UnsupportedUDPAddressType("IPv6 UDP destinations are not supported")
    else:
        raise UnsupportedUDPAddressType(f"Unsupported UDP address type: {address_type}")

    if len(packet) < offset + 2:
        raise UDPHeaderError("Truncated UDP destination port")
    port = int.from_bytes(packet[offset : offset + 2], "big")
    return UDPRequest(address_type, host, port, packet[offset + 2 :])


def encode_udp_response(source: tuple[str, int], data: bytes) -> bytes:
    """Encode a remote IPv4 source address in an RFC 1928 UDP response."""

    host, port = source[:2]
    address = socket.inet_pton(socket.AF_INET, host)
    return b"\x00\x00\x00\x01" + address + port.to_bytes(2, "big") + data


def _client_ip(client: socket.socket, address: tuple[str, int]) -> str:
    try:
        peer = client.getpeername()
        if isinstance(peer, tuple) and peer:
            return peer[0]
    except (IndexError, OSError, TypeError):
        pass
    try:
        return address[0]
    except (IndexError, TypeError):
        return ""


def _same_udp_endpoint(left: tuple[str, int], right: tuple[str, int]) -> bool:
    return left[0] == right[0] and left[1] == right[1]


def _validate_udp_associate_endpoint(
    requested: SOCKS5Address,
    client: socket.socket,
    client_address: tuple[str, int],
) -> tuple[str, int] | None:
    """Validate the UDP ASSOCIATE client address without widening access."""

    if requested.address_type != 1:
        raise SOCKS5RequestError(2, "UDP ASSOCIATE requires an IPv4 client address")
    allowed_ip = _client_ip(client, client_address)
    if requested.host == "0.0.0.0" and requested.port == 0:
        return None
    if requested.host not in {"0.0.0.0", allowed_ip}:
        raise SOCKS5RequestError(2, "UDP ASSOCIATE client address does not match control peer")
    if requested.port == 0:
        return None
    return allowed_ip, requested.port


def udp_associate(
    client: socket.socket,
    client_address: tuple[str, int],
    interface: str | None = None,
    idle_timeout: float = UDP_ASSOCIATE_IDLE_TIMEOUT,
    requested_endpoint: tuple[str, int] | None = None,
    socket_factory: Callable[..., socket.socket] = socket.socket,
) -> None:
    """Run one UDP association until control disconnect, timeout, or failure."""

    interface = interface or get_tun_interface()

    client_relay = None
    upstream = None
    try:
        client_relay = socket_factory(socket.AF_INET, socket.SOCK_DGRAM)
        client_relay.bind(("127.0.0.1", 0))

        upstream = socket_factory(socket.AF_INET, socket.SOCK_DGRAM)
        # This is deliberately before any send.  A failure terminates the
        # association; there is no unbound/default-route fallback.
        bind_socket_to_interface(upstream, interface)
        upstream.bind(("0.0.0.0", 0))

        relay_host, relay_port = client_relay.getsockname()[:2]
        client.sendall(_socks5_reply(0, 1, relay_host, relay_port))
        allowed_ip = _client_ip(client, client_address)
        locked_endpoint: tuple[str, int] | None = None
        last_activity = time.monotonic()
        visited_udp_destinations: set[tuple[str, int]] = set()
        control_open = True

        while control_open:
            remaining = idle_timeout - (time.monotonic() - last_activity)
            if remaining <= 0:
                LOG.debug("SOCKS5 UDP association idle timeout for %s", allowed_ip)
                return
            readable, _, errored = select.select(
                [client, client_relay, upstream],
                [],
                [client, client_relay, upstream],
                min(remaining, UDP_RELAY_SELECT_INTERVAL),
            )
            if errored:
                LOG.error("SOCKS5 UDP association socket error; stopping fail-closed")
                return
            if client in readable:
                try:
                    if not client.recv(1, socket.MSG_PEEK):
                        return
                    LOG.debug("Unexpected data on SOCKS5 UDP control connection")
                    return
                except (BlockingIOError, ConnectionError, OSError):
                    return

            if client_relay in readable:
                packet, source = client_relay.recvfrom(65535)
                source_endpoint = (source[0], source[1])
                if source_endpoint[0] != allowed_ip:
                    LOG.debug("Dropped UDP packet from unauthorized client %s", source_endpoint)
                    continue
                if requested_endpoint is not None and not _same_udp_endpoint(requested_endpoint, source_endpoint):
                    LOG.debug("Dropped UDP packet outside requested client endpoint %s", source_endpoint)
                    continue
                if locked_endpoint is not None and not _same_udp_endpoint(locked_endpoint, source_endpoint):
                    LOG.debug("Dropped UDP packet from unlocked client endpoint %s", source_endpoint)
                    continue
                try:
                    request = parse_udp_request(packet)
                except UDPHeaderError as exc:
                    LOG.debug("Dropped malformed SOCKS5 UDP request: %s", exc)
                    continue
                if locked_endpoint is None:
                    locked_endpoint = source_endpoint

                destination = request.host
                if request.address_type == 3:
                    destination = resolve_dns_over_tun0(destination, interface=interface) or ""
                    if not destination:
                        LOG.error("UDP DNS resolution failed over %s; dropping datagram", interface)
                        continue
                try:
                    # The only public UDP socket is the interface-bound one.
                    upstream.sendto(request.data, (destination, request.port))
                except OSError as exc:
                    LOG.error("UDP send over %s failed; stopping fail-closed: %s", interface, exc)
                    return
                visited_udp_destinations.add((destination, request.port))
                last_activity = time.monotonic()

            if upstream in readable:
                response, source = upstream.recvfrom(65535)
                if locked_endpoint is None:
                    LOG.debug("Dropped unsolicited UDP response before client lock")
                    continue
                source_endpoint = (source[0], source[1])
                if source_endpoint not in visited_udp_destinations:
                    LOG.debug("Dropped UDP response from unvisited remote source %s", source_endpoint)
                    continue
                try:
                    client_relay.sendto(encode_udp_response(source_endpoint, response), locked_endpoint)
                except OSError as exc:
                    LOG.debug("Unable to return UDP response to local client: %s", exc)
                    return
                last_activity = time.monotonic()
    except OSError as exc:
        LOG.error("SOCKS5 UDP association failed on %s; stopping fail-closed: %s", interface, exc)
        try:
            client.sendall(_socks5_reply(1))
        except OSError:
            pass
    finally:
        for sock in (client_relay, upstream):
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass


def socks5_client(
    client: socket.socket,
    first_byte: bytes,
    client_address: tuple[str, int] = ("127.0.0.1", 0),
) -> None:
    upstream = None
    try:
        methods_count = recv_exact(client, 1)[0]
        methods = recv_exact(client, methods_count)
        if 0 not in methods:
            client.sendall(b"\x05\xff")
            return
        client.sendall(b"\x05\x00")
        version, command, _, address_type = recv_exact(client, 4)
        if version != 5:
            return

        try:
            requested_address = read_socks5_address(client, address_type)
        except SOCKS5RequestError as exc:
            client.sendall(_socks5_reply(exc.reply_code))
            return
        except (ConnectionError, OSError):
            try:
                client.sendall(_socks5_reply(1))
            except OSError:
                pass
            return

        if command == 3:
            try:
                requested_endpoint = _validate_udp_associate_endpoint(
                    requested_address, client, client_address
                )
            except SOCKS5RequestError as exc:
                client.sendall(_socks5_reply(exc.reply_code))
                return
            udp_associate(client, client_address, requested_endpoint=requested_endpoint)
            return
        if command != 1:
            client.sendall(_socks5_reply(7))
            return

        try:
            upstream = create_connection((requested_address.host, requested_address.port), timeout=20)
        except Exception:
            try:
                client.sendall(_socks5_reply(4))
            except OSError:
                pass
            raise
        client.sendall(_socks5_reply(0))
        relay(client, upstream)
    finally:
        client.close()
        if upstream:
            upstream.close()


def read_http_header(client: socket.socket, first_byte: bytes) -> bytes:
    data = first_byte
    while b"\r\n\r\n" not in data and len(data) < 65536:
        chunk = client.recv(4096)
        if not chunk:
            break
        data += chunk
    return data


def http_client(client: socket.socket, first_byte: bytes) -> None:
    upstream = None
    try:
        header = read_http_header(client, first_byte)
        head, rest = header.split(b"\r\n\r\n", 1)
        lines = head.decode("iso-8859-1", errors="replace").split("\r\n")
        method, target, version = lines[0].split(" ", 2)
        if method.upper() == "CONNECT":
            host, _, port_text = target.partition(":")
            port = parse_int(port_text) or 443
            upstream = create_connection((host, port), timeout=20)
            client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            if rest:
                upstream.sendall(rest)
            relay(client, upstream)
            return

        parsed = urllib.parse.urlsplit(target)
        if not parsed.hostname:
            client.sendall(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
            return
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        path = urllib.parse.urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
        headers = [line for line in lines[1:] if not line.lower().startswith(("proxy-connection:", "connection:"))]
        request = f"{method} {path} {version}\r\n" + "\r\n".join(headers) + "\r\nConnection: close\r\n\r\n"
        upstream = create_connection((parsed.hostname, port), timeout=20)
        upstream.sendall(request.encode("iso-8859-1") + rest)
        relay(client, upstream)
    except Exception:
        try:
            client.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
        except OSError:
            pass
    finally:
        client.close()
        if upstream:
            upstream.close()


def proxy_client(client: socket.socket, address: tuple[str, int]) -> None:
    try:
        client.settimeout(30)
        first = recv_exact(client, 1)
        if first == b"\x05":
            socks5_client(client, first, address)
        else:
            http_client(client, first)
    except Exception:
        try:
            client.close()
        except OSError:
            pass


def start_proxy_server(host: str, port: int) -> None:
    try:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((host, port))
        server.listen(256)
        print("HTTP proxy: TCP only", flush=True)
        print("SOCKS5 proxy: TCP CONNECT + UDP ASSOCIATE", flush=True)
        print(f"TCP control listener: {host}:{port}", flush=True)
        print(f"UDP upstream interface: {get_tun_interface()}", flush=True)
        print("UDP policy: fail closed, no default-route fallback", flush=True)
    except Exception as e:
        print(f"[ERROR] Failed to start HTTP/SOCKS5 proxy on {host}:{port}: {e}", flush=True)
        return

    while True:
        try:
            client, address = server.accept()
            threading.Thread(target=proxy_client, args=(client, address), daemon=True).start()
        except Exception as e:
            print(f"[ERROR] Proxy accept failed: {e}", flush=True)
            time.sleep(0.5)
