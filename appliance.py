# DO NOT modify or add any import statements
from __future__ import annotations
import re
import os
import sys
import struct
import random
import ipaddress
from dataclasses import dataclass, field
from typing import Dict, Tuple, Optional, List, Any
from support import *
# DO NOT modify or add any import statements

"""
Include your name and student number here (because everybody is submitting 'appliance.py')
"""

# Author: Jonathan Burrell
# -----------------------------------------------------------------------------

"""
Originally developed as a university networking/security assignment and adapted here as a portfolio sample.

Public portfolio note:
- Assignment-specific identifiers were removed for publishing.
- This repository focuses on the core packet-processing and policy logic.
"""

# -----------------------------------------------------------------------------

# Define your classes and functions here

class Interface:
    def __init__(self, name: str, mac: str, ip: str, netmask: str, default_route: str = "0.0.0.0"):
        self.name = name
        self.mac = mac  # should be in format "xx:yy:zz:aa:bb:cc"
        self.ip = ip
        self.netmask = netmask
        self.default_route = default_route

    # --- GETTER/SETTER -------------------------------------------------------------
    def get_mac(self):
        return self.mac  # should be in format "xx:yy:zz:aa:bb:cc"

    def set_mac(self, mac_address: str):
        self.mac = mac_address  # should be in format "xx:yy:zz:aa:bb:cc"

    def get_ip(self):
        return self.ip

    def set_ip(self, ip: str):
        self.ip = ip

    def get_mask(self):
        return self.netmask

    def set_mask(self, mask: str):
        self.netmask = mask

    def get_default(self):
        return self.default_route

    def set_default(self, ip_address: str):
        self.default_route = ip_address

    # --- packet sending -------------------------------------------------------------

    def send_packet(self, packet: bytes):
        """
        simulates sending a “packet” (supplied as raw bytes) out that interface, by printing a message from the
        appropriate interface as “mgt|int|dmz|ext: sent packet ” + the entire packet as a string in hexadecimal digits.
        """
        print(f"{self.name}: sent packet {bytes(packet).hex()}")

class InterfaceHandler:
    def __init__(self, traffic_path: str = "traffic.spcap"):
        # Where the special capture file lives
        self.traffic_path: str = traffic_path
        self._fh = None  # text-mode; file is hex lines

        # Instantiate the four NICs with the spec’s MACs and CIDRs
        self.interfaces = {
            "mgt": Interface("mgt", "28:ee:52:85:f2:3a", "192.168.96.23", "255.255.240.0"),
            "int": Interface("int", "28:ee:52:e2:b7:30", "10.0.0.1", "255.255.0.0"),
            "dmz": Interface("dmz", "28:ee:52:4c:4d:70", "10.1.0.1", "255.255.255.0"),
            "ext": Interface("ext", "28:ee:52:9c:61:ab", "130.102.184.1", "255.255.255.0")
        }

    def __enter__(self):
        # Sample.spcap uses one lowercase-hex frame per line
        self._fh = open(self.traffic_path, "r", encoding="ascii", errors="strict")
        return self

    def __exit__(self, exc_type, exc, tb):
        if self._fh:
            self._fh.close()
            self._fh = None

    def next_packet(self):
        """
        Read the next hex line, convert to bytes, return it; None at EOF.
        """
        if self._fh is None:
            self.__enter__()

        for line in self._fh:
            s = line.strip()

            if not s or s.startswith("#"):
                continue  # skip blanks/comments if any

            # ensure even number of hex digits
            if len(s) % 2 != 0:
                raise ValueError(f"odd length hex line")

            try:
                raw = bytes.fromhex(s)
            except ValueError:
                raise ValueError("Could not read bytes from hex")  # or raise

            # first byte must have 101010 in top 6 bits
            first = raw[0]
            if (first >> 2) != 0b101010:
                raise ValueError(f"Incorrect byte header: {first} != 101010")

            return raw

        return None

    def send_packet(self, interface: str, packet: bytes):
        key = interface.strip().lower()
        nic = self.interfaces.get(key)

        if nic is None:
            raise ValueError(f"unknown interface: {interface} (expected mgt/int/dmz/ext)")

        nic.send_packet(bytes(packet))

    def mgt_packet(self, packet: bytes):
        print(f"Actioned management packet " + bytes(packet).hex())


class PatTable:
    '''
    Records a table that tracks the mappings from internal ports/addresses to firewall ports/addresses (49152- 65535)
    '''
    def __init__(self, out_address: str):
        self.out_address = out_address
        self.EPHEMERAL_START = 49152
        self.EPHEMERAL_END = 65535
        # (in_ip, in_port) -> out_port
        self.out_map: dict[tuple[str,int], int] = {}
        # out_port -> (in_ip, in_port)
        self.in_map: dict[int, tuple[str, int]] = {}

    def set_pat(self, in_address: str, in_port: int, out_port: int):
        key = (in_address, in_port)

        # already mapped - reuse silently
        if key in self.out_map:
            return self.out_map[key]

        # Ensure chosen external port isn't held by a different mapping
        if out_port in self.in_map and self.in_map[out_port] != key:
            raise ValueError(f"PAT: out_port {out_port} already mapped")

        # Record both directions
        self.out_map[key] = out_port
        self.in_map[out_port] = key

        # Print in the exact format the tests expect
        print(f"NAT: allocate {in_address}:{in_port} -> {self.out_address}:{out_port}")
        return out_port

    def get_unused_port(self) -> int:
        while True:
            p = random.randint(self.EPHEMERAL_START, self.EPHEMERAL_END)
            if p not in self.in_map:
                return p

    def get_pat_in(self, out_port: int) -> str | None:
        pair = self.in_map.get(out_port)
        # returns the "in_ip:in_port" for a given external port or none
        return None if pair is None else f"{pair[0]}:{pair[1]}"

    def get_pat_out(self, in_address: str, in_port: int) -> int | None:
        # Return the external port for (in_ip, in_port), or none if missing.
        return self.out_map.get((in_address, in_port))

class PacketEngine:
    def __init__(self, ih):
        # ih is the InterfaceHandler
        self.ih = ih
        self.route_table = RouteTable()
        self.interface_map = {0: "mgt", 1: "int", 2: "dmz", 3: "ext"}
        self.dmz_web_ip = "10.1.0.54"  # web server (80/443)
        self.dmz_jump_ip = "10.1.0.92"  # SSH jump box (22)

        # connection tracking
        self.conns = Connections()

        # PAT table (we use the firewall's external IP)
        ext_ip = self.ih.interfaces["ext"].get_ip()
        self.pat = PatTable(ext_ip)

        # ICMP rate-limit bookkeeping
        self.icmp_allow_left = {}  # src_ip -> remaining echos (start at 5)
        self.non_icmp_since = 0    # counter for non-ICMP packets to reset allowance

    def get_proto(self, p: bytes) -> int:
        return p[15]

    def get_src_ip(self, p: bytes) -> str:
        return int_to_ip(int.from_bytes(p[16:20], "big"))

    def get_dst_ip(self, p: bytes) -> str:
        return int_to_ip(int.from_bytes(p[20:24], "big"))

    def get_udp_ports(self, p: bytes) -> tuple[int, int]:
        # bytes 24:26 sport, 26:28 dport
        return (int.from_bytes(p[24:26], "big"), int.from_bytes(p[26:28], "big"))

    def get_tcp_ports(self, p: bytes) -> tuple[int, int]:
        # bytes 24:26 sport, 26:28 dport
        return (int.from_bytes(p[24:26], "big"), int.from_bytes(p[26:28], "big"))

    def get_tcp_flags(self, p: bytes) -> int:
        # simplified: flags at byte 36 in our synthetic header
        return p[36] if len(p) > 36 else 0

    def get_icmp_type_code(self, p: bytes) -> tuple[int, int]:
        # 24:type, 25:code
        return (p[24], p[25])

    def get_payload(self, p: bytes) -> bytes:
        proto = self.get_proto(p)
        if proto == 1:  # ICMP
            return p[30:]
        elif proto == 6:  # TCP
            return p[37:]
        elif proto == 17:  # UDP
            return p[28:]
        return b""

    def check_header(self, packet: bytes):
        if not packet:
            raise ValueError("Empty Packet (204)")
        byte_0 = packet[0]
        return (byte_0 >> 2) == 0b101010

    def get_interface(self, packet: bytes):
        # check empty packet
        if not packet:
            raise ValueError("Empty packet")

        # mask the first 6 bits
        interface_bits = packet[0] & 0b00000011
        if interface_bits in self.interface_map:
            return self.interface_map[interface_bits]
        else:
            raise ValueError(f"Malformed first byte: {packet[0]} is not a valid")

    def mac_to_string(self, b: bytes):
        return ":".join(f"{octet:02x}" for octet in b)

    def get_dest_mac(self, packet: bytes):
        return packet[1:7]

    def get_source_mac(self, packet: bytes):
        return packet[7:13]

    def get_ethernet(self, packet: bytes):
        return packet[13:15]

    def _set_src_ip(self, b: bytearray, ip: str) -> None:
        b[16:20] = ip_to_int(ip).to_bytes(4, "big")

    def _set_dst_ip(self, b: bytearray, ip: str) -> None:
        b[20:24] = ip_to_int(ip).to_bytes(4, "big")

    def _set_udp_sport(self, b: bytearray, port: int) -> None:
        b[24:26] = port.to_bytes(2, "big")

    def _set_udp_dport(self, b: bytearray, port: int) -> None:
        b[26:28] = port.to_bytes(2, "big")

    def _set_tcp_sport(self, b: bytearray, port: int) -> None:
        b[24:26] = port.to_bytes(2, "big")

    def _set_tcp_dport(self, b: bytearray, port: int) -> None:
        b[26:28] = port.to_bytes(2, "big")

    def _alloc_ephemeral(self) -> int:
        # try random first
        for _ in range(2000):
            p = random.randint(self.pat.EPHEMERAL_START, self.pat.EPHEMERAL_END)
            if p not in self.pat.in_map:
                return p
        # fallback: scan
        for p in range(self.pat.EPHEMERAL_START, self.pat.EPHEMERAL_END + 1):
            if p not in self.pat.in_map:
                return p
        raise RuntimeError("No ephemeral ports available")

    def _tcp_state_from_flags(self, src_ip: str, sport: int, dst_ip: str, dport: int, flags: int) -> str:
        # flags (we only care about SYN/ACK/FIN/RST)
        syn = bool(flags & 0x02)
        ack = bool(flags & 0x10)
        fin = bool(flags & 0x01)
        rst = bool(flags & 0x04)

        prev = self.conns.get_state(6, src_ip, sport, dst_ip, dport)

        if fin or rst:
            return "closed"
        if syn and not ack:
            return "syn_sent"
        if ack and (prev in (None, "new", "syn_sent") or syn):
            return "established"
        return prev or "new"

    def process_packet(self, packet: bytes):
        """
        manages all the processing: performs security checks
        or routing the “packets” to the correct interfaces
        """
        # start by checking the header has the correct prefix
        if not self.check_header(packet):
            raise ValueError("Packet does not have correct prefix")

        ingress = self.get_interface(packet)

        # Pre-routing policy (handles mgt + all ICMP)
        if self.check_packet(packet):
            return

        # From here: non-ICMP (TCP/UDP) only
        proto = self.get_proto(packet)
        src_ip = self.get_src_ip(packet)
        dst_ip = self.get_dst_ip(packet)

        # count non-ICMP (for ping allowance reset)
        if proto != 1:
            self.non_icmp_since += 1
            if self.non_icmp_since >= 5:
                # reset all sources to 5 allowed pings
                self.icmp_allow_left = {}
                self.non_icmp_since = 0

        # --- UDP (DNS) ---
        if proto == 17:
            sport, dport = self.get_udp_ports(packet)

            # Outbound DNS from int/dmz -> ext is allowed via PAT
            if ingress in ("int", "dmz") and dport == 53 and self.route_table.resolve(dst_ip) == "ext":
                b = bytearray(packet)
                # allocate/reuse ext ephemeral for this (src_ip, sport)
                out_port = self.pat.set_pat(src_ip, sport, self._alloc_ephemeral())
                # SNAT: change source to firewall ext IP:ephemeral
                self._set_src_ip(b, self.pat.out_address)
                self._set_udp_sport(b, out_port)
                self.route_packet("ext", bytes(b))
                return

            # Replies from ext -> our PAT ephemeral: translate back to internal
            if ingress == "ext":
                # if reply is to a PAT'ed port, deliver inside
                if dport in self.pat.in_map:
                    in_ip, in_port = self.pat.in_map[dport]
                    b = bytearray(packet)
                    self._set_dst_ip(b, in_ip)
                    self._set_udp_dport(b, in_port)
                    self.route_packet(self.route_table.resolve(in_ip), bytes(b))
                    return

                # New inbound DNS query to us on ext: silently drop
                if dport == 53:
                    return
            # Drop other unsolicited UDP arriving on ext
            if ingress == "ext":
                return

            # default UDP path
            self.route_packet(self.route_table.resolve(dst_ip), packet)
            return

        # --- TCP: DNS on TCP 53 via PAT  ---
        if proto == 6:
            sport, dport = self.get_tcp_ports(packet)
            flags = self.get_tcp_flags(packet)
            is_new_incoming = (flags & 0x02) and not (flags & 0x10)  # SYN without ACK

            # New inbound DNS on ext is not served here: silently drop
            if ingress == "ext" and dport == 53 and is_new_incoming:
                return

            # SYN-flood: if >100 half-open, purge and alert, then drop
            if is_new_incoming and self.conns.half_open_count() > 100:
                self.conns.purge_half_open()
                print("ALERT drop: too many incomplete connections")
                return

            # --- Allow outbound TCP/53 via PAT (DNS over TCP) ---
            if ingress in ("int", "dmz") and dport == 53 and self.route_table.resolve(dst_ip) == "ext":
                b = bytearray(packet)
                out_port = self.pat.set_pat(src_ip, sport, self._alloc_ephemeral())
                self._set_src_ip(b, self.pat.out_address)
                self._set_tcp_sport(b, out_port)
                state = self._tcp_state_from_flags(src_ip, sport, dst_ip, dport, flags)
                self.conns.add_or_update(ingress, 6, src_ip, sport, dst_ip, dport, state)
                self.route_packet("ext", bytes(b))
                return

            # --- ext -> (80/443) proxy to DMZ webserver ---
            if ingress == "ext" and dport in (80, 443):
                b = bytearray(packet)
                self._set_dst_ip(b, self.dmz_web_ip)
                state = self._tcp_state_from_flags(src_ip, sport, self.dmz_web_ip, dport, flags)
                self.conns.add_or_update(ingress, 6, src_ip, sport, self.dmz_web_ip, dport, state)
                self.route_packet("dmz", bytes(b))
                # ensure PAT for webserver replies
                self.pat.set_pat(self.dmz_web_ip, dport, self._alloc_ephemeral())
                return

            # --- ext -> 22 proxy to DMZ jump box ---
            if ingress == "ext" and dport == 22:
                b = bytearray(packet)
                self._set_dst_ip(b, self.dmz_jump_ip)
                state = self._tcp_state_from_flags(src_ip, sport, self.dmz_jump_ip, dport, flags)
                self.conns.add_or_update(ingress, 6, src_ip, sport, self.dmz_jump_ip, dport, state)
                self.route_packet("dmz", bytes(b))
                self.pat.set_pat(self.dmz_jump_ip, 22, self._alloc_ephemeral())
                return

            # --- allow new HTTP/HTTPS on the internal interface (no proxy) ---
            if ingress == "int" and dport in (80, 443):
                # treat as a permitted new connection from int; no NAT unless it's going to ext
                egress = self.route_table.resolve(dst_ip)
                b = bytearray(packet)
                # if this int HTTP/HTTPS goes to ext, SNAT via PAT to ext IP
                if egress == "ext":
                    out_port = self.pat.set_pat(src_ip, sport, self._alloc_ephemeral())
                    self._set_src_ip(b, self.pat.out_address)
                    self._set_tcp_sport(b, out_port)
                state = self._tcp_state_from_flags(src_ip, sport, dst_ip, dport, flags)
                self.conns.add_or_update(ingress, 6, src_ip, sport, dst_ip, dport, state)
                self.route_packet(egress, bytes(b))
                return

            # --- Replies from DMZ back to Internet: SNAT via PAT to ext IP ---
            if ingress == "dmz" and self.route_table.resolve(dst_ip) == "ext":
                # web server replies (80/443)
                if src_ip == self.dmz_web_ip and sport in (80, 443):
                    b = bytearray(packet)
                    out_port = self.pat.set_pat(self.dmz_web_ip, sport, self._alloc_ephemeral())
                    self._set_src_ip(b, self.pat.out_address)
                    self._set_tcp_sport(b, out_port)
                    state = self._tcp_state_from_flags(src_ip, sport, dst_ip, dport, flags)
                    self.conns.add_or_update(ingress, 6, src_ip, sport, dst_ip, dport, state)
                    self.route_packet("ext", bytes(b))
                    return
                # SSH jump-box replies (22)
                if src_ip == self.dmz_jump_ip and sport == 22:
                    b = bytearray(packet)
                    out_port = self.pat.set_pat(self.dmz_jump_ip, 22, self._alloc_ephemeral())
                    self._set_src_ip(b, self.pat.out_address)
                    self._set_tcp_sport(b, out_port)
                    state = self._tcp_state_from_flags(src_ip, sport, dst_ip, dport, flags)
                    self.conns.add_or_update(ingress, 6, src_ip, sport, dst_ip, dport, state)
                    self.route_packet("ext", bytes(b))
                    return

            # --- Replies from ext back to a PAT'ed ephemeral → translate inside ---
            if ingress == "ext" and dport in self.pat.in_map:
                in_ip, in_port = self.pat.in_map[dport]
                b = bytearray(packet)
                self._set_dst_ip(b, in_ip)
                self._set_tcp_dport(b, in_port)
                state = self._tcp_state_from_flags(src_ip, sport, in_ip, in_port, flags)
                self.conns.add_or_update(ingress, 6, src_ip, sport, in_ip, in_port, state)
                self.route_packet(self.route_table.resolve(in_ip), bytes(b))
                return

            # --- int -> ext SSH via PAT ---
            if ingress == "int" and dport == 22 and self.route_table.resolve(dst_ip) == "ext":
                b = bytearray(packet)
                out_port = self.pat.set_pat(src_ip, sport, self._alloc_ephemeral())
                self._set_src_ip(b, self.pat.out_address)
                self._set_tcp_sport(b, out_port)
                state = self._tcp_state_from_flags(src_ip, sport, dst_ip, dport, flags)
                self.conns.add_or_update(ingress, 6, src_ip, sport, dst_ip, dport, state)
                self.route_packet("ext", bytes(b))
                return

            # --- int <-> dmz SSH allowed without PAT ---
            if dport == 22 and ((ingress == "int" and self.route_table.resolve(dst_ip) == "dmz") or
                                (ingress == "dmz" and self.route_table.resolve(dst_ip) == "int")):
                state = self._tcp_state_from_flags(src_ip, sport, dst_ip, dport, flags)
                self.conns.add_or_update(ingress, 6, src_ip, sport, dst_ip, dport, state)
                self.route_packet(self.route_table.resolve(dst_ip), packet)
                return

            # --- Default policy: reject new incoming TCP on ext unless proxied above ---
            if ingress == "ext" and is_new_incoming and dport not in (80, 443, 22):
                print("ALERT drop: new incoming TCP not allowed by policy")
                return

            # --- Default TCP path ---
            state = self._tcp_state_from_flags(src_ip, sport, dst_ip, dport, flags)
            self.conns.add_or_update(ingress, 6, src_ip, sport, dst_ip, dport, state)
            self.route_packet(self.route_table.resolve(dst_ip), packet)
            return

            # --- anything else: default route by destination IP ---
        self.route_packet(self.route_table.resolve(dst_ip), packet)

    def check_packet(self, packet: bytes):
        """
        Pre-routing policy hook.
        Returns True if the packet was fully handled here (dropped or replied),
        False if normal processing should continue in process_packet.
        """
        ingress = self.get_interface(packet)
        proto = self.get_proto(packet)

        # 1) Management NIC: print and stop
        if ingress == "mgt":
            src_ip = self.get_src_ip(packet)
            if proto == 6:  # TCP
                sport, dport = self.get_tcp_ports(packet)
                flags = self.get_tcp_flags(packet)
                is_new_incoming = (flags & 0x02) and not (flags & 0x10)  # SYN without ACK
                # Allow SSH only from 192.168.96.9
                if dport == 22 and src_ip == "192.168.96.9":
                    self.ih.mgt_packet(packet)
                    return True
                # Drop other new incoming TCP on mgt with alert
                if is_new_incoming:
                    print("ALERT drop: new incoming TCP not allowed by policy")
                    return True
                # Otherwise silently drop TCP on mgt
                return True
            # Drop all UDP/ICMP on mgt
            return True

        # 2) ICMP policy
        if proto == 1:
            src_ip = self.get_src_ip(packet)
            icmp_type, icmp_code = self.get_icmp_type_code(packet)
            payload = self.get_payload(packet)

            # Echo-request only
            if icmp_type == 8:
                # oversize > 64 bytes
                if len(payload) > 64:
                    print(f"ALERT drop: oversize ping from {src_ip} ({len(payload)} bytes)")
                    return True

                # per-source allowance: 5, reset after 5 non-ICMP packets
                left = self.icmp_allow_left.get(src_ip, 5)
                if left <= 0:
                    print(f"ALERT drop: ping rate limit from {src_ip}")
                    return True
                self.icmp_allow_left[src_ip] = left - 1

                # build echo-reply (type=0), swap MACs + IPs, keep payload
                b = bytearray(packet)
                # swap MACs
                b[1:7], b[7:13] = packet[7:13], packet[1:7]
                # swap IPs
                b[16:20], b[20:24] = packet[20:24], packet[16:20]
                # ICMP type -> reply
                b[24] = 0

                # route reply toward the source IP
                egress = self.route_table.resolve(src_ip)
                self.route_packet(egress, bytes(b))
                return True

            # all other ICMP types are not allowed by policy
            print(f"ALERT drop: ICMP type {icmp_type}:{icmp_code} not allowed by policy")
            return True

        # Not handled here -> let process_packet continue
        return False

    def route_packet(self, interface: str, packet: bytes):
        """
        that simulates sending a packet to that interface for sending.
        """
        # Print before sending (matches sample_output ordering)
        print(f"ROUTE to {interface}")

        # Set low 2 bits (egress NIC) in the first byte
        code = IFACE_CODES[interface]
        b = bytearray(packet)
        b[0] = (b[0] & 0b11111100) | code

        # Send
        self.ih.send_packet(interface, bytes(b))


class RouteTable:
    def __init__(self):
        self.x = None

    def resolve(self, ip):
        """
        Longest-prefix match among local subnets; default to 'ext'.
        """
        try:
            validate_ipv4(ip)
        except Exception:
            return "ext"

        # Local subnets
        nets = {
            "mgt": ipaddress.IPv4Network("192.168.96.0/20"),
            "int": ipaddress.IPv4Network("10.0.0.0/16"),
            "dmz": ipaddress.IPv4Network("10.1.0.0/24"),
            "ext": ipaddress.IPv4Network("130.102.184.0/24"),
        }

        addr = ipaddress.IPv4Address(ip)
        best = ("ext", -1)  # (iface, prefixlen)
        for iface, net in nets.items():
            if addr in net and net.prefixlen > best[1]:
                best = (iface, net.prefixlen)
        return best[0]




class Connections:
    """maintains a table of connections"""
    def __init__(self):
        # key: canonicalized 5-tuple (proto, (ip1,port1), (ip2,port2))
        # value: {"state": "new|syn_sent|established|closed", "last_nic": "mgt|int|dmz|ext"}
        self._table: dict[tuple, dict] = {}

    def _canon(self, proto: int, a_ip: str, a_p: int, b_ip: str, b_p: int):
        a = (a_ip, a_p)
        b = (b_ip, b_p)
        ep = (a, b) if a <= b else (b, a)
        return (proto, ep)

    def add_or_update(
        self,
        nic: str,
        proto: int,
        src_ip: str,
        src_port: int,
        dst_ip: str,
        dst_p: int,
        state: str,
    ):
        """
        for interface(mgt / int / dmz / ext), protocol,
        source address and port, destination address and port,
        the connection state (“new”, “syn_sent”, “established”, “closed”)
        """
        key = self._canon(proto, src_ip, src_port, dst_ip, dst_p)
        prev = self._table.get(key, {}).get("state")

        # simple progression rules: don't regress established -> syn_sent/new
        if prev == "established" and state in ("new", "syn_sent"):
            state = "established"

        self._table[key] = {"state": state, "last_nic": nic}

    # ------- helpers -------

    def get_state(self, proto: int, src_ip: str, src_port: int, dst_ip: str, dst_p: int):
        key = self._canon(proto, src_ip, src_port, dst_ip, dst_p)
        entry = self._table.get(key)
        return entry["state"] if entry else None

    def state(self, *args):
        if len(args) == 5:
            proto, src_ip, src_port, dst_ip, dst_p = args
        elif len(args) == 6:
            _, proto, src_ip, src_port, dst_ip, dst_p = args
        else:
            raise TypeError("state() expects 5 or 6 positional args")
        return self.get_state(proto, src_ip, src_port, dst_ip, dst_p)

    def half_open_count(self) -> int:
        # half-open means syn_sent
        return sum(1 for v in self._table.values() if v["state"] == "syn_sent")

    def purge_half_open(self) -> None:
        self._table = {k: v for k, v in self._table.items() if v["state"] != "syn_sent"}

# ------------------- Simulator runner -------------------
# DO NOT MODIFY the run_appliance definition IN ANY WAY
# It MUST work as run_appliance("filename.spcap") as defined here

def run_appliance(cap_file: str = "traffic.spcap") -> None:
    ih = InterfaceHandler(cap_file)
    pe = PacketEngine(ih)
    while True:
        raw = ih.next_packet()
        if raw is None:
            break
        pe.process_packet(raw)

# --------------- Main ---------------
# DO NOT modify the run_appliance call
# It MUST work as run_appliance("traffic.spcap")
#
# Leaving a main() wrapper for those who like it
# You could just as easily run_appliance("traffic.spcap") directly
# instead of calling main() to do it

def main():
    run_appliance("traffic.spcap")

if __name__ == "__main__":
    main()