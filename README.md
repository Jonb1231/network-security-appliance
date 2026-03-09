# Network Security Appliance

A Python-based simulated network security appliance that processes synthetic packet captures and applies firewall, routing, NAT/PAT, and connection-tracking logic across four interfaces:

- `mgt` — management network
- `int` — internal network
- `dmz` — DMZ network
- `ext` — external network

This project was originally built as a university networking/security assignment and then cleaned up for portfolio use.

## What it demonstrates

- Packet parsing from a custom capture format
- Multi-interface routing logic
- Policy-based firewall decisions
- ICMP filtering and rate limiting
- NAT/PAT translation
- TCP/UDP handling
- Basic TCP connection-state tracking
- DMZ service forwarding for HTTP/HTTPS/SSH

## Architecture overview

Main components in `appliance.py`:

- `Interface` — represents a simulated network interface
- `InterfaceHandler` — reads packet data from `.spcap` files and sends packets through interfaces
- `PacketEngine` — core firewall/routing/NAT logic
- `RouteTable` — resolves destination interface by subnet
- `PatTable` — stores internal ↔ translated port mappings
- `Connections` — tracks simplified connection state

## Key behaviors implemented

### Firewall and routing
- Validates custom packet header format
- Routes packets based on longest-prefix subnet matching
- Enforces special policy handling for the management interface
- Drops disallowed traffic and prints alerts for policy violations

### ICMP policy
- Allows ICMP echo requests only
- Drops oversized pings
- Applies per-source ping rate limiting
- Generates synthetic echo replies

### NAT / PAT
- Supports outbound PAT for internal and DMZ traffic to the external network
- Rewrites source IP/port for outbound TCP and UDP flows
- Restores internal destination mappings for return traffic

### Service exposure
- Forwards inbound external HTTP/HTTPS traffic to a DMZ web server
- Forwards inbound external SSH traffic to a DMZ jump box

### Connection tracking
- Tracks simplified TCP states such as:
  - `new`
  - `syn_sent`
  - `established`
  - `closed`
- Includes basic half-open connection counting and SYN-flood mitigation behavior

## Repo note

This public version includes the main appliance implementation file only. The original assignment likely also used supporting files such as:

- `support.py`
- sample `.spcap` traffic files
- assignment specification / test harness

Those files are not included here, so this repository is best viewed as a code sample rather than a fully runnable standalone product.

## How I would extend this further

If I were continuing this project, I would:

1. split the code into modules (`routing.py`, `nat.py`, `policy.py`, `connections.py`)
2. add unit tests for packet parsing and policy behavior
3. create a reproducible CLI demo with sample packet files
4. replace print-based output with structured logging
5. document packet format assumptions more explicitly

## Why this is in my portfolio

I’m using this project to showcase:

- systems-style Python programming
- networking fundamentals
- security policy reasoning
- stateful packet-processing logic
- code written under assignment/spec constraints
