# SpaceSec Shield

Lightweight secure communication and real-time monitoring framework for CubeSat-style UDP links.

## Overview

SpaceSec Shield is an academic cybersecurity project that demonstrates a secure command link between a Ground Station and a Satellite Node inside an isolated three-VM lab. The project starts from a basic UDP command/response channel, then adds cryptographic protection, attack validation, and a real-time monitoring dashboard.

The system is designed to show how constrained satellite-style communication can be protected against plaintext exposure, forged commands, replay attacks, packet tampering, and unsafe execution.

## Architecture

The lab consists of three virtual machines connected through an isolated internal network.

| Node | Role | IP Address |
|---|---|---|
| Ground Station | Sends mission commands and hosts the monitoring dashboard | `192.168.10.10` |
| Satellite Node | Receives, verifies, and executes valid commands | `192.168.10.20` |
| Kali Attacker | Performs monitoring and attack simulation | `192.168.10.30` |

Main communication port:

```text
UDP 9000
```

## Project Phases

### Phase 2 — Communication Core

Phase 2 implements the baseline two-way UDP communication channel using C++ BSD sockets.

The Ground Station sends a command, and the Satellite Node receives it, processes it, and returns an acknowledgement.

Files:

```text
phase2_communication/
├── ground_sender.cpp
└── sat_receiver.cpp
```

Build and run:

```bash
# On Satellite Node
g++ sat_receiver.cpp -o sat_receiver
./sat_receiver

# On Ground Station
g++ ground_sender.cpp -o ground_sender
./ground_sender
```

Expected result:

```text
Command sent: CMD: STATUS_CHECK
Response received: ACK: CMD: STATUS_CHECK
```

Phase 2 also uses Linux Traffic Control to simulate space-link delay, jitter, and packet loss:

```bash
sudo tc qdisc add dev ens33 root netem delay 500ms 100ms distribution normal loss 10%
sudo tc qdisc change dev ens33 root netem delay 800ms loss 50%
sudo tc qdisc show dev ens33
sudo tc qdisc del dev ens33 root
```

---

### Phase 3 — Security Layer

Phase 3 adds a secure communication layer on top of the UDP channel.

Security mechanisms:

- X25519 ECDH key exchange
- HKDF-SHA256 session key derivation
- ChaCha20-Poly1305 AEAD encryption
- Timestamp freshness validation
- Nonce-based anti-replay protection
- Verify-before-execute receiver policy

Files:

```text
phase3_security_layer/
├── secure_ground_station.cpp
├── secure_satellite_node.cpp
├── handshake.cpp
├── handshake.hpp
├── crypto.cpp
├── crypto.hpp
├── packet.cpp
├── packet.hpp
├── anti_replay.cpp
└── anti_replay.hpp
```

Build:

```bash
# Ground Station
g++ -std=c++17 secure_ground_station.cpp handshake.cpp crypto.cpp packet.cpp anti_replay.cpp -o secure_ground -lssl -lcrypto

# Satellite Node
g++ -std=c++17 secure_satellite_node.cpp handshake.cpp crypto.cpp packet.cpp anti_replay.cpp -o secure_satellite -lssl -lcrypto
```

Run order:

```bash
# Start Satellite first
./secure_satellite

# Then start Ground Station
./secure_ground
```

Security result:

```text
Valid encrypted commands are accepted.
Replayed packets are rejected.
Tampered packets are rejected.
Expired packets are rejected.
Plaintext commands are not visible in packet captures.
```

---

### Phase 4 — Penetration Testing

Phase 4 validates the secure channel against realistic adversarial scenarios from the Kali attacker VM.

Tested scenarios:

- UDP service discovery
- Command injection
- Replay attack
- Packet tampering
- UDP flooding / DoS
- MITM observation
- Traffic analysis

Files:

```text
phase4_attack_testing/
```

Example commands:

```bash
# UDP service discovery
sudo nmap -sU -p 9000 192.168.10.20

# Raw command injection attempt
echo "CMD: SELF_DESTRUCT" | nc -u 192.168.10.20 9000

# Capture UDP traffic
sudo tcpdump -i eth0 udp port 9000 -w capture.pcap

# Replay captured packets
sudo tcpreplay --intf1=eth0 capture.pcap

# UDP flood simulation
sudo hping3 --udp -p 9000 -d 120 -E /dev/urandom --flood 192.168.10.20
```

Observed results:

```text
Forged commands were rejected.
Replay attempts were rejected.
Tampered packets failed AEAD verification.
Plaintext commands were not visible in Wireshark.
The system remained operational during UDP flooding, although availability can still degrade.
```

---

### Phase 5 — Monitoring Dashboard

Phase 5 implements a real-time monitoring dashboard that visualizes accepted and rejected packet decisions.

Technology stack:

- Python
- Flask
- Chart.js
- HTTP/JSON
- C++ raw-socket dashboard client

Files:

```text
phase5_dashboard/
├── dashboard.py
├── dashboard_client.cpp
├── dashboard_client.hpp
├── secure_satellite_node.cpp
└── templates/
    └── index.html
```

Run dashboard:

```bash
cd phase5_dashboard
python3 dashboard.py
```

Open in browser:

```text
http://localhost:5000
```

The Satellite Node reports packet decisions to the dashboard using JSON events.

Example event types:

```text
ACCEPTED / OK
REJECTED / BAD_FORMAT
REJECTED / DUP_NONCE
REJECTED / REPLAY_TS
REJECTED / TAG_FAIL
```

Dashboard output includes:

- Accepted packet count
- Rejected packet count
- Average latency
- Link status
- Real-time security alert feed
- Critical attack visualization

---

## Repository Structure

```text
SpaceSec-Shield/
├── docs/
│   ├── final_report.pdf
│   ├── phase2_report.pdf
│   ├── phase4_report.pdf
│   └── phase5_report.pdf
├── evidence/
│   └── pcaps/
│       └── spacesec_phase3.pcapng
├── phase2_communication/
│   ├── ground_sender.cpp
│   └── sat_receiver.cpp
├── phase3_security_layer/
│   ├── secure_ground_station.cpp
│   ├── secure_satellite_node.cpp
│   ├── handshake.cpp
│   ├── handshake.hpp
│   ├── crypto.cpp
│   ├── crypto.hpp
│   ├── packet.cpp
│   ├── packet.hpp
│   ├── anti_replay.cpp
│   └── anti_replay.hpp
├── phase4_attack_testing/
├── phase5_dashboard/
│   ├── dashboard.py
│   ├── dashboard_client.cpp
│   ├── dashboard_client.hpp
│   ├── secure_satellite_node.cpp
│   └── templates/
│       └── index.html
├── .gitignore
└── README.md
```

## Security Properties

| Property | Mechanism | Result |
|---|---|---|
| Confidentiality | ChaCha20 encryption | Plaintext commands are not visible |
| Integrity | Poly1305 AEAD tag | Modified packets are rejected |
| Authenticity | Session-key-based AEAD | Forged packets fail verification |
| Replay Protection | Timestamp + nonce cache | Replayed packets are rejected |
| Stability | UDP timeout handling | Lost replies do not freeze the sender |
| Visibility | Flask dashboard | Security decisions are shown in real time |

## Limitations

This project is a controlled academic prototype and not a flight-ready satellite security protocol.

Known limitations:

- The ECDH handshake establishes a shared secret but does not fully authenticate peer identity.
- Active key-replacement MITM attacks require additional defenses such as certificates, signatures, or pre-shared public keys.
- Cryptography cannot fully prevent availability degradation under heavy flooding or RF jamming.
- Dashboard state is stored in memory only.
- The monitoring channel uses HTTP inside an isolated lab environment.
- Real hardware testing would be required before claiming operational readiness.

## Future Work

Potential improvements:

- Add authenticated handshake using certificates or digital signatures.
- Compare ChaCha20-Poly1305 with AES-GCM and Ascon-AEAD.
- Add persistent dashboard logging.
- Separate the monitoring channel from the command channel.
- Add rate limiting and packet filtering.
- Test on embedded hardware such as Raspberry Pi.
- Add fuzzing for malformed packets and handshake inputs.
- Create a formal threat model using STRIDE or MITRE ATT&CK mappings.

## Disclaimer

This project is for academic and defensive cybersecurity education only.

All testing was performed inside an isolated virtual lab environment owned and controlled by the project team. Do not use the attack simulation commands or techniques against any system without explicit authorization.
