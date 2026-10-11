# Protocol and transaction contract

## Identity and transport

One bounded UDP broadcast to port 6811 sends `000000000011` from the explicitly selected Mac IPv4 address. Discovery must produce one unambiguous gateway candidate. A TCP VIN read on port 6801, tester address `0xF4`, gateway diagnostic address `0x10`, service `22 F1 90`, must match the discovered VIN. No saved vehicle identity is built into the tool.

macOS interface binding, source address, link, subnet and route checks precede connections and transmissions. Native module SVK reads (`22 F1 01`) must match the selected CAFD/BTLD software tuple. The gateway IP, diagnostic address, group and parameter offsets are different concepts; users select the module role and named parameter path.

HSFZ uses a four-byte big-endian body length and two-byte control word. Diagnostic and acknowledgement bodies contain source/target bytes. ACKs must echo the full request prefix of `min(UDS length, 5)` bytes in the expected direction. Positive UDS responses must correlate with the request; pending responses, bytes, chunks and deadlines are bounded. Malformed, unexpected, truncated or uncertain traffic stops the operation.

## Parameter encoding

| Module | Group | Region | Encoding |
| --- | --- | --- | --- |
| HU | `3001 EXBOX` | byte 58, mask `FF` | `00` disabled, `0A` timeout, `FF` permanent |
| BDC | `3221 PfFesMaster` | byte 11, mask `08`, shift 3 | logical `00`/`01`, encoded `00`/`08` |
| VSG01 | `3000 VSG Configuration` | byte 7, mask `0F` | logical `00`/`01`; upper nibble preserved |

Offsets are zero-based. The parameter mapping requires the exact software profile. Expected-value checks compare logical selected bits where applicable. Unsupported original enums, unsupported requested values, expected-value mismatches and no-op edits stop before session changes or signing loads.

## Signing

Profiles use Coding1 type 21, RSA1024/MD5 and the 132-byte BMWSigVerify envelope: a big-endian word count of 32, followed by 32 four-byte RSA words in reversed word order. AS signs `FFFFFFFF`, the module's four-byte BTLD identifier and a fresh nonzero eight-byte ECU seed. NCDS signs the complete ordered coding input, including the preserved CAF_ID group.

Bundled configurations and PEM files have fixed SHA-256 pins. Optional local configurations declare the exact module/software profile and pin each role's PEM file. Review validation hashes files without constructing private keys. After approval, protected loading disables core dumps, rechecks configuration and key hashes, and validates RSA factors and CRT geometry. AS and NCDS use separate one-use handles, closed on every path. Private operations use fresh RSA blinding and public fault checks. Python does not guarantee constant-time arithmetic or secure memory erasure.

A configured role does not prove ECU acceptance. The complete fresh original signature must verify before candidate signing. A fresh same-connection seed and a correlated positive `67 02` response are required before any coding write. Public verification also checks the candidate and returned signatures.

## Complete profile transactions

| Profile | Groups | Snapshot bytes | NCDS input bytes | Activation |
| --- | ---: | ---: | ---: | --- |
| HU | 8 | 1043 | 911 | Hard reset, bounded 30-second wait, reconnect |
| BDC | 82 | 6853 | 6721 | Default session |
| VSG01 | 3 | 148 | 16 | Default session |

Complete group order and lengths are defined in [coding_contract.py](../src/i3enet/coding_contract.py). All originals are retained before approval. CAF_ID is preserved; the signature is regenerated. BDC and VSG01 also retain and verify their seven-byte CPS metadata. No TL_ID is replaced.

The approved sequence validates current VIN/software/originals, enters extended and coding sessions, authenticates with a fresh seed, writes whole groups and signature, checks the signature, writes/verifies applicable coding metadata, finalizes and activates, then reads back the complete profile. Original data changing between capture and transaction stops the write.

| Command | Maximum diagnostic frames | Maximum application bytes, including discovery | Maximum TCP connections |
| --- | ---: | ---: | ---: |
| Read VIN | 1 | 17 | 1 |
| Read selected block | 3 | 39 | 3 |
| Code HU | 53 | 1771 | 8 |
| Code BDC | 353 | 10880 | 9 |
| Code VSG01 | 37 | 699 | 9 |

Each command sends at most one discovery datagram. Counters refer to application traffic; TCP control traffic is excluded. Uncertain sends or reporting failures are not converted into zero-traffic claims.

A private journal records durable intent before each mutation and retains raw requests, responses and timing. Its complete-data claim requires independently reopening the journal, validating hashes, correlating frames and checking all readback data. It contains no private RSA components, but does contain vehicle data and wire signatures. Journals never authorize retries or automatic restoration.
