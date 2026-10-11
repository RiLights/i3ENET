# i3ENET

Native macOS ENET reads and parameter coding for the BMW i3. Python 3.11 or later; no runtime dependencies, Windows VM or diagnostic app required.

The tool discovers the gateway, verifies its VIN, checks the selected module's software, and reads fresh originals before coding. Signing keys for the supported profiles are included and selected automatically.

Use i3ENET at your own risk. The software is provided “as is”, without warranties or guarantees of compatibility, successful coding, or recovery. Coding has been tested on a **2017 BMW i3** with the supported profiles below.

## Supported parameters

| ECU | Parameter path | Values | CAFD | BTLD |
| --- | --- | --- | --- | --- |
| `HU` | `EXBOX/LEGAL_DISCLAIMER_TIME` | `00` disabled, `0A` timeout, `FF` permanent | `00000DED/003.015.041` | `00001ABA/130.026.001` |
| `BDC` | `PfFesMaster/FesHasMode4` | `00` inactive, `01` active | `000017BE/085.010.012` | `00002418/085.010.060` |
| `VSG01` | `VSG Configuration/Last user mode` | `00` no, `01` yes | `00001A79/001.003.001` | `00001A77/001.001.002` |

`HU` is the head-unit role. `VSG01` contains the digit zero. Each coding command's effect is described below.

Support is limited to these exact software profiles and parameter paths. A matching module name or model year alone does not establish compatibility. Broader vehicle coverage, persistence across all power-cycle conditions, and native recovery remain unverified.

## Read

Run from this checkout:

```sh
python3 ./i3enet doctor
```

Find the active Ethernet adapter's IPv4 address. `--ip` always means the **Mac's ENET address**; the car gateway is discovered automatically. The example below uses a placeholder address—replace it with the address shown by `doctor`.

```sh
MAC_IP=169.254.10.20
python3 ./i3enet read-vin --ip "$MAC_IP" --live
python3 ./i3enet read-block --ecu HU \
  --parm EXBOX/LEGAL_DISCLAIMER_TIME --ip "$MAC_IP" --live
python3 ./i3enet read-block --ecu BDC \
  --parm PfFesMaster/FesHasMode4 --ip "$MAC_IP" --live
python3 ./i3enet read-block --ecu VSG01 \
  --parm 'VSG Configuration/Last user mode' --ip "$MAC_IP" --live
```

Quote parameter paths containing spaces. Add `--json` for structured reports. Omit `--live` to preview a command without file loading or vehicle traffic.

## Code

Use a parked, awake car with exclusive diagnostic access and an established recovery option. The approval prompt records your acknowledgement of the risks and confirmation of these conditions; the tool cannot measure them.

**Disable the iDrive startup disclaimer.** This sets the head unit's `LEGAL_DISCLAIMER_TIME` to `00`, removing the legal notice shown when iDrive starts. Use `0A` for a notice with a timeout or `FF` for a permanent startup notice.

```sh
python3 ./i3enet --ecu HU \
  --parm EXBOX/LEGAL_DISCLAIMER_TIME --value 00 --ip "$MAC_IP" --live
```

**Enable SPORT mode.** This sets the BDC's `FesHasMode4` flag to `01`, enabling SPORT in the driving-mode selection. Use `00` to disable the flag.

```sh
python3 ./i3enet --ecu BDC \
  --parm PfFesMaster/FesHasMode4 --value 01 --ip "$MAC_IP" --live
```

**Remember the pedestrian-sound setting.** This sets VSG01's `Last user mode` to `01`, enabling memory of the last selected acoustic pedestrian protection setting, including off. Use `00` to disable this memory. It controls the pedestrian-sound setting.

```sh
python3 ./i3enet --ecu VSG01 \
  --parm 'VSG Configuration/Last user mode' --value 01 --ip "$MAC_IP" --live
```

A live command captures the complete originals, displays the current and proposed values, then requires `CODE HEADUNIT`, `CODE BDC` or `CODE VSG01` at a terminal. It authenticates with a fresh ECU seed, writes the complete selected profile, activates it and verifies every coding group, signature and applicable metadata. An already-set value stops before authentication or writing. Optional `--expect 00` also stops if the current logical value differs.

There are no automatic retries or restoration attempts. A stopped transaction can leave partial changes; retain its journal before taking recovery action. Successful readback verifies stored data; observe the intended vehicle behavior separately.

## Signing and local data

The bundled AS authentication and NCDS coding keys are reusable reference material for the listed software profiles. They are public, unencrypted package data, not VIN-specific credentials. Fresh original-signature verification and ECU authentication still gate each write. No reference archive or external installation is needed.

For a local key override, use `--keys /path/to/keys.json`. The schema matches the bundled configurations in [src/i3enet/data](src/i3enet/data): exact module/CAFD/BTLD plus separate AS and NCDS PEM files and their SHA-256 hashes. Unencrypted RSA PKCS#1 and PKCS#8 PEM are supported. Local configurations and key files require mode `0600`, parent directories `0700`, and no links. An override does not expand supported software or parameter paths.

Live reads and coding create `private/` in the current directory. It contains originals and transaction journals, which can include the full VIN and other vehicle data. These files are excluded from Git and distribution packages. Public reports mask the VIN; review reports before sharing local paths or captures.

## Development

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 -B -m unittest discover -s tests
```

Tests use synthetic vehicle exchanges and offline signing checks; they do not contact a car. GitHub Actions runs the suite on macOS with Python 3.11 and 3.14 and checks package installation. See [protocol](docs/protocol.md) for the transaction contract and [contributing](CONTRIBUTING.md) for profile changes.

Project source is licensed under [MIT](LICENSE). Bundled signing material is separate reference data; see [NOTICE](NOTICE).
