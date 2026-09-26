# Secure Legacy Gateway — MCX-N947 ELS Edition

English | [日本語](README.md)

Secure Legacy Gateway is a compact Zephyr-based HTTP-to-HTTPS gateway for the FRDM-MCXN947. It accepts HTTP requests from clients on a local network, connects to upstream servers over HTTPS, and relays responses as a stream. Cryptographic operations use the PSA Crypto API with the NXP ELS/PKC driver.

> [!WARNING]
> This project is currently intended for research and prototyping. The LAN-facing HTTP proxy has no authentication or transport encryption. Use it only on a trusted, isolated network, and never expose TCP port 8080 to the Internet.

## Features

- DHCP-based IPv4 address, gateway, and DNS configuration
- HTTP-to-HTTPS GET conversion with response streaming in small buffers
- Streaming conversion of absolute HTTPS URLs in HTML responses to HTTP URLs
- NXP ELS/PKC integration through PSA Crypto
- Startup self-tests for AES-128-GCM, SHA-256, AES-CMAC, P-256 ECDH, and P-256 ECDSA
- Multiple embedded public root CA certificates
- Stable development MAC address derived from the device UUID

## Supported environment

- Board: FRDM-MCXN947
- Zephyr target: `frdm_mcxn947/mcxn947/cpu0`
- Validated Zephyr version: 4.4.2
- Validated MCUX SDK version: 26.06
- Validated build host: macOS

## Dependencies and licensing notice

Application code in this repository is provided under the Apache License 2.0. Building the ELS edition also requires ELS/PKC components from the NXP MCUX SDK. Those components are not included in this repository. Users must obtain them from NXP and accept the applicable NXP license terms.

This repository is prepared for source-only publication. Firmware artifacts containing or linked with ELS/PKC software—including `.bin`, `.elf`, and `.hex` files—are excluded. Before distributing firmware binaries, confirm that the intended product and distribution method comply with the NXP license terms. Contact NXP or qualified legal counsel when appropriate. See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) for details.

## Building

### 1. Prepare Zephyr and the MCUX SDK

Prepare a Zephyr 4.4 workspace and MCUX SDK 26.06, then activate the Python environment normally used by your Zephyr installation. Replace the example paths below with paths for your system.

```sh
cd /path/to/zephyr-workspace/zephyr
source /path/to/python-venv/bin/activate

export APP_ROOT=/path/to/mcx_http_test
export MCUXSDK_ROOT=/path/to/mcuxsdk-26.06/mcuxsdk
```

`ZEPHYR_BASE` should point to the Zephyr source directory after the environment has been initialized.

### 2. Apply the MCXN947 integration patches

Apply the included build-integration patches to the external components from MCUX SDK 26.06 and to Zephyr. Apply each patch only once.

```sh
git -C "$MCUXSDK_ROOT/components/els_pkc" apply \
  "$APP_ROOT/patches/els-pkc-mcxn947-zephyr.patch"

git -C "$MCUXSDK_ROOT/components/psa_crypto_driver" apply \
  "$APP_ROOT/patches/psa-driver-mcxn947.patch"

git -C "$MCUXSDK_ROOT/middleware/mbedtls/tf-psa-crypto" apply \
  "$APP_ROOT/patches/tf-psa-generated-wrapper.patch"

git -C "$ZEPHYR_BASE" apply \
  "$APP_ROOT/patches/zephyr-mcxn947-integration.patch"
```

The tested component revisions are listed in [patches/README.md](patches/README.md). If Git reports that a patch does not apply, the dependency version may differ or the patch may already be present. Do not force the patch without reviewing the difference.

### 3. Build the ELS edition

```sh
west build -p always \
  -b frdm_mcxn947/mcxn947/cpu0 \
  "$APP_ROOT" \
  -d "$APP_ROOT/build-els" \
  -- \
  -DEXTRA_CONF_FILE=els_psa.conf \
  -DZEPHYR_EXTRA_MODULES="$MCUXSDK_ROOT/components/els_pkc;$MCUXSDK_ROOT/components/psa_crypto_driver" \
  -DZEPHYR_TF_PSA_CRYPTO_OVERRIDE_DIR="$MCUXSDK_ROOT/middleware/mbedtls/tf-psa-crypto" \
  -DNXP_PSA_DRIVER_GENERATED_FILES_DIR="$MCUXSDK_ROOT/components/psa_crypto_driver/generated_files_tf_psa_crypto"
```

### 4. Flash the board

Adjust the LinkServer path for your installation and run:

```sh
export PATH="/Applications/LinkServer_26.6.137:$PATH"
west flash -d "$APP_ROOT/build-els"
```

After startup, obtain the board's DHCP address from the serial console and test the proxy:

```sh
curl --noproxy "" \
  --proxy http://BOARD_IP:8080 \
  http://example.com/ \
  -v \
  -o /dev/null
```

## Source publication

See [PUBLICATION_CHECKLIST.md](PUBLICATION_CHECKLIST.md) for the files that should and should not be published. Do not commit build directories, serial logs, development backups, the MCUX SDK itself, or firmware binaries.

## Security scope

This software is not a general-purpose production proxy. It currently lacks client authentication, an access-control list, rate limiting, and a secure update system. Review [SECURITY.md](SECURITY.md) before deploying it in any environment.

Passing the startup ELS/PKC self-tests confirms expected behavior for the tested operations on the current device. It does not constitute product certification or a security guarantee.

## Project direction

The current milestone focuses on completing the Ethernet-based proxy. A future phase is expected to integrate a Core 1 SCSI implementation and an OS-independent SCSI command or file-I/O transport, avoiding dependence on legacy host-side Ethernet drivers.

## Trademarks and disclaimer

This is an independent project and is not an official product of, endorsed by, or sponsored by NXP Semiconductors or the Zephyr Project. NXP, MCX, EdgeLock, and other names may be trademarks of their respective owners.

The software is provided without warranty under the terms of the Apache License 2.0.
