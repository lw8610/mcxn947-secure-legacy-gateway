# MCUX SDK 26.06 integration patches

These patches contain only the build-integration changes required by this application. They do not contain the NXP ELS/PKC or PSA driver source trees.

Tested component revisions:

| Component | Commit | Patch |
|---|---|---|
| `components/els_pkc` | `6fff673438999d5ae72d2f4f8e7b3b66d1043aae` | `els-pkc-mcxn947-zephyr.patch` |
| `components/psa_crypto_driver` | `a211eea83903fb05c8cca51aabe38cf62e6c0d1f` | `psa-driver-mcxn947.patch` |
| `middleware/mbedtls/tf-psa-crypto` | `fe8b79bedc9e17a2c9ed61976d63257bab57b9da` | `tf-psa-generated-wrapper.patch` |
| Zephyr | `dccb09599635bdff17633fa7e9dab014b91dce90` | `zephyr-mcxn947-integration.patch` |

Run `git apply --check PATCH` in each component repository before applying it. The original file-level licenses remain applicable to the patched files.

The Zephyr patch contains two independent fixes used by the validated build:

- allow the application to select the NXP-maintained TF-PSA-Crypto tree so PSA calls use its generated hardware-driver wrappers;
- wait briefly for ENET-QOS TX completion instead of dropping a competing thread transmission.
