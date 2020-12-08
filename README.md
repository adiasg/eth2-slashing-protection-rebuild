# Slashing Protection Recovery

This repository contains a utility to recover Eth2 validator slashing protection information in the format defined by [EIP-3076: Validator Client Interchange Format (Slashing Protection) v5](https://github.com/ethereum/EIPs/blob/master/EIPS/eip-3076.md). The output file can be imported into an Eth2 validator client to populate the client-specific slashing protection database, thereby restoring the slashing protection guarantees.

:bangbang:**Disclaimer**: *Absolutely no warranties. Use at your own risk.*:bangbang:

## Overview

### General Assumptions
These assumptions are made for all slashing protection rebuild methods:
- The validator is offline while running this script.
- This script is run on a machine with accurate system time.
- The validator has always been using a validator client with accurate system time.

### Slashing Protection Rebuild Methods

#### 1. `uc_safe` (Safest)

##### Description
The `uc_safe` method generates slashing protection information that only allows the validator to make attestations such that `source.epoch >= current_epoch - 1` and `target.epoch > current_epoch`. As compared to the other methods, this method is unconditionally safe (hence the name `uc_safe`) as long as the accurate system time requirement is met. **When used with `--validator_pubkey` or `--validator-pubkey-file` options, this method is usable without an Eth2 API (recommended).**

A single entry will be made in each of the attestation slashing protection and block slashing protection items. The entries will be generated in the following manner:
- Attestation Slashing Protection:
  - `source_epoch`: `current_epoch - 1`
  - `target_epoch`: `current_epoch`
- Block Slashing Protection:
  - `slot`: `current_slot`

These entries prevent the validator from making attestations until the justified epoch is at least `current_epoch - 1`, and from proposing blocks in the current slot, because of [slashing protection conditions 2, 4, and 5](https://github.com/ethereum/EIPs/blob/master/EIPS/eip-3076.md#conditions).

##### Validator Activity Implications
This may lead to some false positives from the slashing prevention detection component (i.e., messages that are not actually slashable are identified as slashable). However, **the validator *WILL* lose out on rewards because of inactivity in *at least* the current epoch.**

Further, if the Eth2 network does not produce new justified blocks, the validator will remain offline. Notably, if a large fraction (`> 1/3`rd) of validators are offline, a validator using a slashing protection file produced by this method will remain offline until the network recovers.

#### 2. `future_only` (Safe)

##### Specific Assumptions
- The beacon node providing the Eth2 API is fully synced.

##### Description
The `future_only` method generates slashing protection information in a way that only allows the validator to make attestations in future epochs, and blocks in future slots.

A single entry will be made in each of the attestation slashing protection and block slashing protection items. The entries will be generated in the following manner:
- Attestation Slashing Protection:
  - `source_epoch`: `current_justified_epoch`
  - `target_epoch`: `current_epoch`
- Block Slashing Protection:
  - `slot`: `current_slot`

This prevents the validator from making attestations in the current epoch, and blocks in the current slot, because of [slashing protection conditions 2, 4, and 5](https://github.com/ethereum/EIPs/blob/master/EIPS/eip-3076.md#conditions).

##### Validator Activity Implications
This may lead to some false positives from the slashing prevention detection component (i.e., messages that are not actually slashable are identified as slashable). However, **the validator *MAY* lose out on rewards because of inactivity in this epoch .**

#### 3. `parse_chain` (Experimental)

##### Specific Assumptions
- The beacon node providing the Eth2 API is fully synced.
- The current justified checkpoint epoch never decreases.

##### Description
The method currently only regenerates the attestation component of the slashing protection file. The block protection item will be filled with the current slot. The purpose of this method is to avoid any false positives from the slashing prevention detection component.

The slashing protection information is generated in the following way:
- Parse entire subtree descending from last justified block
- If signed attestations are present, then identify the attestation with the *largest target epoch* that the validator has signed. Then use the source epoch and target epoch values from that attestation to make a single entry in the `"signed_attestations"` field of the slashing protection file.
- If no signed attestations are found in this subtree, make a single entry in the `"signed_attestations"` field of the slashing protection file with `"source_epoch"` and `"target_epoch"` set to the current justified epoch.

---

## Install

- **Prerequisites**:
  - Python 3
  - (Optional) A fully synced Eth2 Beacon Node with an accessible [Eth2 API](https://github.com/ethereum/eth2.0-APIs) endpoint
- **Installation**:
  1. Verify that the installation will use the correct [Eth2.0 spec version](https://github.com/ethereum/eth2.0-specs/releases) by checking the commit hash in `ETH2_SPEC_COMMIT` in `./Makefile`.
  2. Use `make install` to install the dependencies in a venv.
  3. Activate the venv before executing the utility using `. venv/bin/activate`

## Usage
```
usage: rebuild_slashing_protection.py [-h] (--eth2-api ETH2_API | --genesis-info GENESIS_INFO) --method {uc_safe,future_only,parse_chain}
                                      (--validator-index VALIDATOR_INDEX [VALIDATOR_INDEX ...] | --validator-pubkey VALIDATOR_PUBKEY [VALIDATOR_PUBKEY ...] | --validator-pubkey-file VALIDATOR_PUBKEY_FILE) [--output-file OUTPUT_FILE]
                                      [--log-level {debug,info,warn}]

Utility to rebuild Eth2 validator slashing protection information

optional arguments:
  -h, --help            show this help message and exit
  --eth2-api ETH2_API   Eth2 API to fetch Beacon Chain information from
  --genesis-info GENESIS_INFO
                        file containing genesis information to use in the absence of an Eth2 API. Can only be used with the following options: "--genesis-info GENESIS_INFO --method uc_safe (--validator_pubkey VALIDATOR_PUBKEY [VALIDATOR_PUBKEY ...] |
                        --validator-pubkey-file VALIDATOR_PUBKEY_FILE"
  --method {uc_safe,future_only,parse_chain}
                        method used to rebuild the slashing protection information. The "parse_chain" option is experimental, and must be used with argument "--validator-index VALIDATOR_INDEX" (a single validator index input).
  --validator-index VALIDATOR_INDEX [VALIDATOR_INDEX ...]
                        index(es) of validator(s) for which to regenerate slashing protection information
  --validator-pubkey VALIDATOR_PUBKEY [VALIDATOR_PUBKEY ...]
                        pubkey(s) of validator(s) for which to regenerate slashing protection information
  --validator-pubkey-file VALIDATOR_PUBKEY_FILE
                        file containing whitespace-separated pubkey(s) of validator(s) for which to regenerate slashing protection information. The default output file is "protection-file.json"
  --output-file OUTPUT_FILE
                        output file for slashing protection information
  --log-level {debug,info,warn}
                        preferred log level

```

### Recommended Usage

The `--method uc_safe` along with genesis information from `genesis.json` is highly recommended. These step-by-step instructions outline the recommended usage:

0. Download this repository using `git clone https://github.com/adiasg/eth2-slashing-protection-rebuild.git`.
1. [Installation](#install): verify that the installation will use the correct [Eth2.0 spec version](https://github.com/ethereum/eth2.0-specs/releases) by checking the commit hash in `ETH2_SPEC_COMMIT` in `./Makefile`. Then run `make install`, followed by `. venv/bin/activate`.
1. Fill in your validator public key(s) in a `./pubkey.txt` file.

    `./pubkey.txt`:
    ```
    0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
    0x100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
    ```
2. Verify that `genesis.json` contains the correct `"genesis_time"` and `"genesis_validators_root"` for the Eth2.0 mainnet. These values can be checked against your beacon node's HTTP API at the `/eth/v1/beacon/genesis` endpoint or some other trusted source.

    `./genesis.json`:
    ```
    {
      "genesis_time": "1606824023",
      "genesis_validators_root": "0x4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95"
    }
    ```
3. Run the utility using the recommended options. Remember to activate the venv using `. venv/bin/activate` before this.
    ```bash
    python rebuild_slashing_protection.py --genesis-info ./genesis.json --method uc_safe --validator-pubkey-file ./pubkeys.txt
    ```

    This should produce an output file `protection-file.json`.

    `./protection-file.json`:
    ```
    {
      "metadata": {
        "interchange_format_version": "5",
        "genesis_validators_root": "0x4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95"
      },
      "data": [
        {
          "pubkey": "0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
          "signed_blocks": [
            {
              "slot": "19094"
            }
          ],
          "signed_attestations": [
            {
              "source_epoch": "595",
              "target_epoch": "596"
            }
          ]
        },
        {
          "pubkey": "0x100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
          "signed_blocks": [
            {
              "slot": "19094"
            }
          ],
          "signed_attestations": [
            {
              "source_epoch": "595",
              "target_epoch": "596"
            }
          ]
        }
      ]
    }
    ```
