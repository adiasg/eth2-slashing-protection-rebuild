# Slashing Protection Recovery

This repository contains a script to recover Eth2 validator slashing protection information in the format defined by [EIP-3076: Validator Client Interchange Format (Slashing Protection)](https://eips.ethereum.org/EIPS/eip-3076).

:bangbang:**Disclaimer**: *Absolutely no warranties. Use at your own risk.*:bangbang:

## Overview

### Slashing Protection Regeneration Methods
#### `future_only` (Safe)
The `future_only` method generates slashing protection information in a way that only allows the validator to make attestations in future epochs, and blocks in future slots.

This method will make a single entry each in the attestation slashing protection and block slashing protection items. The items will be generated in the following manner:
- Attestation Slashing Protection:
  - `source_epoch`: Current justified epoch
  - `target_epoch`: Current epoch
- Block Slashing Protection:
  - `slot`: Current slot

This prevents the validator from making attestations in the current epoch, and blocks in the current slot, because of [slashing protection conditions 2, 4, and 5](https://eips.ethereum.org/EIPS/eip-3076#conditions). This may lead to some false positives from the slashing prevention detection component (i.e., messages that are not actually slashable are identified as slashable), but never leads to false negatives. **This means that the validator may possibly lose out on staking rewards for this epoch, but will definitely not experience a slashing penalty.**

#### `parse_chain` (Experimental)
The method currently only regenerates the attestation component of the slashing protection file. The block protection item will be filled with the current slot.

The slashing protection information is generated in the following way:
- Parse entire subtree descending from last justified block
- If signed attestations are present, then identify the attestation with the *largest target epoch* that the validator has signed. Then use the source epoch and target epoch values from that attestation to make a single entry in the `"signed_attestations"` field of the slashing protection file.
- If no signed attestations are found in this subtree, make a single entry in the `"signed_attestations"` field of the slashing protection file with `"source_epoch"` and `"target_epoch"` set to the current justified epoch.

### Assumptions
- The validator is offline while running this script.
- This script is run on a machine with accurate system time.
- The validator has always been using a validator client with accurate system time.
- The current justified checkpoint epoch never decreases.

## Install

- **Prerequisites**:
  - Python 3
  - A fully synced Eth2 Beacon Node with an accessible [Eth2 API](https://github.com/ethereum/eth2.0-APIs) endpoint
- **Installation**: Run `make install`, then `. venv/bin/activate`

## Usage
```
usage: rebuild_slashing_protection.py [-h] --eth2-api ETH2_API --method {future_only,parse_chain}
                                      (--validator-index VALIDATOR_INDEX [VALIDATOR_INDEX ...] | --validator-pubkey VALIDATOR_PUBKEY [VALIDATOR_PUBKEY ...])
                                      [--log-level {debug,info,warn}]

Script to rebuild Eth2 validator slashing protection information

optional arguments:
  -h, --help            show this help message and exit
  --eth2-api ETH2_API   Eth2 API to fetch Beacon Chain information from
  --method {future_only,parse_chain}
                        method used to rebuild the slashing protection information. The "parse_chain" option is
                        experimental, and must be used with the "--validator-index" argument with a single validator index
                        input.
  --validator-index VALIDATOR_INDEX [VALIDATOR_INDEX ...]
                        index(es) of validator for which to regenerate slashing protection information
  --validator-pubkey VALIDATOR_PUBKEY [VALIDATOR_PUBKEY ...]
                        pubkey(s) of validator for which to regenerate slashing protection information
  --log-level {debug,info,warn}
                        preferred log level
```

The script will write to a `protection-file.json` file. This file can be imported into an Eth2 validator client at startup to populate the client-specific slashing protection database.
