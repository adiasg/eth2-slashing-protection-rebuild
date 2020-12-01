# Slashing Protection Recovery

This repository contains a script to recover Eth2 validator slashing protection information in the form of the [Validator Client Interchange Format (Slashing Protection)](https://eips.ethereum.org/EIPS/eip-3076).

:bangbang:**Disclaimer**: *Absolutely no warranties. Use at your own risk.*:bangbang:

## Overview
The script currently only regenerates the attestation component of the slashing protection file.

The slashing protection information is generated in the following way:
- Parse entire subtree descending from last finalized block
- If signed attestations are present, then identify the attestation with the *largest target epoch* that the validator has signed. Then use the source epoch and target epoch values from that attestation to make a single entry in the `"signed_attestations"` field of the slashing protection file.
- If no signed attestations are found in this subtree, make a single entry in the `"signed_attestations"` field of the slashing protection file with `"source_epoch"` and `"target_epoch"` set to the last finalized epoch.

### Assumptions
The validator has always been using a validator client with accurate system time.

## Install

- **Prerequisites**: Python 3
- **Installation**: Run `make install`, then `. venv/bin/activate`

## Usage
```
usage: python rebuild_slashing_protection.py [-h] --eth2-api ETH2_API --validator-index VALIDATOR_INDEX
                                         [--log-level {debug,info,warn}]

optional arguments:
  -h, --help            show this help message and exit
  --eth2-api ETH2_API   Eth2 API to fetch Beacon Chain information from
  --validator-index VALIDATOR_INDEX
                        index of validator for which to regenerate slashing protection information
  --log-level {debug,info,warn}
                        preferred log level
```

The script will write to a `protection-interchange.json` file. This file can be imported into an Eth2 validator client at startup to populate the client-specific slashing protection database.
