#!/usr/bin/env python

import argparse
import httpx
import json
import logging
import time
from eth2spec.phase0.spec import (
    SECONDS_PER_SLOT,
    BLSPubkey, Root,
    compute_epoch_at_slot
)

# Define command line options
parser = argparse.ArgumentParser(description='Utility to rebuild Eth2 '
                                 'validator slashing protection information')
chain_info_group = parser.add_mutually_exclusive_group(required=True)
chain_info_group.add_argument("--eth2-api", type=str,
                              help="Eth2 API to fetch Beacon Chain information"
                              " from")
chain_info_group.add_argument("--genesis-info", type=str,
                              help='file containing genesis information to use'
                                   ' in the absence of an Eth2 API')
parser.add_argument("--method", type=str, required=True,
                    choices=["uc_safe", "future_only"],
                    help='method used to rebuild the slashing protection '
                    'information')
val_input_group = parser.add_mutually_exclusive_group(required=True)
val_input_group.add_argument("--validator-pubkey", type=str, nargs='+',
                             help="pubkey(s) of validator(s) for which to "
                             "regenerate slashing protection information")
val_input_group.add_argument("--validator-pubkey-file", type=str,
                             help='file containing whitespace-separated '
                             'pubkey(s) of validator(s) for which to '
                             'regenerate slashing protection information')
parser.add_argument("--output-file", type=str, required=False,
                    default="protection-file.json",
                    help="output file for slashing protection information "
                    '(default: "protection-file.json")')
parser.add_argument("--log-level", type=str, required=False, default="info",
                    choices=["debug", "info", "warn"],
                    help="preferred log level")
args = parser.parse_args()

# Setup logging
logging.basicConfig(format='%(asctime)s -- %(levelname)8s -- %(message)s')
log_level = args.log_level
if log_level == "warn":
    logging.getLogger().setLevel(logging.WARNING)
elif log_level == "info":
    logging.getLogger().setLevel(logging.INFO)
else:
    logging.getLogger().setLevel(logging.DEBUG)

# Initiaize variables using command line input
ETH2_API = args.eth2_api
GENESIS_INFO = args.genesis_info
METHOD = args.method
VAL_PUBKEY = args.validator_pubkey
VAL_PUBKEY_FILE = args.validator_pubkey_file
OUTPUT_FILE = args.output_file

if VAL_PUBKEY:
    # Make sure that validator pubkeys are well-formed
    try:
        VAL_PUBKEY = list(map(BLSPubkey, VAL_PUBKEY))
    except Exception:
        logging.exception(f'Error while reading validator pubkey(s) from command line input: {VAL_PUBKEY}. Please ensure that well-formed, "0x"-prefixed pubkeys are entered in a whitespace-separated format.')

if VAL_PUBKEY_FILE:
    # Read the validator pubkey file and initiaize VAL_PUBKEY
    with open(VAL_PUBKEY_FILE, "r") as val_pubkey_file:
        file_content = val_pubkey_file.read()
        logging.info(f'Fetching validator pubkey(s) from file: {GENESIS_INFO}')
        raw_val_pubkey = file_content.strip().split()
        # Make sure that validator pubkeys are well-formed
        try:
            VAL_PUBKEY = list(map(BLSPubkey, raw_val_pubkey))
        except:
            logging.exception(f'Error while reading validator pubkey(s) from file: {GENESIS_INFO}. Please ensure that well-formed, "0x"-prefixed pubkeys are entered in a whitespace-separated format. Exiting program.')
            exit(1)
        logging.info(f'Reading validator pubkeys from file: {VAL_PUBKEY_FILE}')
        for i in range(len(VAL_PUBKEY)):
            logging.info(f'\tPUBKEY: {VAL_PUBKEY[i]}')

OFFLINE_MODE = False
if ETH2_API is None:
    OFFLINE_MODE = True


def query_eth2_api(endpoint):
    # Function to get data from the specified endpoint of the Eth2 API
    url = ETH2_API + endpoint
    response = httpx.get(url, timeout=100)
    if response.status_code != 200:
        raise Exception(
            f"GET {url} returned with status code {response.status_code}"
            f" and message {response.json()['message']}"
        )
    response_json = response.json()
    response_data = response_json["data"]
    return response_data


def generate_validator_protection_json(validator_pubkey, att_source_epoch, att_target_epoch, block_slot):
    # Generate a validator protection information item in interchange format version 5
    # https://github.com/ethereum/EIPs/blob/master/EIPS/eip-3076.md#json-schema
    return {
                "pubkey": str(validator_pubkey),
                "signed_blocks": [
                    {
                        "slot": str(block_slot),
                    }
                ],
                "signed_attestations": [
                    {
                        "source_epoch": str(att_source_epoch),
                        "target_epoch": str(att_target_epoch)
                    }
                ]
            }


def write_protection_file(genesis_validators_root, validator_protection_info):
    # Write the validator protection information items to a protection file in interchange format version 5
    # https://github.com/ethereum/EIPs/blob/master/EIPS/eip-3076.md#json-schema
    protection_file = OUTPUT_FILE
    interchange_json = {
                         "metadata": {
                                "interchange_format_version": "5",
                                "genesis_validators_root": str(genesis_validators_root)
                            },
                         "data": validator_protection_info
                        }
    logging.info(f'Writing to file: {protection_file}')
    with open(protection_file, "w") as f:
        f.write(json.dumps(interchange_json, indent=2))


# Fetch genesis information from appropriate source
if OFFLINE_MODE:
    # Fetch genesis information from genesis information file
    with open(GENESIS_INFO, "r") as genesis_info_file:
        file_content = genesis_info_file.read()
        logging.info(f'Fetching Genesis information from file {GENESIS_INFO}')
        genesis = json.loads(file_content)
else:
    # Check that the Beacon Node serving the Eth2 API is fully synced
    syncing = query_eth2_api("/eth/v1/node/syncing")
    logging.debug(f'Got syncing status for Beacon Node at {ETH2_API} - Status: {syncing}')
    if syncing["is_syncing"]:
        logging.critical(f'The Beacon Node serving Eth2 API at {ETH2_API} is not fully synced! Status: {syncing}\n'
                          'Processing based on further information from this Beacon Node is unsafe. Exiting program.')
        exit(1)
    # Fetch genesis information from Eth2 API
    logging.info(f'Fetching Genesis information from Eth2 API at {ETH2_API}')
    genesis = query_eth2_api("/eth/v1/beacon/genesis")
try:
    genesis_validators_root = Root(genesis["genesis_validators_root"])
except Exception:
    logging.exception('Error while reading "genesis_validators_root". Please make sure that "genesis_validators_root" is a well-formed, "0x"-prefixed, 32-byte root. Exiting program.')
    exit(1)
logging.debug(f'Fetched Genesis information: {genesis}')

genesis_time = int(genesis["genesis_time"])
current_time = int(time.time())
if current_time < genesis_time:
    logging.critical(f'Current time is lesser than genesis time - Current time: {current_time}, Genesis time: {genesis_time}. Exiting program.')
    exit(1)
current_slot = (current_time - genesis_time) // SECONDS_PER_SLOT
current_epoch = compute_epoch_at_slot(current_slot)
logging.info(f'Current chain information - Slot: {current_slot}, Epoch: {current_epoch}')


validator_pubkeys = VAL_PUBKEY
logging.info(f'Rebuilding validator protection file using method "{METHOD}" for the folowing Validators - ')
for i in range(len(validator_pubkeys)):
    logging.info(f'\tPUBKEY: {validator_pubkeys[i]}')

if METHOD == "uc_safe":
    # Set the source and target epoch for attestation slashing protection to the previous epoch and current epoch respectively
    att_source_epoch = current_epoch - 1
    att_target_epoch = current_epoch
    # Set the block slot for block slashing protection to the current slot
    block_slot = current_slot

if METHOD == "future_only":
    # Fetch the current justified checkpoint information
    finality_checkpoints = query_eth2_api("/eth/v1/beacon/states/head/finality_checkpoints")
    justified_epoch = int(finality_checkpoints["current_justified"]["epoch"])
    logging.info(f'Current justified checkpoint information - Current Justified Epoch: {justified_epoch}')
    # Set the source and target epoch for attestation slashing protection to the justified epoch
    att_source_epoch = justified_epoch
    att_target_epoch = current_epoch
    # Set the block slot for block slashing protection to the current slot
    block_slot = current_slot

logging.info(f'Plugging in fake Attestation with Source Epoch: {att_source_epoch}, Target Epoch: {att_target_epoch}')
logging.info(f'Plugging in fake Block with Slot: {block_slot}')
validator_protection_info = []
for validator_pubkey in validator_pubkeys:
    validator_protection_info.append(generate_validator_protection_json(validator_pubkey, att_source_epoch, att_target_epoch, block_slot))
write_protection_file(genesis_validators_root, validator_protection_info)
exit(0)
