import argparse
import httpx
import json
import logging
from eth2spec.phase0.spec import (
    SLOTS_PER_EPOCH,
    Attestation, BeaconState, SignedBeaconBlock,
    compute_epoch_at_slot, get_beacon_committee
)

parser = argparse.ArgumentParser()
parser.add_argument("--eth2-api", type=str, required=True,
                    help="Eth2 API to fetch Beacon Chain information from")
parser.add_argument("--validator-index", type=int, required=True,
                    help="index of validator for which to regenerate "
                    "slashing protection information")
parser.add_argument("--log-level", type=str, required=False, default="info",
                    choices=["debug", "info", "warn"],
                    help="preferred log level")
args = parser.parse_args()

logging.basicConfig(format='%(asctime)s -- %(levelname)s -- %(message)s')
log_level = args.log_level
if log_level == "warn":
    logging.getLogger().setLevel(logging.WARNING)
elif log_level == "info":
    logging.getLogger().setLevel(logging.INFO)
else:
    logging.getLogger().setLevel(logging.DEBUG)

ETH2_API = args.eth2_api
VAL_INDEX = args.validator_index


def query_eth2_api(endpoint):
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


def fetch_state(state_id):
    state_json = query_eth2_api(f"/eth/v1/debug/beacon/states/{state_id}")
    return BeaconState.from_obj(state_json)


def fetch_block(block_id):
    block_json = query_eth2_api(f"/eth/v1/beacon/blocks/{block_id}")
    signed_block = SignedBeaconBlock.from_obj(block_json)
    return signed_block.message


def cache_get_validator_committee_index(state, attestation_slot, attestation_index, validator_index, cache):
    if (attestation_slot, attestation_index) in cache:
        return cache[(attestation_slot, attestation_index)]
    committee = get_beacon_committee(state, attestation_slot, attestation_index)
    if validator_index in committee:
        validator_index_in_bitlist = committee.index(validator_index)
    else:
        validator_index_in_bitlist = -1
    cache[(attestation_slot, attestation_index)] = validator_index_in_bitlist
    return validator_index_in_bitlist


def get_signed_attestations(block, head_state, validator_index, committee_cache, head):
    signed_attestations = []
    for attestation in block.body.attestations:
        logging.debug(f'Checking Attestation - Slot: {attestation.data.slot}, Index: {attestation.data.index}')
        validator_index_in_bitlist = cache_get_validator_committee_index(head_state, attestation.data.slot, attestation.data.index, validator_index, committee_cache)
        if validator_index_in_bitlist > 0:
            logging.info(f'Validator is in the committee for Attestation - Slot: {attestation.data.slot}, Index: {attestation.data.index} in the chain of Block - Slot: {head["slot"]}, Root: {head["root"]}')
            validator_has_signed = attestation.aggregation_bits[validator_index_in_bitlist]
            if validator_has_signed:
                logging.info(f'Validator has signed Attestation - Slot: {attestation.data.slot}, Index: {attestation.data.index} in the chain of Block - Slot: {head["slot"]}, Root: {head["root"]}')
                if compute_epoch_at_slot(block.slot) == attestation.data.target.epoch:
                    logging.debug("This is the best possible attestation in the chain")
                    return [attestation]
                signed_attestations.append(attestation)
    return signed_attestations


def process_chain(head, finalized_epoch, processed_blocks, best_attestations_in_chains):
    logging.info(f"Processing chain from head: {head}")
    head_root = head["root"]
    # The below block header fetching might cause problems sometimes
    # If a head that was returned by `/eth/v1/debug/beacon/heads` is now
    # orphaned, it might be pruned and thus not retrievable from the API
    head_block_header = query_eth2_api(f"/eth/v1/beacon/headers/{head_root}")
    head_state_root = head_block_header["header"]["message"]["state_root"]
    logging.info(f"Fetching state: {head_state_root}. This may take some time...")
    head_state = fetch_state(head_state_root)
    logging.info("Fetching state completed")
    candidate_attestations = []
    committee_cache = {}

    # Initiaize loop variables
    current_block_root = head_root
    block = fetch_block(current_block_root)
    while current_block_root not in processed_blocks and block.slot > finalized_epoch * SLOTS_PER_EPOCH:
        logging.info(f'Processing Block - Slot: {block.slot}, Root: {current_block_root}')
        signed_attestations = get_signed_attestations(block, head_state, VAL_INDEX, committee_cache, head)
        if signed_attestations:
            logging.debug(f'Signed attestations in this block: {signed_attestations}')
            candidate_attestations.extend(signed_attestations)
            highest_target_attestation = max(candidate_attestations, key=lambda att: att.data.target.epoch)
            logging.debug(f'Best attestation in current chain: {highest_target_attestation}')
            if highest_target_attestation.data.target.epoch == compute_epoch_at_slot(block.slot):
                logging.info(f'Found better attestation in current chain: {highest_target_attestation}')
                best_attestations_in_chains.append(highest_target_attestation)
                break
        else:
            logging.debug("No signed attestations in this block")

        processed_blocks.append(current_block_root)
        # Update loop variables
        current_block_root = block.parent_root
        block = fetch_block(current_block_root)
    if current_block_root in processed_blocks:
        logging.debug(f'Block - Slot: {block.slot}, Root: {current_block_root} was already processed')
    elif block.slot <= finalized_epoch * SLOTS_PER_EPOCH:
        logging.debug(f'Block - Slot: {block.slot}, Root: {current_block_root} is not higher than Finalized Slot: {finalized_epoch * SLOTS_PER_EPOCH}')


validator_info = query_eth2_api(f'/eth/v1/beacon/states/head/validators/{VAL_INDEX}')
validator_pubkey = validator_info["validator"]["pubkey"]
logging.info(f'Rebuilding validator protection file for Validator - Index: {VAL_INDEX}, pubkey: {validator_pubkey}')
finality_checkpoints_before = query_eth2_api("/eth/v1/beacon/states/head/finality_checkpoints")
heads = query_eth2_api("/eth/v1/debug/beacon/heads")
finality_checkpoints = query_eth2_api("/eth/v1/beacon/states/head/finality_checkpoints")

if finality_checkpoints_before["finalized"] != finality_checkpoints["finalized"]:
    logging.critical("The finalized block changed while in the middle of fetching data from the Eth2 node. "
                    f'The old finalized checkpoint was: {finality_checkpoints_before["finalized"]}, and '
                    f'the new finalized checkpoint is: {finality_checkpoints["finalized"]} '
                    "To safeguard against processing inconsistent data, the program will exit. "
                    "Try running this script again.")
    exit(1)

finalized_epoch = int(finality_checkpoints["finalized"]["epoch"])
processed_blocks = []
best_attestations_in_chains = []

sorted(heads, key=lambda head: int(head["slot"]), reverse=True)
for head in heads:
    process_chain(head, finalized_epoch, processed_blocks, best_attestations_in_chains)
    best_attestation = max(best_attestations_in_chains, key=lambda att: att.data.target.epoch)
    if compute_epoch_at_slot(best_attestation.data.slot) > compute_epoch_at_slot(int(head["slot"])):
        break

if best_attestations_in_chains:
    best_attestation = max(best_attestations_in_chains, key=lambda att: att.data.target.epoch)
    logging.info(f'Best Attestation found with Source Epoch: {best_attestation.data.source.epoch}, Target Epoch: {best_attestation.data.target.epoch}')
else:
    logging.info("No attestations from this validator were found in the sub-tree rooted at the last finalized block.")
    best_attestation = Attestation()
    best_attestation.source.epoch = finalized_epoch
    best_attestation.target.epoch = finalized_epoch
    logging.info(f'Plugging in fake Attestation with Source Epoch: {finalized_epoch}, Target Epoch: {finalized_epoch}')

logging.info("This program does not rebuild block protection history yet. The highest known head slot will be plugged into the block protection component.")
best_block_slot = heads[0]["slot"]
logging.info(f'Plugging in fake Block with Slot: {best_block_slot}')

genesis = query_eth2_api("/eth/v1/beacon/genesis")
genesis_validators_root = genesis["genesis_validators_root"]
logging.debug(f'Fetched genesis_validators_root: {genesis_validators_root}')

interchange_json = {
                     "metadata": {
                            "interchange_format_version": "5",
                            "genesis_validators_root": genesis_validators_root
                        },
                     "data": [
                            {
                                "pubkey": validator_pubkey,
                                "signed_blocks": [
                                    {
                                        "slot": str(best_block_slot),
                                    }
                                ],
                                "signed_attestations": [
                                    {
                                        "source_epoch": str(best_attestation.data.source.epoch),
                                        "target_epoch": str(best_attestation.data.target.epoch)
                                    }
                                ]
                            }
                        ]
                    }

logging.info("Writing to file: protection-interchange.json")
with open("protection-interchange.json", "w") as f:
    f.write(json.dumps(interchange_json))
