REQS = wheel httpx

# To use a specific Eth2 spec version, enter the commit hash here and uncomment relevant lines
ETH2_SPEC_COMMIT = 579da6d2dc734b269dbf67aa1004b54bb9449784

install:
	if [ ! -d "eth2.0-specs" ]; then git clone https://github.com/ethereum/eth2.0-specs; fi
	# Uncomment the line below to use specific Eth2 spec version
	cd eth2.0-specs && git reset --hard $(ETH2_SPEC_COMMIT)
	python3 -m venv venv; . venv/bin/activate; pip3 install $(REQS);  pip3 install ./eth2.0-specs

clean:
	rm -rf venv eth2.0-specs
