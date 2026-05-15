.PHONY: all phase3 wasm wasm_exec spas spa_vclient spa_rclient services test clean prepare-samples eval

GOROOT := $(shell go env GOROOT)

# `make all` builds the Go cmd binaries. They import the embed packages
# (web/ppiav, web/vclient, web/rclient), so wasm + dist must exist first.
# Depend on phase3 so `make` from a fresh checkout Just Works.
all: phase3

phase3: wasm spas services

wasm: wasm_exec
	GOOS=js GOARCH=wasm go build -o web/ppiav/ppiav.wasm ./web/ppiav/bridge

wasm_exec:
	cp $(GOROOT)/lib/wasm/wasm_exec.js web/vclient/wasm_exec.js

spas: spa_vclient spa_rclient

spa_vclient:
	cd web/vclient && npm install && npm run build

spa_rclient:
	cd web/rclient && npm install && npm run build

services: wasm spas
	go build -o bin/ppiav-vservice ./cmd/ppiav-vservice
	go build -o bin/ppiav-vagent ./cmd/ppiav-vagent
	go build -o bin/ppiav-rservice ./cmd/ppiav-rservice

test:
	go test ./...

# Stratified UTKFace batch + cleartext ref logits → models/out/eval_inputs.json.
# Requires ./models/data/UTKFace and ./models/out/weights_fhe.pth.
prepare-samples:
	cd models && uv run python -m models.prepare_samples \
	    --batch 10 --stratified --with-ref-logit \
	    --data-dir ./data/UTKFace \
	    --out-dir ./out/inputs \
	    --out-manifest ./out/eval_inputs.json

# Drive the full protocol across the prepared batch.
# Requires a compiled Orion model at ./models/out/logn16.
eval: prepare-samples
	cd bench && uv run python -m bench.eval \
	    --inputs ../models/out/eval_inputs.json \
	    --orion  ../models/out/logn16

clean:
	rm -rf bin/
	rm -f web/ppiav/ppiav.wasm
	rm -f web/vclient/wasm_exec.js
	rm -rf web/vclient/dist web/rclient/dist
