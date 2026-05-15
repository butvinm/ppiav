.PHONY: all wasm ts

all: wasm ts

wasm:
	GOOS=js GOARCH=wasm go build -o ppiav.wasm ./bridge

ts:
	npm run build
