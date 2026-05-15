//go:build js && wasm

package ppiav

import (
	"fmt"
	"syscall/js"
)

// RegisterJS registers the globalThis.ppiav namespace. All functions
// accept and return JS values; the underlying logic lives in core.go and
// is host-buildable for tests.
//
// JS surface (handle-based — the TS wrapper in web/ppiav/ts/ppiav/index.ts
// wraps these as a Client class that hides the handle and converts
// {error} responses into thrown JS Errors). The TS PpiavBridge interface
// in that file mirrors the signatures below 1:1 — keep them in sync.
//
//	ppiav.newClient(paramsJSON: string, sid: string)
//	    → {handle: number} | {error: string}
//	ppiav.deleteClient(handle: number)
//	    → null
//	ppiav.genPKShare(handle: number)
//	    → Uint8Array | {error: string}
//	ppiav.aggregatePK(handle: number, agentShareBytes: Uint8Array)
//	    → null | {error: string}
//	ppiav.genRLKShareRound1(handle: number)
//	    → Uint8Array | {error: string}
//	ppiav.aggregateRLKRound1(handle: number, agentShareBytes: Uint8Array)
//	    → null | {error: string}
//	ppiav.genRLKShareRound2(handle: number)
//	    → Uint8Array | {error: string}
//	ppiav.genGaloisShares(handle: number)
//	    → Uint8Array | {error: string}
//	ppiav.encryptImage(handle: number, tensor: Float64Array)
//	    → Uint8Array | {error: string}
//	ppiav.partialDecrypt(handle: number, authenticatedCtBytes: Uint8Array)
//	    → Uint8Array | {error: string}
func RegisterJS() {
	ns := js.Global().Get("Object").New()

	ns.Set("newClient", js.FuncOf(jsNewClient))
	ns.Set("deleteClient", js.FuncOf(jsDeleteClient))
	ns.Set("genPKShare", js.FuncOf(jsGenPKShare))
	ns.Set("aggregatePK", js.FuncOf(jsAggregatePK))
	ns.Set("genRLKShareRound1", js.FuncOf(jsGenRLKShareRound1))
	ns.Set("aggregateRLKRound1", js.FuncOf(jsAggregateRLKRound1))
	ns.Set("genRLKShareRound2", js.FuncOf(jsGenRLKShareRound2))
	ns.Set("genGaloisShares", js.FuncOf(jsGenGaloisShares))
	ns.Set("encryptImage", js.FuncOf(jsEncryptImage))
	ns.Set("partialDecrypt", js.FuncOf(jsPartialDecrypt))

	// Readiness signal — matches the convention from
	// web/ppiav/bridge/lattigo/lattigo.go.
	ns.Set("__ready", true)

	js.Global().Set("ppiav", ns)
}

// --- JS<->Go helpers (mirror lattigo/helpers.go without sharing the file
// to keep the two bridges independent — this package is tiny). ---

func jsErrorResult(msg string) any {
	obj := js.Global().Get("Object").New()
	obj.Set("error", msg)
	return obj
}

func jsHandleResult(h uint64) any {
	obj := js.Global().Get("Object").New()
	// JS Numbers are float64; handles fit in a uint53 safely for the
	// foreseeable future. Pass as float64 directly.
	obj.Set("handle", float64(h))
	return obj
}

func jsBytesToGo(v js.Value) []byte {
	length := v.Length()
	b := make([]byte, length)
	js.CopyBytesToGo(b, v)
	return b
}

func jsBytesFromGo(b []byte) js.Value {
	arr := js.Global().Get("Uint8Array").New(len(b))
	js.CopyBytesToJS(arr, b)
	return arr
}

func jsFloat64ArrayToGo(v js.Value) []float64 {
	// JS Float64Array → Go []float64. syscall/js does not provide a
	// direct CopyBytesToGo for non-byte typed arrays, so we read each
	// slot via Index(i).Float(). For ImageLen=12288 this is fast enough
	// (single-digit ms); revisit only if profiling demands.
	length := v.Length()
	out := make([]float64, length)
	for i := 0; i < length; i++ {
		out[i] = v.Index(i).Float()
	}
	return out
}

// --- Function bindings ---

func jsNewClient(_ js.Value, args []js.Value) any {
	if len(args) < 2 {
		return jsErrorResult("newClient: need (paramsJSON, sid)")
	}
	paramsJSON := []byte(args[0].String())
	sid := args[1].String()
	h, err := NewClient(paramsJSON, sid)
	if err != nil {
		return jsErrorResult(fmt.Sprintf("newClient: %v", err))
	}
	return jsHandleResult(h)
}

func jsDeleteClient(_ js.Value, args []js.Value) any {
	if len(args) < 1 {
		return nil
	}
	DeleteClient(uint64(args[0].Float()))
	return nil
}

func jsGenPKShare(_ js.Value, args []js.Value) any {
	if len(args) < 1 {
		return jsErrorResult("genPKShare: need (handle)")
	}
	h := uint64(args[0].Float())
	out, err := GenPKShare(h)
	if err != nil {
		return jsErrorResult(fmt.Sprintf("genPKShare: %v", err))
	}
	return jsBytesFromGo(out)
}

func jsAggregatePK(_ js.Value, args []js.Value) any {
	if len(args) < 2 {
		return jsErrorResult("aggregatePK: need (handle, agentShareBytes)")
	}
	h := uint64(args[0].Float())
	bytes := jsBytesToGo(args[1])
	if err := AggregatePK(h, bytes); err != nil {
		return jsErrorResult(fmt.Sprintf("aggregatePK: %v", err))
	}
	return nil
}

func jsGenRLKShareRound1(_ js.Value, args []js.Value) any {
	if len(args) < 1 {
		return jsErrorResult("genRLKShareRound1: need (handle)")
	}
	h := uint64(args[0].Float())
	out, err := GenRLKShareRound1(h)
	if err != nil {
		return jsErrorResult(fmt.Sprintf("genRLKShareRound1: %v", err))
	}
	return jsBytesFromGo(out)
}

func jsAggregateRLKRound1(_ js.Value, args []js.Value) any {
	if len(args) < 2 {
		return jsErrorResult("aggregateRLKRound1: need (handle, agentShareBytes)")
	}
	h := uint64(args[0].Float())
	bytes := jsBytesToGo(args[1])
	if err := AggregateRLKRound1(h, bytes); err != nil {
		return jsErrorResult(fmt.Sprintf("aggregateRLKRound1: %v", err))
	}
	return nil
}

func jsGenRLKShareRound2(_ js.Value, args []js.Value) any {
	if len(args) < 1 {
		return jsErrorResult("genRLKShareRound2: need (handle)")
	}
	h := uint64(args[0].Float())
	out, err := GenRLKShareRound2(h)
	if err != nil {
		return jsErrorResult(fmt.Sprintf("genRLKShareRound2: %v", err))
	}
	return jsBytesFromGo(out)
}

func jsGenGaloisShares(_ js.Value, args []js.Value) any {
	if len(args) < 1 {
		return jsErrorResult("genGaloisShares: need (handle)")
	}
	h := uint64(args[0].Float())
	out, err := GenGaloisShares(h)
	if err != nil {
		return jsErrorResult(fmt.Sprintf("genGaloisShares: %v", err))
	}
	return jsBytesFromGo(out)
}

func jsEncryptImage(_ js.Value, args []js.Value) any {
	if len(args) < 2 {
		return jsErrorResult("encryptImage: need (handle, tensor)")
	}
	h := uint64(args[0].Float())
	tensor := jsFloat64ArrayToGo(args[1])
	out, err := EncryptImage(h, tensor)
	if err != nil {
		return jsErrorResult(fmt.Sprintf("encryptImage: %v", err))
	}
	return jsBytesFromGo(out)
}

func jsPartialDecrypt(_ js.Value, args []js.Value) any {
	if len(args) < 2 {
		return jsErrorResult("partialDecrypt: need (handle, authenticatedCtBytes)")
	}
	h := uint64(args[0].Float())
	bytes := jsBytesToGo(args[1])
	out, err := PartialDecrypt(h, bytes)
	if err != nil {
		return jsErrorResult(fmt.Sprintf("partialDecrypt: %v", err))
	}
	return jsBytesFromGo(out)
}
