# Fabric — Go

Go client for resolving handles and broadcasting updates via the Spaces certrelay network.

## Installation

```bash
go get github.com/spacesprotocol/fabric-go
```

Includes BIP-340 Schnorr signing via `btcec/v2`.

## Querying Records

```go
package main

import (
    "fmt"
    fabric "github.com/spacesprotocol/fabric-go"
    libveritas "github.com/spacesprotocol/libveritas-go"
)

func main() {
    f := fabric.New(nil) // nil = default seeds

    // Resolve a single handle
    zone, err := f.Resolve("alice@bitcoin")
    if err != nil {
        panic(err)
    }

    j, _ := libveritas.ZoneToJson(zone)
    fmt.Println(j)

    // Resolve multiple handles at once
    zones, err := f.ResolveAll([]string{"alice@bitcoin", "bob@bitcoin"})
    if err != nil {
        panic(err)
    }
    for _, zone := range zones {
        j, _ := libveritas.ZoneToJson(zone)
        fmt.Println(j)
    }

    // Export a .spacecert certificate chain
    certBytes, err := f.Export("alice@bitcoin")
}
```

## Updating Records & Broadcasting

```go
package main

import (
    fabric "github.com/spacesprotocol/fabric-go"
    libveritas "github.com/spacesprotocol/libveritas-go"
)

func main() {
    f := fabric.New(nil)

    // 1. Pack records into wire format
    recordSet, _ := libveritas.RecordSetPack([]libveritas.Record{
        libveritas.RecordTxt("name", "alice"),
        libveritas.RecordTxt("SIP-7", "v=0;dest=sp1qqx..."),
    })

    // 2. Sign the record set
    signature, _ := fabric.SignMessage(recordSet.ToBytes(), secretKey)

    // 3. Create offchain records (record set + signature)
    offchainRecords, _ := libveritas.CreateOffchainRecords(recordSet, signature)

    // 4. Build the message
    builder := libveritas.NewMessageBuilder()
    builder.AddRecords("alice@bitcoin", offchainRecords)

    // 5. Get a chain proof from a relay
    chainProofReq := builder.ChainProofRequest()
    chainProof, _ := f.Prove([]byte(chainProofReq))

    // 6. Finalize the message with the proof
    msg, _ := builder.Build(chainProof)

    // 7. Broadcast to the network
    f.Broadcast(msg.ToBytes())
}
```

## Offline Verification

Access the internal `Veritas` instance for offline proof verification:

```go
f := fabric.New(nil)
f.Bootstrap()

v := f.Veritas()
// Use v directly for custom verification
```

## Configuration

```go
f := fabric.New([]string{"https://relay1.example.com", "https://relay2.example.com"})
f.SetDevMode(true)                 // Skip finality checks (testing only)
f.SetAnchorSetHash("abcdef..")    // Pin to specific anchor set
f.SetPreferLatest(false)           // Disable freshest-relay preference
```

## Re-exports

This package re-exports all `libveritas-go` types as aliases so you can use them directly:

```go
import fabric "github.com/spacesprotocol/fabric-go"

var zone fabric.Zone
var msg fabric.Message
var builder fabric.MessageBuilder
```
