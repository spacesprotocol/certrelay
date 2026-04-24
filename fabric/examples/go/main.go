package main

// <doc:install>
// go get github.com/spacesprotocol/fabric-go
// </doc:install>

import (
	"encoding/hex"
	"fmt"
	"log"

	fabric "github.com/spacesprotocol/fabric-go"
	lv "github.com/spacesprotocol/libveritas-go"
)

func exampleResolveIntro() error {
	// <doc:resolve-intro>
	f := fabric.New()
	zone, err := f.Resolve("alice@bitcoin")
	// </doc:resolve-intro>
	if err != nil {
		return err
	}
	_ = zone
	return nil
}

/// Resolve a single handle
func exampleResolve() error {
	// <doc:resolve>
	f := fabric.New()
	zone, err := f.Resolve("alice@bitcoin")
	if err != nil {
		return err
	}
	if zone == nil {
		fmt.Println("handle not found")
		return nil
	}

	fmt.Printf("Handle found: %s\n", zone.Handle)
	// </doc:resolve>

	return nil
}

/// Verification
func exampleTrustAndVerification() error {
	f := fabric.New()

	// <doc:verification>
	// Before pinning a trust id: resolve uses observed (peer) state
	// badge() returns Unverified
	zone, err := f.Resolve("alice@bitcoin")
	if err != nil {
		return err
	}

	f.Badge(*zone) // Unverified

	// Pin trust from a QR scan
	qr := "veritas://scan?id=14ef902621df01bdeee0b23fedf67458563a20df600af8979a4748dcd9d1b9f9"

	// For highest level of trust (scan QR code from Veritas desktop)
	if err := f.TrustFromQr(qr); err != nil {
		return err
	}

	// Does not require re-resolving, badge now checks
	// whether zone was against a trusted root
	f.Badge(*zone) // Orange if handle is sovereign (final certificate)

	// Or from a semi-trusted source (e.g. an explorer you trust with qr scanned over HTTPS)
	// .Badge() will not show Orange for roots in this trust pool,
	// but it will not report it as "Unverified".
	if err := f.SemiTrustFromQr(qr); err != nil {
		return err
	}

	// Check current trust ids
	f.Trusted()     // pinned id from local verification
	f.SemiTrusted() // pinned id from semi-trusted source
	f.Observed()    // latest from peers

	// Clear trusted state
	f.ClearTrusted()
	f.ClearSemiTrusted()

	// </doc:verification>

	return nil
}

/// Unpack records from a resolved handle
func exampleUnpackRecords() error {
	f := fabric.New()
	zone, err := f.Resolve("alice@bitcoin")
	if err != nil {
		return err
	}

	// <doc:unpack-records>
	records, err := zone.Records.Unpack()
	if err != nil {
		return err
	}

	for _, record := range records {
		switch r := record.(type) {
		case lv.ParsedRecordTxt:
			fmt.Printf("txt %s=%s\n", r.Key, joinStrings(r.Value))
		case lv.ParsedRecordAddr:
			fmt.Printf("addr %s=%s\n", r.Key, joinStrings(r.Value))
		}
	}
	// </doc:unpack-records>

	return nil
}

/// Resolve multiple handles
func exampleResolveAll() error {
	f := fabric.New()

	// <doc:resolve-all>
	zones, err := f.ResolveAll([]string{"alice@bitcoin", "bob@bitcoin"})
	if err != nil {
		return err
	}

	for _, zone := range zones {
		fmt.Printf("%s: %s\n", zone.Handle, zone.Sovereignty)
	}
	// </doc:resolve-all>

	return nil
}

/// Pack records into a RecordSet
func examplePackRecords() error {
	// <doc:pack-records>
	records, err := lv.RecordSetPack([]lv.Record{
		lv.RecordSeq{Version: 1},
		lv.RecordTxt{Key: "website", Value: []string{"https://example.com"}},
		lv.RecordAddr{Key: "btc", Value: []string{"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"}},
		lv.RecordAddr{Key: "nostr", Value: []string{
			"npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6",
			"wss://relay.example.com",
		}},
	})
	// </doc:pack-records>

	if err != nil {
		return err
	}
	_ = records
	return nil
}

/// Publish signed records
func examplePublish() error {
	f := fabric.New()
	secretKey, err := hex.DecodeString(
		"0000000000000000000000000000000000000000000000000000000000000001",
	)
	if err != nil {
		return err
	}

	rs, err := lv.RecordSetPack([]lv.Record{
		lv.RecordSeq{Version: 1},
		lv.RecordTxt{Key: "website", Value: []string{"https://example.com"}},
		lv.RecordAddr{Key: "btc", Value: []string{"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"}},
	})
	if err != nil {
		return err
	}

	// <doc:publish>
	cert, err := f.Export("alice@bitcoin")
	if err != nil {
		return err
	}
	err = f.Publish(cert, rs, secretKey, true)
	if err != nil {
		return err
	}
	// </doc:publish>

	return nil
}

/// Resolve by numeric ID
func exampleResolveById() error {
	f := fabric.New()

	// <doc:resolve-by-id>
	zone, err := f.ResolveById("num1qx8dtlzq...")
	if err != nil {
		return err
	}
	if zone == nil {
		fmt.Println("handle not found")
		return nil
	}

	fmt.Printf("Handle found: %s\n", zone.Handle)
	// </doc:resolve-by-id>

	return nil
}

/// Search by address
func exampleSearchAddr() error {
	f := fabric.New()

	// <doc:search-addr>
	zones, err := f.SearchAddr("nostr", "npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6")
	if err != nil {
		return err
	}

	for _, zone := range zones {
		fmt.Printf("%s: %s\n", zone.Handle, zone.Sovereignty)
	}
	// </doc:search-addr>

	return nil
}

/// Advanced: Build and broadcast a message manually
func exampleMessageBuilder() error {
	f := fabric.New()
	secretKey, err := hex.DecodeString(
		"0000000000000000000000000000000000000000000000000000000000000001",
	)
	if err != nil {
		return err
	}

	certBytes, err := f.Export("alice@bitcoin")
	if err != nil {
		return err
	}
	records, err := lv.RecordSetPack([]lv.Record{
		lv.RecordSeq{Version: 1},
		lv.RecordAddr{Key: "btc", Value: []string{"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"}},
	})
	if err != nil {
		return err
	}

	// <doc:message-builder>
	builder := lv.NewMessageBuilder()
	if err := builder.AddHandle(certBytes, records.ToBytes()); err != nil {
		return err
	}

	proofReq, err := builder.ChainProofRequest()
	if err != nil {
		return err
	}
	proofBytes, err := f.Prove([]byte(proofReq))
	if err != nil {
		return err
	}

	result, err := builder.Build(proofBytes)
	if err != nil {
		return err
	}

	for _, u := range result.Unsigned {
		u.SetFlags(u.Flags() | lv.SigPrimaryZone())
		sig, err := fabric.SignSchnorr(u.SigningId(), secretKey)
		if err != nil {
			return err
		}
		if err := result.Message.SetRecords(u.Canonical(), u.PackSig(sig)); err != nil {
			return err
		}
	}

	if err := f.Broadcast(result.Message.ToBytes()); err != nil {
		return err
	}
	// </doc:message-builder>

	return nil
}

func joinStrings(ss []string) string {
	result := ""
	for i, s := range ss {
		if i > 0 {
			result += ", "
		}
		result += s
	}
	return result
}

func main() {
	if err := exampleResolve(); err != nil {
		log.Fatal(err)
	}

	if err := exampleTrustAndVerification(); err != nil {
		fmt.Printf("verification example failed (expected): %v\n", err)
	}

	if err := exampleUnpackRecords(); err != nil {
		log.Fatal(err)
	}

	if err := exampleResolveAll(); err != nil {
		log.Fatal(err)
	}

	if err := examplePackRecords(); err != nil {
		log.Fatal(err)
	}

	if err := examplePublish(); err != nil {
		log.Fatal(err)
	}

	if err := exampleResolveById(); err != nil {
		log.Fatal(err)
	}

	if err := exampleSearchAddr(); err != nil {
		log.Fatal(err)
	}

	if err := exampleMessageBuilder(); err != nil {
		log.Fatal(err)
	}

	fmt.Println("Done!")
}
