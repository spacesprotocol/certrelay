package fabric

// Re-export libveritas types so consumers can use them without a separate import.

import libveritas "github.com/spacesprotocol/libveritas-go"

type Zone = libveritas.Zone
type Message = libveritas.Message
type MessageBuilder = libveritas.MessageBuilder
type Anchors = libveritas.Anchors
type Veritas = libveritas.Veritas
type QueryContext = libveritas.QueryContext
type VerifiedMessage = libveritas.VerifiedMessage
type Lookup = libveritas.Lookup
type RecordSet = libveritas.RecordSet
type Record = libveritas.Record
type DataUpdateEntry = libveritas.DataUpdateEntry
type CommitmentState = libveritas.CommitmentState
type DelegateState = libveritas.DelegateState
type VeritasError = libveritas.VeritasError

var CreateCertificateChain = libveritas.CreateCertificateChain
