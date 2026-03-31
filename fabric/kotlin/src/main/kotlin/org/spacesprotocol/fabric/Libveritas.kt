@file:Suppress("unused")

package org.spacesprotocol.fabric

// Re-export libveritas types so consumers can use them without a separate import.

typealias Zone = org.spacesprotocol.libveritas.Zone
typealias Message = org.spacesprotocol.libveritas.Message
typealias MessageBuilder = org.spacesprotocol.libveritas.MessageBuilder
typealias Anchors = org.spacesprotocol.libveritas.Anchors
typealias Veritas = org.spacesprotocol.libveritas.Veritas
typealias QueryContext = org.spacesprotocol.libveritas.QueryContext
typealias VerifiedMessage = org.spacesprotocol.libveritas.VerifiedMessage
typealias Lookup = org.spacesprotocol.libveritas.Lookup
typealias RecordSet = org.spacesprotocol.libveritas.RecordSet
typealias Record = org.spacesprotocol.libveritas.Record
typealias DataUpdateEntry = org.spacesprotocol.libveritas.DataUpdateEntry
typealias CommitmentState = org.spacesprotocol.libveritas.CommitmentState
typealias DelegateState = org.spacesprotocol.libveritas.DelegateState
typealias TrustSet = org.spacesprotocol.libveritas.TrustSet
typealias VeritasException = org.spacesprotocol.libveritas.VeritasException
typealias InternalException = org.spacesprotocol.libveritas.InternalException

/** Re-export the top-level helper so callers can use it without a libveritas import. */
fun createCertificateChain(subject: String, certBytesList: List<ByteArray>): ByteArray =
    org.spacesprotocol.libveritas.createCertificateChain(subject, certBytesList)

