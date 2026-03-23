package org.spacesprotocol.fabric

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class HandleHint(
    val handle: String,
    val seq: Int,
)

@Serializable
data class EpochResult(
    @SerialName("epoch_tip") val epochTip: Int,
    val handles: List<HandleHint> = emptyList(),
)

@Serializable
data class SpaceHint(
    val space: String,
    @SerialName("epoch_tip") val epochTip: Int,
    val seq: Int,
    @SerialName("delegate_seq") val delegateSeq: Int,
)

@Serializable
data class HintsResponse(
    @SerialName("anchor_tip") val anchorTip: Int = 0,
    val spaces: List<SpaceHint> = emptyList(),
    val epochs: List<EpochResult> = emptyList(),
)

fun compareHints(a: HintsResponse, b: HintsResponse): Int {
    val scoreA = hintsScore(a)
    val scoreB = hintsScore(b)
    if (scoreA != scoreB) return scoreA.compareTo(scoreB)
    return a.anchorTip.compareTo(b.anchorTip)
}

private fun hintsScore(h: HintsResponse): Int {
    var score = 0
    for (s in h.spaces) {
        score += s.epochTip * 1000 + s.seq + s.delegateSeq
    }
    for (e in h.epochs) {
        score += e.epochTip * 100
        for (hh in e.handles) {
            score += hh.seq
        }
    }
    return score
}
