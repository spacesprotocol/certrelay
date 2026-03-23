package org.spacesprotocol.fabric

class FabricError(
    val code: String,
    override val message: String,
    val status: Int = 0,
) : Exception(
    if (status > 0) "$code ($status): $message" else "$code: $message"
)
