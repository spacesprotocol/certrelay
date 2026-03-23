package org.spacesprotocol.fabric.cli

import org.spacesprotocol.fabric.DEFAULT_SEEDS
import org.spacesprotocol.fabric.Fabric
import org.spacesprotocol.libveritas.zoneToJson
import kotlin.system.exitProcess

fun main(args: Array<String>) {
    val handles = mutableListOf<String>()
    var seeds: List<String>? = null
    var anchorSetHash: String? = null
    var devMode = false

    var i = 0
    while (i < args.size) {
        when (args[i]) {
            "--seeds" -> {
                i++
                if (i >= args.size) exitUsage("--seeds requires a value")
                seeds = args[i].split(",")
            }
            "--anchor-set-hash" -> {
                i++
                if (i >= args.size) exitUsage("--anchor-set-hash requires a value")
                anchorSetHash = args[i]
            }
            "--dev-mode" -> devMode = true
            "--help", "-h" -> {
                printUsage()
                exitProcess(0)
            }
            else -> {
                if (args[i].startsWith("-")) exitUsage("unknown option: ${args[i]}")
                handles.add(args[i])
            }
        }
        i++
    }

    if (handles.isEmpty()) exitUsage("no handles specified")

    val fabric = Fabric(
        seeds = seeds ?: DEFAULT_SEEDS,
        devMode = devMode,
        anchorSetHash = anchorSetHash,
    )

    val zones = try {
        fabric.resolveAll(handles)
    } catch (e: Exception) {
        System.err.println("error: $e")
        exitProcess(1)
    }

    for (handle in handles) {
        val zone = zones.find { it.handle == handle }
        if (zone == null) {
            System.err.println("$handle: not found")
            continue
        }
        try {
            println(zoneToJson(zone))
        } catch (e: Exception) {
            System.err.println("$handle: $e")
        }
    }
}

fun printUsage() {
    println("""Usage: fabric [options] <handle> [<handle> ...]

Resolve handles via the certrelay network.

Options:
  --seeds <url,url,...>      Seed relay URLs (comma-separated)
  --anchor-set-hash <hex>    Anchor set hash for verification
  --dev-mode                 Enable dev mode (skip finality checks)
  -h, --help                 Show this help""")
}

fun exitUsage(msg: String): Nothing {
    System.err.println("error: $msg")
    printUsage()
    exitProcess(1)
}
