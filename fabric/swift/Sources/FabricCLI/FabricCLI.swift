import Fabric
import Foundation

@main
struct FabricCLI {
    static func main() async throws {
        var args = Array(CommandLine.arguments.dropFirst())
        var handles = [String]()
        var seeds: [String]?
        var anchorSetHash: String?
        var devMode = false

        while !args.isEmpty {
            let arg = args.removeFirst()
            switch arg {
            case "--seeds":
                guard !args.isEmpty else { exit(usage: "--seeds requires a value") }
                seeds = args.removeFirst().split(separator: ",").map(String.init)
            case "--anchor-set-hash":
                guard !args.isEmpty else { exit(usage: "--anchor-set-hash requires a value") }
                anchorSetHash = args.removeFirst()
            case "--dev-mode":
                devMode = true
            case "--help", "-h":
                printUsage()
                Foundation.exit(0)
            default:
                if arg.hasPrefix("-") {
                    exit(usage: "unknown option: \(arg)")
                }
                handles.append(arg)
            }
        }

        if handles.isEmpty {
            exit(usage: "no handles specified")
        }

        let fabric = Fabric(
            seeds: seeds ?? defaultSeeds,
            anchorSetHash: anchorSetHash,
            devMode: devMode
        )

        let zones = try await fabric.resolveAll(handles)

        for handle in handles {
            guard let zone = zones.first(where: { $0.handle == handle }) else {
                fputs("\(handle): not found\n", stderr)
                continue
            }
            print(try zoneToJson(zone: zone))
        }
    }

    static func printUsage() {
        print("""
        Usage: fabric [options] <handle> [<handle> ...]

        Resolve handles via the certrelay network.

        Options:
          --seeds <url,url,...>      Seed relay URLs (comma-separated)
          --anchor-set-hash <hex>    Anchor set hash for verification
          --dev-mode                 Enable dev mode (skip finality checks)
          -h, --help                 Show this help
        """)
    }

    static func exit(usage: String) -> Never {
        fputs("error: \(usage)\n", stderr)
        printUsage()
        Foundation.exit(1)
    }
}
