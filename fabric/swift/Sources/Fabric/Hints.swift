import Foundation

struct HandleHint: Decodable {
    let seq: Int
    let name: String
}

struct EpochResult: Decodable {
    let epoch: Int
    let res: [HandleHint]
}

struct SpaceHint: Decodable {
    let epoch_tip: Int
    let name: String
    let seq: Int
    let delegate_seq: Int
    let epochs: [EpochResult]
}

struct HintsResponse: Decodable {
    let anchor_tip: Int
    let hints: [SpaceHint]
}

/// Compare two HintsResponses by freshness.
/// Returns positive if `a` is fresher, negative if `b` is fresher, 0 if equal.
func compareHints(_ a: HintsResponse, _ b: HintsResponse) -> Int {
    var score = 0

    for space in a.hints {
        guard let otherSpace = b.hints.first(where: { $0.name == space.name }) else {
            score += 1
            continue
        }

        score += cmpScore(space.epoch_tip, otherSpace.epoch_tip)
        score += cmpScore(space.seq, otherSpace.seq)
        score += cmpScore(space.delegate_seq, otherSpace.delegate_seq)

        let selfHandles = flattenHandles(space)
        let otherHandles = flattenHandles(otherSpace)

        for (name, selfSeq) in selfHandles {
            if let otherSeq = otherHandles[name] {
                score += cmpScore(selfSeq, otherSeq)
            } else {
                score += 1
            }
        }
        for name in otherHandles.keys where selfHandles[name] == nil {
            score -= 1
        }
    }

    for otherSpace in b.hints where !a.hints.contains(where: { $0.name == otherSpace.name }) {
        score -= 1
    }

    if score != 0 {
        return score > 0 ? 1 : -1
    }
    return cmpScore(a.anchor_tip, b.anchor_tip)
}

private func cmpScore<T: Comparable>(_ a: T, _ b: T) -> Int {
    if a > b { return 1 }
    if a < b { return -1 }
    return 0
}

private func flattenHandles(_ space: SpaceHint) -> [String: Int] {
    var map = [String: Int]()
    for epoch in space.epochs {
        for handle in epoch.res {
            let existing = map[handle.name] ?? 0
            if handle.seq > existing {
                map[handle.name] = handle.seq
            }
        }
    }
    return map
}
