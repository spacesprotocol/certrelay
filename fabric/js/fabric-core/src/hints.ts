export interface HandleHint {
  seq: number;
  name: string;
}

export interface EpochResult {
  epoch: number;
  res: HandleHint[];
}

export interface SpaceHint {
  epoch_tip: number;
  name: string;
  seq: number;
  delegate_seq: number;
  epochs: EpochResult[];
}

export interface HintsResponse {
  anchor_tip: number;
  hints: SpaceHint[];
}

function cmpScore(a: number, b: number): number {
  if (a > b) return 1;
  if (a < b) return -1;
  return 0;
}

function flattenHandles(space: SpaceHint): Map<string, number> {
  const map = new Map<string, number>();
  for (const epoch of space.epochs) {
    for (const handle of epoch.res) {
      const existing = map.get(handle.name) ?? 0;
      if (handle.seq > existing) {
        map.set(handle.name, handle.seq);
      }
    }
  }
  return map;
}

/**
 * Compare two HintsResponses by freshness.
 * Returns positive if `a` is fresher, negative if `b` is fresher, 0 if equal.
 * Mirrors the Rust `Ord` implementation exactly.
 */
export function compareHints(a: HintsResponse, b: HintsResponse): number {
  let score = 0;

  for (const space of a.hints) {
    const otherSpace = b.hints.find((s) => s.name === space.name);
    if (!otherSpace) {
      score += 1;
      continue;
    }

    score += cmpScore(space.epoch_tip, otherSpace.epoch_tip);
    score += cmpScore(space.seq, otherSpace.seq);
    score += cmpScore(space.delegate_seq, otherSpace.delegate_seq);

    const selfHandles = flattenHandles(space);
    const otherHandles = flattenHandles(otherSpace);

    for (const [name, selfSeq] of selfHandles) {
      const otherSeq = otherHandles.get(name);
      if (otherSeq !== undefined) {
        score += cmpScore(selfSeq, otherSeq);
      } else {
        score += 1;
      }
    }
    for (const name of otherHandles.keys()) {
      if (!selfHandles.has(name)) {
        score -= 1;
      }
    }
  }

  for (const otherSpace of b.hints) {
    if (!a.hints.some((s) => s.name === otherSpace.name)) {
      score -= 1;
    }
  }

  if (score !== 0) {
    return score > 0 ? 1 : -1;
  }
  return cmpScore(a.anchor_tip, b.anchor_tip);
}
