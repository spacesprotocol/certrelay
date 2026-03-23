from dataclasses import dataclass, field


@dataclass
class HandleHint:
    handle: str
    seq: int


@dataclass
class EpochResult:
    epoch_tip: int
    handles: list[HandleHint] = field(default_factory=list)


@dataclass
class SpaceHint:
    space: str
    epoch_tip: int
    seq: int
    delegate_seq: int


@dataclass
class HintsResponse:
    anchor_tip: int = 0
    spaces: list[SpaceHint] = field(default_factory=list)
    epochs: list[EpochResult] = field(default_factory=list)


def _hints_score(h: HintsResponse) -> int:
    score = 0
    for s in h.spaces:
        score += s.epoch_tip * 1000 + s.seq + s.delegate_seq
    for e in h.epochs:
        score += e.epoch_tip * 100
        for hh in e.handles:
            score += hh.seq
    return score


def CompareHints(a: HintsResponse, b: HintsResponse) -> int:
    """Returns >0 if a is fresher, <0 if b is fresher, 0 if equal."""
    sa, sb = _hints_score(a), _hints_score(b)
    if sa != sb:
        return 1 if sa > sb else -1
    if a.anchor_tip != b.anchor_tip:
        return 1 if a.anchor_tip > b.anchor_tip else -1
    return 0
