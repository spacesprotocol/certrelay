package fabric

type HandleHint struct {
	Handle string `json:"handle"`
	Seq    int    `json:"seq"`
}

type EpochResult struct {
	EpochTip int          `json:"epoch_tip"`
	Handles  []HandleHint `json:"handles"`
}

type SpaceHint struct {
	Space       string `json:"space"`
	EpochTip    int    `json:"epoch_tip"`
	Seq         int    `json:"seq"`
	DelegateSeq int    `json:"delegate_seq"`
}

type HintsResponse struct {
	AnchorTip int           `json:"anchor_tip"`
	Spaces    []SpaceHint   `json:"spaces"`
	Epochs    []EpochResult `json:"epochs"`
}

// CompareHints returns >0 if a is fresher, <0 if b is fresher, 0 if equal.
func CompareHints(a, b HintsResponse) int {
	scoreA := hintsScore(a)
	scoreB := hintsScore(b)
	if scoreA > scoreB {
		return 1
	}
	if scoreA < scoreB {
		return -1
	}
	if a.AnchorTip > b.AnchorTip {
		return 1
	}
	if a.AnchorTip < b.AnchorTip {
		return -1
	}
	return 0
}

func hintsScore(h HintsResponse) int {
	score := 0
	for _, s := range h.Spaces {
		score += s.EpochTip*1000 + s.Seq + s.DelegateSeq
	}
	for _, e := range h.Epochs {
		score += e.EpochTip * 100
		for _, hh := range e.Handles {
			score += hh.Seq
		}
	}
	return score
}
