package scorer

import (
	"math"
	"math/rand/v2"
	"sort"
)

const (
	// DefaultBootstrapResamples is the canonical B = 1,000 non-parametric bootstrap count.
	DefaultBootstrapResamples = 1000
)

// ConfidenceInterval holds a point estimate and its 95% bootstrap [Lower, Upper] interval.
type ConfidenceInterval struct {
	Point float64 `json:"point"`
	Lower float64 `json:"lower_95"`
	Upper float64 `json:"upper_95"`
}

// BootstrapCI computes a deterministic seeded 95% percentile bootstrap CI over a slice of length n.
func BootstrapCI(n int, resamples int, seed uint64, stream uint64, point float64, eval func(indices []int) float64) ConfidenceInterval {
	if n <= 0 || resamples <= 0 {
		return ConfidenceInterval{Point: point, Lower: point, Upper: point}
	}
	rng := rand.New(rand.NewPCG(seed, stream))
	vals := make([]float64, resamples)
	indices := make([]int, n)
	for b := 0; b < resamples; b++ {
		for i := 0; i < n; i++ {
			indices[i] = rng.IntN(n)
		}
		vals[b] = eval(indices)
	}
	return percentileCI(point, vals)
}

// StratifiedBootstrapCI resamples benign (nB) and malicious (nM) groups independently with replacement.
func StratifiedBootstrapCI(
	nB, nM int,
	resamples int,
	seed uint64,
	stream uint64,
	point float64,
	eval func(bIdx, mIdx []int) float64,
) ConfidenceInterval {
	if nB <= 0 || nM <= 0 || resamples <= 0 {
		return ConfidenceInterval{Point: point, Lower: point, Upper: point}
	}
	rng := rand.New(rand.NewPCG(seed, stream))
	vals := make([]float64, resamples)
	bIdx := make([]int, nB)
	mIdx := make([]int, nM)
	for b := 0; b < resamples; b++ {
		for i := 0; i < nB; i++ {
			bIdx[i] = rng.IntN(nB)
		}
		for j := 0; j < nM; j++ {
			mIdx[j] = rng.IntN(nM)
		}
		vals[b] = eval(bIdx, mIdx)
	}
	return percentileCI(point, vals)
}

func percentileCI(point float64, samples []float64) ConfidenceInterval {
	sort.Float64s(samples)
	lo := quantileSorted(samples, 0.025)
	hi := quantileSorted(samples, 0.975)
	return ConfidenceInterval{
		Point: round6(point),
		Lower: round6(lo),
		Upper: round6(hi),
	}
}

func quantileSorted(sorted []float64, q float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	if len(sorted) == 1 {
		return sorted[0]
	}
	pos := q * float64(len(sorted)-1)
	lo := int(math.Floor(pos))
	hi := int(math.Ceil(pos))
	if lo == hi {
		return sorted[lo]
	}
	frac := pos - float64(lo)
	return sorted[lo]*(1-frac) + sorted[hi]*frac
}

func round6(v float64) float64 {
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return 0
	}
	return math.Round(v*1e6) / 1e6
}
