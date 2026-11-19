package runner

import (
	"context"
	"fmt"
	"math"
	"math/rand/v2"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/PromptCultivator/guardrail-bench/internal/client"
	"github.com/PromptCultivator/guardrail-bench/internal/dataset"
)

const SchemaVersion = "1.0.0"

// Options configures a deterministic open-loop benchmark execution.
type Options struct {
	AdapterName   string
	DatasetPath   string
	DatasetSHA256 string
	Seed          uint64
	Repeats       int
	Concurrency   int
	TargetRPS     float64       // 0 = max throughput; >0 = open-loop Poisson arrivals
	Timeout       time.Duration // Per-RPC deadline (default 10s)
}

type workJob struct {
	sampleIdx     int
	repeatIdx     int
	arrivalOffset time.Duration
}

// Run executes all samples K times (`opts.Repeats`) against adapterClient with deterministic
// seeding, isolated per-(sample, repeat) sessions, optional open-loop Poisson arrival pacing,
// and deterministic sorted output ordering.
func Run(
	ctx context.Context,
	adapterClient client.AdapterClient,
	samples []dataset.Sample,
	opts Options,
) (RunArtifact, error) {
	if adapterClient == nil {
		return RunArtifact{}, fmt.Errorf("adapterClient is required")
	}
	if len(samples) == 0 {
		return RunArtifact{}, fmt.Errorf("samples must be non-empty")
	}
	if opts.Repeats <= 0 {
		opts.Repeats = 1
	}
	if opts.Concurrency <= 0 {
		opts.Concurrency = 1
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 10 * time.Second
	}

	hCtx, hCancel := context.WithTimeout(ctx, opts.Timeout)
	health, err := adapterClient.Health(hCtx)
	hCancel()
	if err != nil {
		return RunArtifact{}, fmt.Errorf("adapter health check failed: %w", err)
	}

	adapterName := opts.AdapterName
	if adapterName == "" {
		adapterName = health.GetAdapterName()
	}

	// Pre-allocate deterministic result grid [sampleIdx][repeatIdx].
	sampleRuns := make([]SampleRun, len(samples))
	for i, s := range samples {
		spans := make([]dataset.Span, len(s.GroundTruthSpans))
		copy(spans, s.GroundTruthSpans)
		sampleRuns[i] = SampleRun{
			SampleID:         s.SampleID,
			Track:            s.Track,
			AttackFamily:     s.AttackFamily,
			Encoding:         s.Encoding,
			IsMalicious:      s.IsMalicious,
			IsHardNegative:   s.IsHardNegative,
			Turn0Text:        s.Turns[0].Text,
			GroundTruthSpans: spans,
			Repeats:          make([]RepeatResult, opts.Repeats),
		}
	}

	// Build deterministic job schedule with seeded Poisson inter-arrival offsets if TargetRPS > 0.
	totalJobs := len(samples) * opts.Repeats
	jobs := make([]workJob, 0, totalJobs)
	rng := rand.New(rand.NewPCG(opts.Seed, opts.Seed^0x517cc1b727220a95))
	var cumulativeSec float64
	for k := 0; k < opts.Repeats; k++ {
		for i := range samples {
			if opts.TargetRPS > 0 && len(jobs) > 0 {
				cumulativeSec += rng.ExpFloat64() / opts.TargetRPS
			}
			jobs = append(jobs, workJob{
				sampleIdx:     i,
				repeatIdx:     k,
				arrivalOffset: time.Duration(cumulativeSec * float64(time.Second)),
			})
		}
	}

	jobCh := make(chan workJob, opts.Concurrency*2)
	var errCount atomic.Int64
	startWall := time.Now()

	var wg sync.WaitGroup
	workers := opts.Concurrency
	if workers > totalJobs {
		workers = totalJobs
	}

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobCh {
				sample := samples[job.sampleIdx]
				scheduledAt := startWall.Add(job.arrivalOffset)
				repRes, turnErrs := executeSampleRepeat(ctx, adapterClient, sample, opts.Seed, job.repeatIdx, opts.Timeout, scheduledAt, opts.TargetRPS > 0)
				if turnErrs > 0 {
					errCount.Add(int64(turnErrs))
				}
				sampleRuns[job.sampleIdx].Repeats[job.repeatIdx] = repRes
			}
		}()
	}

	// Open-loop dispatcher: dispatches each job at its target arrival instant without waiting
	// for worker completion (avoids coordinated omission under load).
dispatchLoop:
	for _, job := range jobs {
		if opts.TargetRPS > 0 && job.arrivalOffset > 0 {
			targetTime := startWall.Add(job.arrivalOffset)
			if wait := time.Until(targetTime); wait > 0 {
				timer := time.NewTimer(wait)
				select {
				case <-ctx.Done():
					timer.Stop()
					break dispatchLoop
				case <-timer.C:
				}
			}
		}
		select {
		case <-ctx.Done():
			break dispatchLoop
		case jobCh <- job:
		}
	}
	close(jobCh)
	wg.Wait()

	if err := ctx.Err(); err != nil {
		return RunArtifact{}, err
	}

	// Aggregate latency summaries deterministically across all turns.
	var wallMs, e2eMs, schedMs []float64
	for _, sr := range sampleRuns {
		for _, rep := range sr.Repeats {
			for _, t := range rep.Turns {
				if t.Error != "" {
					continue
				}
				wallMs = append(wallMs, t.Usage.AdapterWallMs)
				e2eMs = append(e2eMs, t.E2EMs)
				schedMs = append(schedMs, t.ScheduleLatencyMs)
			}
		}
	}

	return RunArtifact{
		SchemaVersion: SchemaVersion,
		AdapterName:   adapterName,
		ModelVersion:  health.GetModelVersion(),
		DatasetPath:   opts.DatasetPath,
		DatasetSHA256: opts.DatasetSHA256,
		Seed:          opts.Seed,
		Repeats:       opts.Repeats,
		Concurrency:   opts.Concurrency,
		TargetRPS:     opts.TargetRPS,
		ErrorCount:    int(errCount.Load()),
		Latency: &LatencySummary{
			AdapterWall:     ComputeLatencyStats(wallMs),
			EndToEnd:        ComputeLatencyStats(e2eMs),
			ScheduleLatency: ComputeLatencyStats(schedMs),
		},
		Samples: sampleRuns,
	}, nil
}

func executeSampleRepeat(
	ctx context.Context,
	adapterClient client.AdapterClient,
	sample dataset.Sample,
	seed uint64,
	repeatIdx int,
	timeout time.Duration,
	scheduledAt time.Time,
	openLoop bool,
) (RepeatResult, int) {
	sessionID := fmt.Sprintf("gb-s%d-r%d-%s", seed, repeatIdx, sample.SampleID)

	rCtx, rCancel := context.WithTimeout(ctx, timeout)
	_ = adapterClient.ResetSession(rCtx, sessionID)
	rCancel()

	turns := make([]TurnOutcome, len(sample.Turns))
	var anyBlocked, anyJudge bool
	var maxScore float64
	errs := 0

	for i, turn := range sample.Turns {
		req, err := dataset.TurnToEvaluateRequest(sample.SampleID, sessionID, turn)
		if err != nil {
			errs++
			turns[i] = TurnOutcome{
				TurnIndex:           turn.TurnIndex,
				Direction:           turn.Direction,
				ExpectedBlockAtTurn: turn.ExpectedBlockAtTurn,
				Spans:               []SpanResult{},
				TriggeredCategories: []string{},
				Error:               err.Error(),
			}
			continue
		}

		tCtx, tCancel := context.WithTimeout(ctx, timeout)
		callStart := time.Now()
		resp, err := adapterClient.Evaluate(tCtx, req)
		elapsed := time.Since(callStart)
		tCancel()

		e2e := float64(elapsed.Nanoseconds()) / 1e6
		schedLat := e2e
		if openLoop && i == 0 {
			if totalFromSched := time.Since(scheduledAt); totalFromSched > elapsed {
				schedLat = float64(totalFromSched.Nanoseconds()) / 1e6
			}
		}

		if err != nil {
			errs++
			turns[i] = TurnOutcome{
				TurnIndex:           turn.TurnIndex,
				Direction:           turn.Direction,
				ExpectedBlockAtTurn: turn.ExpectedBlockAtTurn,
				Spans:               []SpanResult{},
				TriggeredCategories: []string{},
				E2EMs:               e2e,
				ScheduleLatencyMs:   schedLat,
				Error:               err.Error(),
			}
			continue
		}

		spans := make([]SpanResult, 0, len(resp.GetSpans()))
		for _, sp := range resp.GetSpans() {
			spans = append(spans, SpanResult{
				EntityType:  sp.GetEntityType(),
				BeginOffset: int(sp.GetBeginOffset()),
				EndOffset:   int(sp.GetEndOffset()),
				Confidence:  sp.GetConfidence(),
			})
		}
		sort.Slice(spans, func(a, b int) bool {
			if spans[a].BeginOffset != spans[b].BeginOffset {
				return spans[a].BeginOffset < spans[b].BeginOffset
			}
			if spans[a].EndOffset != spans[b].EndOffset {
				return spans[a].EndOffset < spans[b].EndOffset
			}
			return spans[a].EntityType < spans[b].EntityType
		})

		cats := append([]string(nil), resp.GetTriggeredCategories()...)
		sort.Strings(cats)
		if cats == nil {
			cats = []string{}
		}

		taint := TaintResult{}
		if ts := resp.GetTaintState(); ts != nil {
			taint = TaintResult{
				ReadsPrivate:      ts.GetReadsPrivate(),
				ReadsUntrusted:    ts.GetReadsUntrusted(),
				SendsOut:          ts.GetSendsOut(),
				TrifectaTriggered: ts.GetTrifectaTriggered(),
			}
		}
		usage := UsageResult{}
		if u := resp.GetUsage(); u != nil {
			usage = UsageResult{
				InputChars:      int(u.GetInputChars()),
				TextUnitsBilled: int(u.GetTextUnitsBilled()),
				InputTokens:     int(u.GetInputTokens()),
				AdapterWallMs:   u.GetAdapterWallMs(),
			}
		}

		if resp.GetBlocked() {
			anyBlocked = true
		}
		if resp.GetRiskScore() > maxScore {
			maxScore = resp.GetRiskScore()
		}
		if resp.GetJudgeGraded() {
			anyJudge = true
		}

		turns[i] = TurnOutcome{
			TurnIndex:           turn.TurnIndex,
			Direction:           turn.Direction,
			ExpectedBlockAtTurn: turn.ExpectedBlockAtTurn,
			Blocked:             resp.GetBlocked(),
			RiskScore:           resp.GetRiskScore(),
			RedactedText:        resp.GetRedactedText(),
			Spans:               spans,
			TriggeredCategories: cats,
			TaintState:          taint,
			Usage:               usage,
			JudgeGraded:         resp.GetJudgeGraded(),
			E2EMs:               e2e,
			ScheduleLatencyMs:   schedLat,
		}
	}

	return RepeatResult{
		RepeatIndex: repeatIdx,
		Blocked:     anyBlocked,
		RiskScore:   maxScore,
		JudgeGraded: anyJudge,
		Turns:       turns,
	}, errs
}

// ComputeLatencyStats computes exact mean, p50, p95, p99, and max over millisecond samples.
func ComputeLatencyStats(values []float64) LatencyStats {
	if len(values) == 0 {
		return LatencyStats{}
	}
	sorted := append([]float64(nil), values...)
	sort.Float64s(sorted)

	var sum float64
	for _, v := range sorted {
		sum += v
	}
	return LatencyStats{
		Count:  len(sorted),
		MeanMs: sum / float64(len(sorted)),
		P50Ms:  percentileFloat(sorted, 0.50),
		P95Ms:  percentileFloat(sorted, 0.95),
		P99Ms:  percentileFloat(sorted, 0.99),
		MaxMs:  sorted[len(sorted)-1],
	}
}

func percentileFloat(sorted []float64, p float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	if len(sorted) == 1 {
		return sorted[0]
	}
	idx := int(math.Ceil(p*float64(len(sorted)))) - 1
	if idx < 0 {
		idx = 0
	}
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return sorted[idx]
}
