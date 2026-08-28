package edgemetrics

// Collector turns raw Caddy access-log lines into per-service latency samples. It is the glue
// between the edge supervisor (which hands it each captured stdout line) and the aggregator the
// autoscaler reads: parse → attribute (host,path → service) → record. A line that doesn't parse, or
// whose host isn't a known route, is silently dropped — so garbage, Caddy's own logs, and hostile
// Host headers never record a sample.
type Collector struct {
	agg *Aggregator
	idx *HostIndex
}

// NewCollector wires the aggregator (the rolling sample store) to the host index (host→service).
func NewCollector(agg *Aggregator, idx *HostIndex) *Collector {
	return &Collector{agg: agg, idx: idx}
}

// Ingest processes ONE access-log line. It never retains the slice (ParseAccess copies out what it
// needs) and never panics, so it is safe to call directly from the supervisor's stdout scanner.
// Unparseable / unattributable lines are no-ops.
func (c *Collector) Ingest(line []byte) {
	if rec, ok := ParseAccessFull(line); ok {
		c.IngestRecord(rec)
	}
}

// IngestRecord records an ALREADY-PARSED access record — so a caller that also feeds another consumer
// (the per-route error log) can json-parse each line only once. Unattributable records are no-ops.
func (c *Collector) IngestRecord(rec AccessRecord) {
	if c == nil || c.agg == nil || c.idx == nil {
		return
	}
	if key, ok := c.idx.Lookup(rec.Host, rec.Path); ok {
		c.agg.Record(key, rec.DurMs)
	}
}
