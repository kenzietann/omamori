// Shared, dependency-free chart math. Counts represent the supplied API sample only.
(function (root) {
  const levels = ["critical", "high", "medium", "low", "informational"];
  function severityCounts(alerts) {
    return levels.map((level) => [
      level,
      alerts.filter((alert) => alert.level === level).length,
    ]);
  }
  function timeBuckets(alerts) {
    if (!alerts.length)
      return { start: 0, step: 3600000, width: 1, buckets: [] };
    const times = alerts.map((alert) => new Date(alert.time).getTime());
    if (times.some((time) => !Number.isFinite(time)))
      throw new Error("An alert has an invalid timestamp.");
    const hour = 3600000,
      min = Math.min(...times),
      max = Math.max(...times);
    const step = max - min > 24 * hour ? 24 * hour : hour;
    const start = Math.floor(min / step) * step;
    const total = Math.floor((max - start) / step) + 1;
    const width = Math.max(1, Math.ceil(total / 12));
    const buckets = Array.from(
      { length: Math.ceil(total / width) },
      (_, index) => ({ start: start + index * width * step, count: 0 }),
    );
    for (const time of times)
      buckets[Math.floor((time - start) / (width * step))].count++;
    return { start, step, width, buckets };
  }
  const api = Object.freeze({ levels, severityCounts, timeBuckets });
  root.OmamoriCharts = api;
  if (typeof module !== "undefined") module.exports = api;
})(globalThis);
