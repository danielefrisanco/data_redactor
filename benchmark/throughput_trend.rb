# frozen_string_literal: true

# Throughput-trend comparator for CI.
#
# Reads the current ratio (ci_throughput_gate.rb's BENCHMARK_JSON output) and a
# cached history of prior ratios, then:
#   - appends the current point to the history (written back to HISTORY),
#   - prints a Markdown comparison vs. the previous point to stdout (for a PR
#     comment via `gh pr comment`),
#   - exits non-zero if the ratio dropped more than DROP_PCT below the previous
#     point (a real regression; the ratio cancels runner speed, so a drop is the
#     engine, not the runner).
#
# This replaces github-action-benchmark: that tool only posts COMMIT comments
# (not PR-thread comments) and couples history to a gh-pages branch. We keep the
# history as a plain JSON array in actions/cache and post the PR comment with the
# built-in gh CLI — no third-party action, no gh-pages.
#
#   RATIO_JSON=ratio.json HISTORY=bench-cache/history.json \
#     ruby benchmark/throughput_trend.rb > comment.md
#
# Env:
#   RATIO_JSON  current point, ci_throughput_gate.rb schema  (required)
#   HISTORY     JSON array of {commit,ratio,date}; created if absent (required)
#   COMMIT      short SHA to label the point                  (default "local")
#   APPEND      "1" to append+write the point, "0" to compare only (default "1")
#   DROP_PCT    max allowed drop vs. previous before failing  (default 10)

require "json"
require "time"

ratio_json = ENV.fetch("RATIO_JSON")
history_path = ENV.fetch("HISTORY")
commit = ENV.fetch("COMMIT", "local")
append = ENV.fetch("APPEND", "1") == "1"
drop_pct = Float(ENV.fetch("DROP_PCT", "10"))

current = JSON.parse(File.read(ratio_json))
  .find { |e| e["name"] == "C/pure-Ruby throughput ratio" }
  &.fetch("value")
abort "no ratio entry in #{ratio_json}" if current.nil?

history = File.exist?(history_path) ? JSON.parse(File.read(history_path)) : []
previous = history.last

# Comparison line. With no prior point this is the first record — nothing to
# compare, so the delta is omitted rather than faked.
if previous
  prev_ratio = previous.fetch("ratio")
  delta_pct = (current - prev_ratio) / prev_ratio * 100.0
  arrow = delta_pct >= 0 ? "🟢 +" : "🔴 "
  trend = format("%s%.1f%% vs previous (%.3fx → %.3fx)", arrow, delta_pct, prev_ratio, current)
  regressed = delta_pct < -drop_pct
else
  delta_pct = nil
  trend = "first recorded point — no baseline to compare yet"
  regressed = false
end

puts "### Throughput trend (C engine vs pure-Ruby gsub)"
puts
puts format("**Ratio: %.3fx** — %s", current, trend)
puts
puts "<sub>Runner-independent metric (the ratio cancels runner speed). " \
     "History lives in the CI cache; only merges to `main` advance it.</sub>"

if append
  history << { "commit" => commit, "ratio" => current, "date" => Time.now.utc.iso8601 }
  File.write(history_path, JSON.pretty_generate(history))
  warn "appended point (#{history.size} total) to #{history_path}"
end

if regressed
  warn format("FAIL: ratio dropped %.1f%% (> %.0f%% allowed) vs previous", -delta_pct, drop_pct)
  exit 1
end
