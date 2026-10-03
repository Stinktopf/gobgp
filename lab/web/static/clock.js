// The clock of the replay: every variant of a run on one time axis.
//
// By time, each variant plays its own time since its start. By steps, the
// variants align at every mark they share: each action and the end of each
// until_stable. A mark is known by its step and how often that step has
// marked before, so actions of parallel steps match in any order; older
// runs without steps match by name. Between two marks the clock runs as
// long as the slowest variant needs; the others hold their state.
//
// make(runs, bySteps) takes {variant: {t, events}} and returns
//   toRun(run, c)   the time of a run at clock time c
//   fromRun(run, t) the clock time of time t of a run
//   events          the events of the first run, each with its clock time c
//   end             the length of the clock
//   holds           whether a run holds at its end until the clock ends
(() => {
  const segment = (bounds, v) => { let k = 0; while (k < bounds.length - 2 && bounds[k + 1] <= v) k++; return k; };

  function idsOf(run) {
    const seen = {};
    return run.events.map((e) => {
      const base = e.step != null ? `${e.name}@${e.step}` : e.name;
      seen[base] = (seen[base] || 0) + 1;
      return `${base}#${seen[base]}`;
    });
  }

  function make(runs, bySteps) {
    const names = Object.keys(runs), all = Object.values(runs), first = all[0];
    if (!bySteps || all.length < 2) {
      return {
        toRun: (run, c) => c, fromRun: (run, t) => t,
        events: (first?.events || []).map((e) => ({ ...e, c: e.t })),
        end: Math.max(1, ...all.map((r) => r.t.at(-1) ?? 1)),
        holds: false,
      };
    }
    const ids = all.map(idsOf);
    const times = all.map((r, j) => new Map(ids[j].map((id, k) => [id, Math.max(0, r.events[k].t)])));
    // The marks of every run, in the order of the first, skipping any that
    // would run backwards in another run.
    const kept = [], latest = all.map(() => 0);
    for (const id of ids[0]) {
      const ts = times.map((m) => m.get(id));
      if (ts.some((t, j) => t == null || t < latest[j])) continue;
      kept.push(id);
      ts.forEach((t, j) => (latest[j] = t));
    }
    const marks = new Map(all.map((r, j) => [r, [0, ...kept.map((id) => times[j].get(id)), Math.max(latest[j], r.t.at(-1) ?? 0)]]));
    const common = [0];
    for (let k = 1; k < kept.length + 2; k++) {
      common.push(common[k - 1] + Math.max(...all.map((r) => marks.get(r)[k] - marks.get(r)[k - 1])));
    }
    const at = new Map(kept.map((id, k) => [id, common[k + 1]]));
    const clock = {
      toRun(run, c) {
        const m = marks.get(run), k = segment(common, c);
        return m[k] + Math.min(c - common[k], m[k + 1] - m[k]);
      },
      fromRun(run, t) {
        const m = marks.get(run), k = segment(m, t);
        return common[k] + (t - m[k]);
      },
      end: Math.max(1, common.at(-1)),
      holds: true,
    };
    // An end of until_stable tells how it ended in each run, a check whether
    // it passed and why not.
    const byId = all.map((r, j) => new Map(ids[j].map((id, k) => [id, r.events[k]])));
    const outcome = (e, id) => (e.name === "settled" ? names.map((n, j) => [n, byId[j].get(id)?.stable])
      : names.map((n, j) => [n, byId[j].get(id)?.passed, byId[j].get(id)?.problems || []]));
    clock.events = first.events.map((e, k) => ({
      ...e, c: at.get(ids[0][k]) ?? clock.fromRun(first, e.t),
      ...((e.name === "settled" || e.name === "expect") && at.has(ids[0][k]) ? { each: outcome(e, ids[0][k]) } : {}),
    }));
    return clock;
  }

  const api = { make };
  if (typeof module !== "undefined") module.exports = api;
  else window.ReplayClock = api;
})();
