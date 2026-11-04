import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createContext, runInContext } from 'node:vm';
import { test } from 'node:test';
import ts from 'typescript';

const compile = source => ts.transpileModule(source, { compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2020 } }).outputText;
const statusSource = await readFile(new URL('../src/lib/dnsProbeStatus.ts', import.meta.url), 'utf8');
const hookSource = await readFile(new URL('../src/lib/useDNSProbes.ts', import.meta.url), 'utf8');
const statusContext = createContext({ exports: {}, Date: { now: () => 9999999999999 } });
runInContext(compile(statusSource), statusContext);
const { dnsProbeOnline, dnsProbeStatus } = statusContext.exports;

test('server time survives browser clock skew; stale snapshots become unknown rather than offline', () => {
  const probe = { enabled: true, last_heartbeat_at: 1000, status_checked_at: 1020, received_at_ms: 5000 };
  assert.equal(dnsProbeOnline(probe, 5000), true);
  assert.equal(dnsProbeOnline(probe, 64000), true);
  assert.equal(dnsProbeStatus(probe, 65000), 'stale');
  assert.equal(dnsProbeOnline(probe, 35000, 30), true);
  assert.equal(dnsProbeOnline(probe, 35000, 15), false);
  assert.equal(dnsProbeOnline({ ...probe, enabled: false }, 5000), false);
  assert.equal(dnsProbeOnline({ ...probe, last_heartbeat_at: undefined }, 5000), false);
  assert.equal(dnsProbeOnline({ ...probe, last_heartbeat_at: 1021 }, 5000), false);
  assert.equal(dnsProbeStatus({ ...probe, online: false }, 5000), 'offline');
  assert.equal(dnsProbeStatus({ ...probe, online: true }, 5000), 'online');
});

test('each DNS rule keeps its own offline threshold independently of the probe default', () => {
  const probe = { enabled: true, online: false, last_heartbeat_at: 1000, status_checked_at: 1120, received_at_ms: 5000 };
  assert.equal(dnsProbeStatus(probe, 5000), 'offline');
  assert.equal(dnsProbeOnline(probe, 5000, 180), true);
  assert.equal(dnsProbeOnline(probe, 5000, 60), false);
  assert.equal(dnsProbeOnline({ ...probe, enabled: false }, 5000, 180), false);
  assert.equal(dnsProbeStatus(probe, 65000, 180), 'stale');
});

function runtime({ live = true, hidden = false } = {}) {
  const state = [], refs = [], effects = [], requests = [], intervals = new Map(), timeouts = new Map(), errors = [];
  const window = new EventTarget(), document = new EventTarget();
  document.visibilityState = hidden ? 'hidden' : 'visible';
  let now = 0, id = 0;
  window.setInterval = (fn, ms) => { assert.equal(ms, 30000); intervals.set(++id, fn); return id; };
  window.clearInterval = key => intervals.delete(key);
  window.setTimeout = fn => { timeouts.set(++id, fn); return id; };
  window.clearTimeout = key => timeouts.delete(key);
  const react = {
    useState(initial) { const i = state.length; state.push(typeof initial === 'function' ? initial() : initial); return [state[i], value => { state[i] = value; }]; },
    useRef(value) { const ref = { current: value }; refs.push(ref); return ref; },
    useCallback(fn) { return fn; },
    useEffect(fn) { effects.push(fn); },
  };
  const api = {
    apiGet(path, params, options) { return new Promise((resolve, reject) => requests.push({ path, options, resolve, reject })); },
    unwrapList: response => response.data,
  };
  const context = createContext({ exports: {}, require: name => name === 'react' ? react : name === 'antd' ? { message: { error: value => errors.push(value) } } : api,
    window, document, performance: { now: () => now }, AbortController });
  runInContext(compile(hookSource), context);
  const hook = context.exports.useDNSProbes(live);
  const cleanups = effects.map(fn => fn());
  return { hook, state, requests, errors, intervals, window, document, setNow: value => { now = value; },
    tick: () => [...intervals.values()].forEach(fn => fn()), cleanup: () => cleanups.forEach(fn => fn?.()), timeouts };
}
const flush = () => new Promise(resolve => setImmediate(resolve));
const probe = (stamp = 1000) => ({ id: 7, enabled: true, last_heartbeat_at: stamp, status_checked_at: stamp + 10 });

test('a page open longer than 90 seconds keeps loading fresh heartbeats', async () => {
  const r = runtime();
  r.requests[0].resolve({ data: [probe()] }); await flush();
  for (let second = 30; second <= 120; second += 30) {
    r.setNow(second * 1000); r.tick();
    const request = r.requests.at(-1);
    assert.equal(request.path, '/dns-failover/probes');
    assert.equal(request.options.cache, 'no-store');
    request.resolve({ data: [probe(1000 + second)] }); await flush();
    assert.equal(dnsProbeOnline(r.state[0][0], r.state[1]), true);
  }
  assert.equal(r.requests.length, 5);
  r.cleanup(); assert.equal(r.intervals.size, 0);
});

test('hidden tabs pause polling, returning refreshes, overlapping quiet requests are skipped', async () => {
  const r = runtime({ hidden: true });
  r.document.visibilityState = 'hidden'; r.tick(); assert.equal(r.requests.length, 0);
  r.document.visibilityState = 'visible'; r.document.dispatchEvent(new Event('visibilitychange'));
  assert.equal(r.requests.length, 1);
  r.tick(); r.window.dispatchEvent(new Event('focus')); assert.equal(r.requests.length, 1);
  r.requests[0].resolve({ data: [probe()] }); await flush();
  r.window.dispatchEvent(new Event('focus')); assert.equal(r.requests.length, 2);
  r.cleanup(); assert.equal(r.requests[1].options.signal.aborted, true);
  r.requests[1].resolve({ data: [] }); await flush();
  assert.equal(r.state[0].length, 1);
  r.window.dispatchEvent(new Event('focus')); assert.equal(r.requests.length, 2);
});

test('manual refresh supersedes older responses; failed polling cannot keep old heartbeats online', async () => {
  const r = runtime({ live: false });
  const older = r.hook.loadProbes(), newer = r.hook.loadProbes();
  assert.equal(r.requests[0].options.signal.aborted, true);
  r.requests[1].resolve({ data: [probe()] }); await newer;
  r.requests[0].resolve({ data: [] }); await older;
  assert.equal(r.state[0].length, 1);
  r.setNow(120000); const failed = r.hook.loadProbes(true);
  r.requests[2].reject(new Error('network failed')); await failed;
  assert.equal(dnsProbeStatus(r.state[0][0], 120000), 'stale');
  assert.equal(r.errors.length, 0);
  const recovered = r.hook.loadProbes(true); assert.equal(r.requests.length, 4);
  r.requests[3].resolve({ data: [probe(1120)] }); await recovered;
  assert.equal(dnsProbeOnline(r.state[0][0], r.state[1]), true);
  r.cleanup();
});

test('unrelated tabs do not poll; manual refresh remains available', async () => {
  const r = runtime({ live: false });
  r.tick(); r.window.dispatchEvent(new Event('focus'));
  assert.equal(r.intervals.size, 0); assert.equal(r.requests.length, 0);
  const manual = r.hook.loadProbes();
  r.requests[0].resolve({ data: [probe()] }); await manual;
  assert.equal(r.state[0].length, 1);
  r.cleanup();
});
