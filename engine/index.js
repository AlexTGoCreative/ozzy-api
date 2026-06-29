// === Agatha / Anderton native engine binding ===
//
// Loads the native engine DLL directly into the ozzy-api process via koffi FFI,
// so there is no separate Node/Express host on :3002 anymore. The engine is
// initialized once at module load and reused for every scan.
//
// Two native interfaces are used:
//   - getWorkflowInfo() — returns the per-rule settings schema the engine
//     exposes (one feature group per file-type family). The Settings UI renders
//     directly from this, so the controls always match what the engine supports
//     (e.g. the reputation toggle only appears when the engine was built with
//     the reputation_engine feature).
//   - process()         — the scan entry point. It accepts a `preferences`
//     block with the per-file-type layer toggles + thresholds and returns a
//     verdict. This is the only interface that honours the per-file-type config,
//     which is why we use it instead of the older flat sdk_scan().

const path = require('path');
const fs = require('fs');
const koffi = require('koffi');
const Semaphore = require('../lib/semaphore');

// The engine DLL + ONNX model is loaded exactly once (sdk_initialize below).
// Scans are then dispatched through koffi's asynchronous interface so they run
// on koffi worker threads instead of blocking the Node event loop. A counting
// semaphore caps how many scans run at once (default 8) — "load once, serve
// with a bounded pool of threads". Tune with AGATHA_SCAN_THREADS.
const SCAN_THREADS = Math.max(1, parseInt(process.env.AGATHA_SCAN_THREADS, 10) || 8);
const scanSemaphore = new Semaphore(SCAN_THREADS);

const PACKAGE_DIR =
  process.env.AGATHA_PACKAGE_DIR ||
  process.env.PACKAGE_DIR ||
  path.join(__dirname, 'package');

// Dual file-engine binaries live in the SAME package dir:
//   - Detection (default, mandatory): agatha.dll / libagatha.so
//   - Deflection (optional):           agatha-deflection.dll / libagatha-deflection.so
// Detection is required; if the deflection binary is absent we log a warning and
// fall back to the detection engine so the app still runs.
const DETECTION_LIB_NAME =
  process.platform === 'win32'
    ? path.join(PACKAGE_DIR, 'agatha.dll')
    : path.join(PACKAGE_DIR, 'libagatha.so');

const DEFLECTION_LIB_NAME =
  process.platform === 'win32'
    ? path.join(PACKAGE_DIR, 'agatha-deflection.dll')
    : path.join(PACKAGE_DIR, 'libagatha-deflection.so');

// === Engine diagnostics log ===
// The engine (built with the extractor_diagnostics + hyperlink_sdk features)
// writes a structured diagnostics log — feature-extraction timings, the ML
// feature vector, the effective scan layers, the inference verdict, and the
// scored deepscan URLs (PDF/OOXML hyperlinks) — to <AGATHA_LOG_DIR>/engine.log.
//
// We pin AGATHA_LOG_DIR to a known path and force the level to `debug` (the
// feature vector / extractor lines are emitted at debug) *before* sdk_initialize
// runs, since the engine reads both env vars once during its reinitialize().
// Each scan then captures only the slice of engine.log appended while it ran, so
// the UI can show the diagnostics for exactly that file.
const LOG_DIR =
  process.env.AGATHA_LOG_DIR ||
  path.join(PACKAGE_DIR, 'agatha');
const LOG_FILE = path.join(LOG_DIR, 'engine.log');

process.env.AGATHA_LOG_DIR = LOG_DIR;
// Honour an explicit level override, else default to debug for full diagnostics.
if (!process.env.AGATHA_LOG_LEVEL) {
  process.env.AGATHA_LOG_LEVEL = 'debug';
}
// Dump the full named ML feature vector (every feature=value) per scan. The
// engine gates this behind this env var because the vector is large; we opt in
// by default so the UI Logs panel shows it. Set AGATHA_LOG_FEATURE_VECTOR=0
// to suppress it.
if (process.env.AGATHA_LOG_FEATURE_VECTOR !== '0') {
  process.env.AGATHA_LOG_FEATURE_VECTOR = '1';
}
try { fs.mkdirSync(LOG_DIR, { recursive: true }); } catch (e) { /* ignore */ }

// Current size of engine.log, or 0 if it does not exist yet. Used as the cursor
// before a scan so we can read back only what that scan appended.
function logSize() {
  try { return fs.statSync(LOG_FILE).size; } catch (e) { return 0; }
}

// Read the bytes appended to engine.log since `startOffset`. Best-effort: returns
// '' when logging is unavailable. NOTE: the native engine serialises scans
// internally (one full pipeline at a time), so under the UI's typical
// one-scan-at-a-time use the delta maps cleanly to a single scan; truly
// concurrent API scans may interleave lines.
function readLogSince(startOffset) {
  try {
    const end = fs.statSync(LOG_FILE).size;
    if (end <= startOffset) return '';
    const fd = fs.openSync(LOG_FILE, 'r');
    try {
      const len = end - startOffset;
      const buf = Buffer.alloc(len);
      fs.readSync(fd, buf, 0, len, startOffset);
      return buf.toString('utf8');
    } finally {
      fs.closeSync(fd);
    }
  } catch (e) {
    return '';
  }
}

// Serialise the offset→scan→delta window so each scan's log slice is attributed
// only to that scan. The native engine already runs one full pipeline at a time
// (its internal SCAN_GUARD mutex), so this adds no real throughput cost — it just
// stops a second scan from snapshotting its start-offset while the first scan is
// still appending. The semaphore below still bounds how many calls queue here.
let scanChain = Promise.resolve();
function runSerial(work) {
  const run = scanChain.then(work, work);
  // Keep the chain alive across both fulfilment and rejection.
  scanChain = run.then(() => undefined, () => undefined);
  return run;
}

// Each binary is loaded as its own independent koffi instance with its own
// initialize/process/getWorkflowInfo/deinitialize handles. `detection` is the
// mandatory default; `deflection` is optional (may be null when its binary is
// absent on this host).
//   { lib, sdkInitialize, sdkDeinitialize, nativeProcess, nativeGetWorkflowInfo,
//     ready }
let detection = null;
let deflection = null;

// Cached schema — getWorkflowInfo is pure (reads no engine state) so we fetch it
// once per mode and reuse it for every Settings request. The threshold
// default_values differ per mode because each engine binary compiles its own
// scan profile (detection thresholds vs deflection = 95), so we cache per mode.
const cachedWorkflowInfo = { detection: null, deflection: null };

// Load one engine binary and run its sdk_initialize(). Returns a handle object,
// or null if the library could not be loaded / initialized. `mandatory` only
// affects the wording of the log lines.
function loadEngine(libName, label, mandatory) {
  try {
    const lib = koffi.load(libName);
    const handle = {
      lib,
      sdkInitialize: lib.func('int sdk_initialize()'),
      sdkDeinitialize: lib.func('int sdk_deinitialize()'),
      // Both take a JSON string in and write a heap JSON string out via _Out_ char**.
      nativeProcess: lib.func('int process(const char *task, _Out_ const char **result)'),
      nativeGetWorkflowInfo: lib.func('int getWorkflowInfo(_Out_ const char **output)'),
      ready: false,
    };

    const initResult = handle.sdkInitialize();
    if (initResult === 0) {
      handle.ready = true;
      console.log(`[agatha] ${label} engine initialized successfully from: ${libName}`);
    } else {
      console.error(`[agatha] ${label} engine initialization failed with code: ${initResult}`);
    }
    return handle;
  } catch (err) {
    const level = mandatory ? 'error' : 'warn';
    console[level](`[agatha] Failed to load ${label} native library: ${err.message}`);
    console[level](`[agatha] Looked for: ${libName}`);
    if (mandatory) {
      console.error('[agatha] The API will start but Agatha scans will report "engine unavailable".');
    }
    return null;
  }
}

// The engine DLLs have sibling dependencies (onnxruntime, reputation-engine);
// putting the package dir on PATH lets the loader resolve them on Windows.
if (process.platform === 'win32') {
  process.env.PATH = PACKAGE_DIR + ';' + process.env.PATH;
}

detection = loadEngine(DETECTION_LIB_NAME, 'Detection', true);

// Deflection is OPTIONAL: only attempt to load it if its binary exists, so a
// missing file produces a clean warning rather than a noisy load error.
if (fs.existsSync(DEFLECTION_LIB_NAME)) {
  deflection = loadEngine(DEFLECTION_LIB_NAME, 'Deflection', false);
}
if (!deflection || !deflection.ready) {
  deflection = null;
  console.warn(`[agatha] Deflection engine unavailable (looked for ${DEFLECTION_LIB_NAME}); falling back to detection for mode='deflection'.`);
}

// Whether the optional deflection engine loaded and initialized.
function deflectionAvailable() {
  return !!(deflection && deflection.ready);
}

// Cleanly deinitialize on process exit so the ONNX runtime tears down once
// per loaded engine.
process.on('exit', () => {
  for (const handle of [detection, deflection]) {
    if (handle && handle.ready && handle.sdkDeinitialize) {
      try { handle.sdkDeinitialize(); } catch (e) { /* ignore */ }
    }
  }
});

function isReady() {
  return !!(detection && detection.ready);
}

/**
 * Returns the engine's workflow schema + default values, exactly as the engine
 * exposes them. Shape:
 *   { version, schema: { version, schema: [ feature groups ] }, default_values }
 * Returns null when the engine is unavailable.
 *
 * The threshold `default_value`s are read from the ACTIVE compiled scan profile,
 * which differs per binary, so the schema is mode-specific. When
 * mode==='deflection' and the deflection engine loaded we read from it (e.g.
 * thresholds of 95); otherwise we fall back to the detection engine's schema.
 * Cached per resolved mode.
 *
 * @param {'detection'|'deflection'} mode
 */
function getWorkflowInfo(mode = 'detection') {
  // Resolve which binary actually answers, applying the deflection fallback.
  const useDeflection = mode === 'deflection' && deflectionAvailable();
  const handle = useDeflection ? deflection : detection;
  const resolvedMode = useDeflection ? 'deflection' : 'detection';

  if (!handle || !handle.ready || !handle.nativeGetWorkflowInfo) return null;
  if (cachedWorkflowInfo[resolvedMode]) return cachedWorkflowInfo[resolvedMode];

  const outPtr = [null];
  const ret = handle.nativeGetWorkflowInfo(outPtr);
  if (ret !== 0 || !outPtr[0]) {
    console.error(`[agatha] getWorkflowInfo (${resolvedMode}) failed with code:`, ret);
    return null;
  }
  try {
    cachedWorkflowInfo[resolvedMode] = JSON.parse(outPtr[0]);
    return cachedWorkflowInfo[resolvedMode];
  } catch (err) {
    console.error(`[agatha] getWorkflowInfo (${resolvedMode}) parse error:`, err.message);
    return null;
  }
}

/**
 * Scan a file through the UIF process endpoint with optional per-file-type
 * preferences.
 *
 * @param {string} filePath          Absolute path to the file to scan.
 * @param {object|null} preferences  Flat dotted-key map (e.g. { "pe": true,
 *                                    "pe.ml_enabled": true, "pe.threshold": 80,
 *                                    "image.deepscan_enabled": false }). Omit /
 *                                    null to use the engine's profile defaults.
 * @returns {{ ok: boolean, verdict: string|null, confidence: number,
 *             fileType: string, sha256: string, error?: string }}
 *   verdict is one of 'clean' | 'malicious' | 'unknown' | 'unsupported'.
 *   confidence is a 0–100 integer: malicious-confidence for malicious/unknown,
 *   benign-confidence for clean.
 */
const ENGINE_DOWN = { ok: false, verdict: null, confidence: 0, fileType: '', sha256: '', error: 'Engine not initialized' };

function buildTask(filePath, preferences) {
  const taskInput = { input_file_path: filePath };
  if (preferences && typeof preferences === 'object' && Object.keys(preferences).length > 0) {
    taskInput.preferences = preferences;
  }
  return JSON.stringify({ task_input: taskInput });
}

// Decode the engine's process() result. `ret` is the native return code, `raw`
// is the JSON string written to the _Out_ pointer. Shared by the sync and async
// paths so they stay in lockstep.
function mapResult(ret, raw) {
  let parsed = null;
  try {
    parsed = raw ? JSON.parse(raw) : null;
  } catch (err) {
    return { ok: false, verdict: null, confidence: 0, fileType: '', sha256: '', error: `Bad engine response: ${err.message}` };
  }

  // Error path: process() returns non-zero and an error envelope.
  if (ret !== 0 || !parsed || parsed.err_code !== undefined || !parsed.final_verdict) {
    const detail = parsed && parsed.err_details ? parsed.err_details : 'Scan failed';
    return { ok: false, verdict: null, confidence: 0, fileType: '', sha256: '', error: detail };
  }

  const fv = parsed.final_verdict;
  return {
    ok: true,
    verdict: fv.verdict || null,
    confidence: typeof fv.confidence === 'number' ? fv.confidence : 0,
    fileType: fv.detail?.file_type || '',
    sha256: fv.detail?.sha256 || '',
  };
}

/**
 * Synchronous scan — blocks the event loop for the duration of the scan. Kept
 * for callers that need a blocking result; prefer scanAsync() in request
 * handlers so the server can serve multiple scans concurrently.
 */
// Resolve the requested scan mode to a concrete engine handle. mode==='deflection'
// uses the deflection engine when it loaded, otherwise falls back to detection.
// Returns { handle, mode } where `mode` is the mode actually used (post-fallback).
function resolveEngine(mode) {
  if (mode === 'deflection' && deflectionAvailable()) {
    return { handle: deflection, mode: 'deflection' };
  }
  return { handle: detection, mode: 'detection' };
}

function scan(filePath, preferences = null, mode = 'detection') {
  const { handle, mode: usedMode } = resolveEngine(mode);
  if (!handle || !handle.ready || !handle.nativeProcess) return { ...ENGINE_DOWN, mode: usedMode, logs: '' };

  const task = buildTask(filePath, preferences);
  const logStart = logSize();
  const outPtr = [null];
  const ret = handle.nativeProcess(task, outPtr);
  const result = mapResult(ret, outPtr[0]);
  result.mode = usedMode;
  result.logs = readLogSince(logStart);
  return result;
}

/**
 * Asynchronous, concurrency-bounded scan. The native process() call runs on a
 * koffi worker thread (the event loop stays free), and at most SCAN_THREADS
 * scans run at once — additional scans queue on the semaphore. Same return
 * shape as scan(). Never rejects: native failures resolve to an error object.
 */
async function scanAsync(filePath, preferences = null, mode = 'detection') {
  const { handle, mode: usedMode } = resolveEngine(mode);
  if (!handle || !handle.ready || !handle.nativeProcess) return { ...ENGINE_DOWN, mode: usedMode, logs: '' };

  const task = buildTask(filePath, preferences);
  return scanSemaphore.run(
    () =>
      runSerial(
        () =>
          new Promise((resolve) => {
            const outPtr = [null];
            // Cursor into engine.log taken just before the scan; the delta read
            // in the callback is the diagnostics this scan produced. runSerial
            // guarantees no other scan is logging within this window. Both
            // binaries share the same AGATHA_LOG_DIR/engine.log, so the serial
            // guard keeps the per-scan delta correct regardless of which ran.
            const logStart = logSize();
            // koffi decodes _Out_ params before invoking the callback, so
            // outPtr[0] holds the engine's JSON string by the time we read it.
            handle.nativeProcess.async(task, outPtr, (err, ret) => {
              if (err) {
                return resolve({ ok: false, verdict: null, confidence: 0, fileType: '', sha256: '', error: `Engine call failed: ${err.message}`, mode: usedMode, logs: readLogSince(logStart) });
              }
              const result = mapResult(ret, outPtr[0]);
              result.mode = usedMode;
              result.logs = readLogSince(logStart);
              resolve(result);
            });
          })
      )
  );
}

// Current scan-pool occupancy, for health/diagnostics endpoints.
function poolStats() {
  return { threads: SCAN_THREADS, ...scanSemaphore.stats() };
}

module.exports = { isReady, deflectionAvailable, getWorkflowInfo, scan, scanAsync, poolStats, PACKAGE_DIR };
