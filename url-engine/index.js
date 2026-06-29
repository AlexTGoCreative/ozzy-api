// === Agatha URL (Hyperlink) native engine binding ===
//
// Loads the Hyperlink URL-classification engine DLL directly into the ozzy-api
// process via koffi FFI, exactly like the file engine in ../engine. The engine
// is initialized once at module load and reused for every URL scan.
//
// The native C API (see agatha-url/src/ffi) is:
//   int sdk_initialize()
//   int sdk_deinitialize()
//   int sdk_scan(const char *input, const char **output)   // {"url":"…"} in, JSON out
//   int freeString(const char **str)
//
// sdk_scan returns a JSON envelope:
//   { "verdict": 0|1|2|-1, "benign_probability": f, "malicious_probability": f, "url": "…" }
//   verdict: 0 = Clean · 1 = Infected · 2 = Suspicious · -1 = FailedToScan
//   probabilities are 0.0–1.0 floats.
//
// Runtime dependencies live beside the DLL in ./package:
//   hyperlinkengine.dll · onnxruntime.dll · model_hyperlink.onnx

const path = require('path');
const fs = require('fs');
const koffi = require('koffi');
const Semaphore = require('../lib/semaphore');

// Loaded once (sdk_initialize below); URL scans then run through koffi's async
// interface, bounded to a small concurrent pool so they never block the event
// loop. The URL model is light, but the same load-once + bounded-threads model
// as the file engine keeps behaviour consistent. Tune with AGATHA_URL_THREADS.
const URL_SCAN_THREADS = Math.max(1, parseInt(process.env.AGATHA_URL_THREADS, 10) || 8);
const scanSemaphore = new Semaphore(URL_SCAN_THREADS);

const PACKAGE_DIR =
  process.env.AGATHA_URL_PACKAGE_DIR ||
  path.join(__dirname, 'package');

const LIB_NAME =
  process.platform === 'win32'
    ? path.join(PACKAGE_DIR, 'hyperlinkengine.dll')
    : path.join(PACKAGE_DIR, 'libhyperlinkengine.so');

// === Hyperlink engine diagnostics log ===
// The rebuilt agatha-url engine honours the HYPERLINK_LOG_DIR env var and appends
// per-scan diagnostics to <HYPERLINK_LOG_DIR>/hyperlink.log, using the SAME
// timestamped line format as the file engine's engine.log. We pin the dir to a
// known path and set the env var BEFORE sdk_initialize runs, since the engine
// reads it once during initialization. Each scan then captures only the slice of
// hyperlink.log appended while it ran (file-delta technique, mirrors ../engine).
const LOG_DIR =
  process.env.HYPERLINK_LOG_DIR ||
  path.join(PACKAGE_DIR, 'hyperlink');
const LOG_FILE = path.join(LOG_DIR, 'hyperlink.log');

process.env.HYPERLINK_LOG_DIR = LOG_DIR;
try { fs.mkdirSync(LOG_DIR, { recursive: true }); } catch (e) { /* ignore */ }

// Current size of hyperlink.log, or 0 if it does not exist yet. Used as the
// cursor before a scan so we can read back only what that scan appended. No-ops
// gracefully (returns 0 / '') if the engine has not created the file yet.
function logSize() {
  try { return fs.statSync(LOG_FILE).size; } catch (e) { return 0; }
}

// Read the bytes appended to hyperlink.log since `startOffset`. Best-effort:
// returns '' when logging is unavailable.
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
// only to that scan, in case the native engine appends to the shared log file
// while another scan is in flight. The semaphore below still bounds queueing.
let scanChain = Promise.resolve();
function runSerial(work) {
  const run = scanChain.then(work, work);
  scanChain = run.then(() => undefined, () => undefined);
  return run;
}

let lib = null;
let sdkInitialize = null;
let sdkDeinitialize = null;
let nativeScan = null;
let engineReady = false;

try {
  // The engine DLL depends on onnxruntime.dll sitting next to it; putting the
  // package dir on PATH lets the Windows loader resolve it.
  if (process.platform === 'win32') {
    process.env.PATH = PACKAGE_DIR + ';' + process.env.PATH;
  }

  lib = koffi.load(LIB_NAME);

  sdkInitialize = lib.func('int sdk_initialize()');
  sdkDeinitialize = lib.func('int sdk_deinitialize()');
  // input JSON in, heap JSON string out via _Out_ char**. koffi decodes the
  // out-pointer straight into a JS string (same pattern as ../engine), so there
  // is no raw pointer to hand back to the native freeString.
  nativeScan = lib.func('int sdk_scan(const char *input, _Out_ const char **output)');

  const initResult = sdkInitialize();
  if (initResult === 0) {
    engineReady = true;
    console.log(`[agatha-url] Engine initialized successfully from: ${PACKAGE_DIR}`);
  } else {
    console.error(`[agatha-url] Engine initialization failed with code: ${initResult}`);
  }
} catch (err) {
  console.error(`[agatha-url] Failed to load native library: ${err.message}`);
  console.error(`[agatha-url] Looked for: ${LIB_NAME}`);
  console.error('[agatha-url] The API will start but URL engine scans will report "engine unavailable".');
}

// Cleanly deinitialize on process exit so the ONNX runtime tears down once.
process.on('exit', () => {
  if (sdkDeinitialize && engineReady) {
    try { sdkDeinitialize(); } catch (e) { /* ignore */ }
  }
});

function isReady() {
  return engineReady;
}

/**
 * Scan a single URL through the Hyperlink engine.
 *
 * @param {string} url  The URL to classify.
 * @returns {{ ok: boolean, verdict: number, benign_probability: number,
 *             malicious_probability: number, url: string, error?: string }}
 *   verdict is the native code: 0 clean · 1 infected · 2 suspicious · -1 failed.
 *   probabilities are 0–100 percentages (converted from the engine's 0–1 floats).
 */
function down(url, error) {
  return { ok: false, verdict: -1, benign_probability: 0, malicious_probability: 0, url, error };
}

// Decode the engine's sdk_scan result. Shared by the sync and async paths.
function mapResult(ret, raw, url) {
  if (ret !== 0 || !raw) return down(url, 'Scan failed');

  let parsed = null;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    return down(url, `Bad engine response: ${err.message}`);
  }

  return {
    ok: parsed.verdict !== -1,
    verdict: typeof parsed.verdict === 'number' ? parsed.verdict : -1,
    benign_probability: Math.round((parsed.benign_probability || 0) * 1000) / 10,
    malicious_probability: Math.round((parsed.malicious_probability || 0) * 1000) / 10,
    url: parsed.url || url,
  };
}

/**
 * Synchronous URL scan — blocks the event loop. Prefer scanAsync() in request
 * handlers.
 */
function scan(url) {
  if (!engineReady || !nativeScan) return { ...down(url, 'Engine not initialized'), logs: '' };

  const input = JSON.stringify({ url });
  const logStart = logSize();
  const outPtr = [null];
  const ret = nativeScan(input, outPtr);
  const result = mapResult(ret, outPtr[0], url);
  result.logs = readLogSince(logStart);
  return result;
}

/**
 * Asynchronous, concurrency-bounded URL scan. Runs on a koffi worker thread and
 * caps in-flight scans at URL_SCAN_THREADS. Same return shape as scan(); never
 * rejects.
 */
async function scanAsync(url) {
  if (!engineReady || !nativeScan) return { ...down(url, 'Engine not initialized'), logs: '' };

  const input = JSON.stringify({ url });
  return scanSemaphore.run(
    () =>
      runSerial(
        () =>
          new Promise((resolve) => {
            const outPtr = [null];
            // Cursor into hyperlink.log just before the scan; the delta read in
            // the callback is the diagnostics this scan produced. runSerial keeps
            // the window exclusive when the engine writes to the shared log file.
            const logStart = logSize();
            nativeScan.async(input, outPtr, (err, ret) => {
              if (err) return resolve({ ...down(url, `Engine call failed: ${err.message}`), logs: readLogSince(logStart) });
              const result = mapResult(ret, outPtr[0], url);
              result.logs = readLogSince(logStart);
              resolve(result);
            });
          })
      )
  );
}

function poolStats() {
  return { threads: URL_SCAN_THREADS, ...scanSemaphore.stats() };
}

module.exports = { isReady, scan, scanAsync, poolStats, PACKAGE_DIR };
