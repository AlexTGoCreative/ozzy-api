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
//   - process()         — the UIF scan entry point. It accepts a `preferences`
//     block with the per-file-type layer toggles + thresholds and returns a
//     verdict. This is the only interface that honours the per-file-type config,
//     which is why we use it instead of the older flat sdk_scan().

const path = require('path');
const koffi = require('koffi');

const PACKAGE_DIR =
  process.env.AGATHA_PACKAGE_DIR ||
  process.env.PACKAGE_DIR ||
  path.join(__dirname, 'package');

const LIB_NAME =
  process.platform === 'win32'
    ? path.join(PACKAGE_DIR, 'andertonengine.dll')
    : path.join(PACKAGE_DIR, 'libandertonengine.so');

let lib = null;
let sdkInitialize = null;
let sdkDeinitialize = null;
let nativeProcess = null;
let nativeGetWorkflowInfo = null;
let engineReady = false;

// Cached schema — getWorkflowInfo is pure (reads no engine state) so we fetch it
// once and reuse it for every Settings request.
let cachedWorkflowInfo = null;

try {
  // The engine DLL has sibling dependencies (onnxruntime, reputation-engine);
  // putting the package dir on PATH lets the loader resolve them on Windows.
  if (process.platform === 'win32') {
    process.env.PATH = PACKAGE_DIR + ';' + process.env.PATH;
  }

  lib = koffi.load(LIB_NAME);

  sdkInitialize = lib.func('int sdk_initialize()');
  sdkDeinitialize = lib.func('int sdk_deinitialize()');
  // Both take a JSON string in and write a heap JSON string out via _Out_ char**.
  nativeProcess = lib.func('int process(const char *task, _Out_ const char **result)');
  nativeGetWorkflowInfo = lib.func('int getWorkflowInfo(_Out_ const char **output)');

  const initResult = sdkInitialize();
  if (initResult === 0) {
    engineReady = true;
    console.log(`[agatha] Engine initialized successfully from: ${PACKAGE_DIR}`);
  } else {
    console.error(`[agatha] Engine initialization failed with code: ${initResult}`);
  }
} catch (err) {
  console.error(`[agatha] Failed to load native library: ${err.message}`);
  console.error(`[agatha] Looked for: ${LIB_NAME}`);
  console.error('[agatha] The API will start but Agatha scans will report "engine unavailable".');
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
 * Returns the engine's workflow schema + default values, exactly as the engine
 * exposes them. Shape:
 *   { version, schema: { version, schema: [ feature groups ] }, default_values }
 * Returns null when the engine is unavailable.
 */
function getWorkflowInfo() {
  if (!engineReady || !nativeGetWorkflowInfo) return null;
  if (cachedWorkflowInfo) return cachedWorkflowInfo;

  const outPtr = [null];
  const ret = nativeGetWorkflowInfo(outPtr);
  if (ret !== 0 || !outPtr[0]) {
    console.error('[agatha] getWorkflowInfo failed with code:', ret);
    return null;
  }
  try {
    cachedWorkflowInfo = JSON.parse(outPtr[0]);
    return cachedWorkflowInfo;
  } catch (err) {
    console.error('[agatha] getWorkflowInfo parse error:', err.message);
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
function scan(filePath, preferences = null) {
  if (!engineReady || !nativeProcess) {
    return { ok: false, verdict: null, confidence: 0, fileType: '', sha256: '', error: 'Engine not initialized' };
  }

  const taskInput = { input_file_path: filePath };
  if (preferences && typeof preferences === 'object' && Object.keys(preferences).length > 0) {
    taskInput.preferences = preferences;
  }
  const task = JSON.stringify({ task_input: taskInput });

  const outPtr = [null];
  const ret = nativeProcess(task, outPtr);

  let parsed = null;
  try {
    parsed = outPtr[0] ? JSON.parse(outPtr[0]) : null;
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

module.exports = { isReady, getWorkflowInfo, scan, PACKAGE_DIR };
