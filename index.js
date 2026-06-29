const express = require('express');
const multer = require('multer');
const cors = require('cors');
const axios = require('axios');
const dotenv = require('dotenv');
const fs = require('fs');
const mongoose = require('mongoose');
const User = require('./models/User');
const ChatHistory = require('./models/ChatHistory');
const ScanHistory = require('./models/ScanHistory');
const auth = require('./middleware/auth');
const { body, validationResult } = require('express-validator');
const jwt = require('jsonwebtoken');

dotenv.config();

const app = express();
const upload = multer({ limits: { fileSize: 2 * 1024 * 1024 * 1024 } }); // 2 GB

const corsOptions = {
  origin: '*', 
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true,
  optionsSuccessStatus: 200
};

app.use(cors(corsOptions));
app.use(express.json());

mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(async () => {
  console.log('MongoDB connected');
  // Drop stale email index from previous schema
  try {
    await mongoose.connection.collection('users').dropIndex('email_1');
    console.log('Dropped stale email_1 index');
  } catch (e) {
    // Index doesn't exist, ignore
  }
})
.catch(err => console.error('MongoDB connection error:', err));

const MD_API_KEY = process.env.METADEFENDER_API_KEY;
const JWT_SECRET = process.env.JWT_SECRET;

if (!MD_API_KEY) {
  throw new Error('Missing METADEFENDER_API_KEY in environment');
}
if (!JWT_SECRET) {
  throw new Error('Missing JWT_SECRET in environment');
}

app.post('/auth/register', [
  body('username').isLength({ min: 3 }).trim().escape(),
  body('password').isLength({ min: 6 })
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { username, password } = req.body;
    
    const existingUser = await User.findOne({ username });
    if (existingUser) {
      return res.status(400).json({ message: 'Username already exists' });
    }

    const user = new User({ username, password });
    await user.save();

    const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: '7d' });
    res.json({
      token,
      user: { id: user._id, username: user.username }
    });
  } catch (err) {
    console.error('Register error:', err);
    res.status(500).json({ message: err.message });
  }
});

app.post('/auth/login', [
  body('username').isLength({ min: 3 }).trim().escape(),
  body('password').isLength({ min: 6 })
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { username, password } = req.body;
    
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(400).json({ message: 'User does not exist' });
    }

    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: '7d' });
    res.json({
      token,
      user: { id: user._id, username: user.username }
    });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.get('/chat-history', auth, async (req, res) => {
  try {
    const histories = await ChatHistory.find({ userId: req.user.id })
      .sort({ lastUpdated: -1 });
    res.json(histories);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.post('/chat-history', auth, async (req, res) => {
  try {
    const { messages, scanData, /* sandboxData, */ urlData, agathaData } = req.body; // Sandbox disabled
    const chatHistory = new ChatHistory({
      userId: req.user.id,
      messages,
      scanData,
      // sandboxData, // Sandbox disabled
      urlData,
      agathaData
    });
    await chatHistory.save();
    res.json(chatHistory);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// === Update Chat ===

app.put('/chat-history/:chatId', auth, async (req, res) => {
  try {
    const { chatId } = req.params;
    const { messages, scanData, /* sandboxData, */ urlData, agathaData } = req.body; // Sandbox disabled

    const chatHistory = await ChatHistory.findOne({ _id: chatId, userId: req.user.id });
    if (!chatHistory) {
      return res.status(404).json({ message: 'Chat history not found or unauthorized' });
    }

    const updatedChat = await ChatHistory.findByIdAndUpdate(
      chatId,
      {
        messages,
        scanData,
        // sandboxData, // Sandbox disabled
        urlData,
        agathaData,
        lastUpdated: new Date()
      },
      { new: true }
    );

    res.json(updatedChat);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.delete('/chat-history', auth, async (req, res) => {
  try {
    await ChatHistory.deleteMany({ userId: req.user.id });
    res.json({ message: 'Chat history cleared' });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// === File Scan ===
app.post('/scan-file', auth, upload.single('file'), async (req, res) => {
  try {
    const file = req.file;

    if (!file) {
      return res.status(400).json({ message: 'No file uploaded' });
    }

    const response = await axios.post(
      'https://api.metadefender.com/v4/file',
      file.buffer,
      {
        headers: {
          'apikey': MD_API_KEY,
          'Content-Type': 'application/octet-stream',
          'filename': file.originalname
        }
      }
    );

    const hash = response.data?.data_id;
    res.json({ message: 'File scan initiated', hash });
  } catch (error) {
    console.error(error.response?.data || error.message);
    res.status(500).json({ error: error.message });
  }
});

// === Direct URL Scan ===
app.get('/scan-url-direct', auth, async (req, res) => {
    try {
      const { encodedUrl } = req.query;
      if (!encodedUrl) {
        return res.status(400).json({ error: 'Missing encodedUrl' });
      }

      const encodedForAPI = encodeURIComponent(encodedUrl);
  
      const response = await axios.get(
        `https://api.metadefender.com/v4/url/${encodedForAPI}`,
        {
          headers: {
            'apikey': MD_API_KEY,
          },
        }
      );
  
      res.json(response.data);
    } catch (error) {
      console.error("Eroare scan-url-direct:", error.response?.data || error.message);
      res.status(error.response?.status || 500).json({ error: error.message });
    }
});

// === Agatha URL Engine Scan (in-process, native FFI) ===
// Classifies a single URL with the Hyperlink ONNX engine. Returns the same
// verdict shape the frontend's ScanResults uses for the file Agatha engine so
// the two can be compared side by side:
//   0 = clean · 1 = malicious · 2 = suspicious · -1 = unavailable
app.get('/agatha-url-scan', auth, async (req, res) => {
  // `mode` is accepted for parity with the file scan but the URL engine is
  // mode-agnostic for now; we just don't choke on it.
  const { url } = req.query;
  if (!url) {
    return res.status(400).json({ error: 'Missing url' });
  }

  try {
    const result = await agathaUrlEngine.scanAsync(url);

    if (!result.ok) {
      return res.status(200).json({
        engine: 'Agatha URL',
        verdict: -1,
        threat_name: '',
        malicious_probability: 0,
        benign_probability: 0,
        url,
        error: result.error || 'Engine unavailable',
        scan_time: new Date().toISOString(),
        engine_logs: result.logs || '',
      });
    }

    const mal = result.malicious_probability;
    res.json({
      engine: 'Agatha URL',
      verdict: result.verdict,
      threat_name: result.verdict === 1 ? `Hyperlink/malicious_${Math.round(mal)}` : '',
      malicious_probability: mal,
      benign_probability: result.benign_probability,
      url: result.url,
      scan_time: new Date().toISOString(),
      // Per-scan engine diagnostics (matches /agatha-scan's engine_logs shape).
      engine_logs: result.logs || '',
    });
  } catch (error) {
    console.error('Agatha URL scan error:', error.message);
    res.status(200).json({
      engine: 'Agatha URL',
      verdict: -1,
      threat_name: '',
      malicious_probability: 0,
      benign_probability: 0,
      url,
      error: 'Engine unavailable',
      scan_time: new Date().toISOString(),
      engine_logs: '',
    });
  }
});

// === Get Sandbox === (disabled — only multiscanning + Agatha are active)
// app.get('/sandbox/:sha1', auth, async (req, res) => {
//   const { sha1 } = req.params;
//
//   try {
//     const response = await axios.get(`https://api.metadefender.com/v4/hash/${sha1}/sandbox`, {
//       headers: {
//         apikey: MD_API_KEY,
//       },
//     });
//
//     res.json(response.data);
//   } catch (error) {
//     console.error('Error fetching sandbox data:', error.message);
//     res.status(500).json({ error: 'Failed to fetch sandbox data from Metadefender.' });
//   }
// });
  
// === Scan Status ===
app.get('/scan/:hash', auth, async (req, res) => {
  try {
    const { hash } = req.params;
    const response = await axios.get(
      `https://api.metadefender.com/v4/file/${hash}`,
      { headers: { apikey: MD_API_KEY } }
    );

    res.json(response.data);
  } catch (error) {
    console.error(error.response?.data || error.message);
    res.status(error.response?.status || 500).json({ error: error.message });
  }
});

// === Scan History ===
app.get('/scan-history', auth, async (req, res) => {
  try {
    const scanHistory = await ScanHistory.find({ userId: req.user.id }).sort({ timestamp: -1 });
    res.json(scanHistory);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.post('/scan-history', auth, async (req, res) => {
  try {
    const scanHistory = new ScanHistory({
      ...req.body,
      userId: req.user.id
    });
    await scanHistory.save();
    res.json(scanHistory);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.delete('/scan-history', auth, async (req, res) => {
  try {
    await ScanHistory.deleteMany({ userId: req.user.id });
    res.json({ message: 'Scan history cleared' });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// === Agatha Engine (in-process, native FFI) ===
// The native engine DLL is loaded directly into this process via koffi (see
// ./engine), so there is no separate Node host on :3002. Scans go through the
// engine's UIF `process` interface, which honours the per-file-type preferences
// (layer toggles + thresholds) the user configures in the Settings panel.
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const agathaEngine = require('./engine');
// Agatha URL (Hyperlink) engine — same in-process FFI pattern as the file
// engine above, but classifies URLs instead of files.
const agathaUrlEngine = require('./url-engine');

// Map the engine's string verdict to the numeric verdict + probability pair the
// frontend's ScanResults component expects.
//   0 = clean · 1 = malicious · 2 = unknown · 3 = unsupported · -1 = unavailable
function mapEngineResult(result) {
  if (!result.ok) {
    return { verdict: -1, threat_name: '', malicious_probability: 0, benign_probability: 0, error: result.error || 'Engine unavailable' };
  }
  const conf = Math.max(0, Math.min(100, result.confidence));
  switch (result.verdict) {
    case 'malicious':
      return {
        verdict: 1,
        threat_name: `${result.fileType || 'Agatha'}/malicious_${Math.round(conf)}`,
        malicious_probability: conf,
        benign_probability: 100 - conf,
      };
    case 'clean':
      return { verdict: 0, threat_name: '', malicious_probability: 100 - conf, benign_probability: conf };
    case 'unknown':
      return { verdict: 2, threat_name: '', malicious_probability: conf, benign_probability: 100 - conf };
    case 'unsupported':
      return { verdict: 3, threat_name: '', malicious_probability: 0, benign_probability: 0 };
    default:
      return { verdict: -1, threat_name: '', malicious_probability: 0, benign_probability: 0, error: 'Unrecognized verdict' };
  }
}

app.post('/agatha-scan', auth, upload.single('file'), async (req, res) => {
  try {
    const file = req.file;
    if (!file) {
      return res.status(400).json({ message: 'No file uploaded' });
    }

    // Per-file-type preferences chosen in the Settings panel. Sent as a JSON
    // string form field; absent/invalid means "use the engine profile defaults".
    let preferences = null;
    if (req.body?.preferences) {
      try {
        const parsed = JSON.parse(req.body.preferences);
        if (parsed && typeof parsed === 'object') preferences = parsed;
      } catch (e) {
        console.warn('[agatha] Ignoring malformed preferences payload:', e.message);
      }
    }

    // The engine scans a path on disk, so stage the upload in the OS temp dir.
    // Include a random suffix so concurrent scans (up to 8 in flight) can't
    // collide on the same temp filename within the same millisecond.
    const unique = `${Date.now()}_${crypto.randomBytes(6).toString('hex')}`;
    const tempPath = path.join(os.tmpdir(), `agatha_${unique}_${file.originalname}`);
    fs.writeFileSync(tempPath, file.buffer);

    // Scan mode: 'detection' (default, low-FP) or 'deflection' (low-FN). Sent as
    // a multipart form field. The engine falls back to detection if the
    // deflection binary is not loaded; result.mode reflects what actually ran.
    const mode = req.body?.mode === 'deflection' ? 'deflection' : 'detection';

    try {
      const result = await agathaEngine.scanAsync(tempPath, preferences, mode);
      res.json({
        engine: 'Agatha',
        ...mapEngineResult(result),
        mode: result.mode || mode,
        file_type: result.fileType || undefined,
        scan_time: new Date().toISOString(),
        // Raw engine diagnostics for this scan (feature vector, scan layers,
        // inference verdict, scored deepscan URLs). Surfaced in the UI "Logs" panel.
        engine_logs: result.logs || '',
      });
    } finally {
      try { fs.unlinkSync(tempPath); } catch (e) { /* ignore */ }
    }
  } catch (error) {
    console.error('Agatha scan error:', error.message);
    // Return a graceful error so it doesn't break the main scan flow
    res.status(200).json({
      engine: 'Agatha',
      verdict: -1,
      threat_name: '',
      malicious_probability: 0,
      benign_probability: 0,
      error: 'Engine unavailable',
      scan_time: new Date().toISOString(),
      engine_logs: ''
    });
  }
});

// === Agatha Engine Workflow Schema ===
// Returns the per-rule settings schema the engine exposes (one feature group per
// file-type family). The Settings panel renders its controls directly from this,
// so the UI always matches what the engine actually supports.
app.get('/agatha-workflow-info', auth, async (req, res) => {
  // The threshold defaults are mode-specific (detection vs deflection profiles),
  // so the UI passes ?mode= and we return that mode's schema. Unknown/absent mode
  // falls back to detection. If the deflection engine is unavailable the engine
  // layer transparently falls back to the detection schema.
  const mode = req.query.mode === 'deflection' ? 'deflection' : 'detection';
  const info = agathaEngine.getWorkflowInfo(mode);
  if (!info) {
    return res.status(200).json({ available: false, mode });
  }
  res.json({ available: true, mode, ...info });
});

// === Agatha Engine Config Info ===
app.get('/agatha-config', auth, async (req, res) => {
  const deflectionAvailable =
    typeof agathaEngine.deflectionAvailable === 'function'
      ? agathaEngine.deflectionAvailable()
      : false;
  res.json({
    available: agathaEngine.isReady(),
    // Backward-compatible: keep `mode` as the default mode; add the dual-mode
    // fields the mode-aware frontend reads.
    mode: 'detection',
    modes: ['detection', 'deflection'],
    deflection_available: deflectionAvailable,
    verdicts: ['Clean', 'Infected', 'Unknown', 'Unsupported'],
    supported_file_types: ['PE', 'ELF', 'Mach-O', 'PDF', 'OOXML', 'Image'],
  });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
