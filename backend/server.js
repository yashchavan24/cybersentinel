import 'dotenv/config';
import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import { authRouter } from './auth.js';
import { apiRouter } from './routes.js';
import { initDB } from './db.js';

const app = express();
app.disable('x-powered-by');
app.set('trust proxy', 1);
app.use(helmet());
app.use(cors({ origin: (process.env.CORS_ORIGIN || 'http://localhost:5173').split(',') }));
app.use(express.json({ limit: '1mb' }));
app.use('/api', rateLimit({ windowMs: 15 * 60e3, limit: 500, standardHeaders: true, legacyHeaders: false, message: { error: 'Rate limit exceeded' } }));

app.get('/api/health', (req, res) => res.json({ status: 'operational', engine: 'CyberSentinel v1', time: new Date().toISOString() }));
app.use('/api/auth', authRouter);
app.use('/api', apiRouter);
app.use('/api', (req, res) => res.status(404).json({ error: 'Not found' }));
app.use((err, req, res, next) => { console.error(err); res.status(500).json({ error: 'Internal server error' }); });

const PORT = process.env.PORT || 5000;
(async () => {
  try {
    await initDB();
    app.listen(PORT, () => console.log(`🛡  CyberSentinel API on http://localhost:${PORT}`));
  } catch (err) {
    console.error('❌ Failed to start:', err);
    process.exit(1);
  }
})();