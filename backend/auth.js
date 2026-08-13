import 'dotenv/config';
import { Router } from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import rateLimit from 'express-rate-limit';
import { z } from 'zod';
import { db } from './db.js';

const JWT_SECRET = process.env.JWT_SECRET || 'dev-insecure-secret';
if (!process.env.JWT_SECRET) console.warn('⚠  Using insecure dev JWT_SECRET');

export function auth(req, res, next) {
  const h = req.headers.authorization || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Authentication required' });
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch (e) { console.error('JWT error:', e.message); res.status(401).json({ error: 'Invalid or expired token' }); }
}

export function audit(req, action, detail = '') {
  try {
    const userId = req.user?.id ?? null;
    const username = req.user?.username ?? 'anonymous';
    const ip = req.ip || req.socket?.remoteAddress || 'unknown';
    db.prepare('INSERT INTO audit_logs (user_id,username,action,detail,ip,created_at) VALUES (?,?,?,?,?,?)')
      .run(userId, username, action, String(detail || '').slice(0, 500), ip, new Date().toISOString());
  } catch (e) { console.error('Audit write failed:', e.message); }
}

export const authRouter = Router();
const loginLimiter = rateLimit({ windowMs: 15 * 60e3, limit: 10, standardHeaders: true, legacyHeaders: false, message: { error: 'Too many login attempts' } });
const regLimiter = rateLimit({ windowMs: 60 * 60e3, limit: 5, standardHeaders: true, legacyHeaders: false, message: { error: 'Registration rate limit' } });

const regSchema = z.object({
  username: z.string().trim().min(3).max(32).regex(/^[a-zA-Z0-9_.-]+$/, 'Letters, numbers, _ . - only'),
  email: z.string().trim().email(),
  password: z.string().min(8).max(100).refine(p => /[A-Z]/.test(p) && /[a-z]/.test(p) && /\d/.test(p), 'Needs upper, lower and number')
});
const loginSchema = z.object({ username: z.string().trim().min(3).max(64), password: z.string().min(1).max(100) });

authRouter.post('/register', regLimiter, (req, res) => {
  try {
    const b = regSchema.safeParse(req.body);
    if (!b.success) return res.status(400).json({ error: b.error.errors[0].message });
    const { username, email, password } = b.data;

    const existing = db.prepare('SELECT id FROM users WHERE username=? OR email=?').get(username, email);
    if (existing) return res.status(409).json({ error: 'Username or email already taken' });

    const hash = bcrypt.hashSync(password, 12);
    const now = new Date().toISOString();
    const info = db.prepare('INSERT INTO users (username,email,password_hash,role,created_at) VALUES (?,?,?,?,?)')
      .run(username, email, hash, 'analyst', now);

    const newUser = { id: info.lastInsertRowid, username, role: 'analyst' };
    audit({ user: newUser, ip: req.ip }, 'REGISTER', username);

    const token = jwt.sign({ id: newUser.id, username, role: 'analyst' }, JWT_SECRET, { expiresIn: process.env.JWT_EXPIRES_IN || '8h' });
    res.json({ token, user: { id: newUser.id, username, email, role: 'analyst' } });
  } catch (e) {
    console.error('Register error:', e);
    res.status(500).json({ error: 'Registration failed: ' + e.message });
  }
});

authRouter.post('/login', loginLimiter, (req, res) => {
  try {
    const b = loginSchema.safeParse(req.body);
    if (!b.success) return res.status(400).json({ error: b.error.errors[0].message });
    const { username, password } = b.data;

    const user = db.prepare('SELECT * FROM users WHERE username=?').get(username);
    const fail = () => {
      try {
        if (user) {
          const n = (user.failed_attempts || 0) + 1;
          const lockUntil = n >= 5 ? Date.now() + 15 * 60e3 : null;
          db.prepare('UPDATE users SET failed_attempts=?, locked_until=? WHERE id=?').run(n, lockUntil, user.id);
        }
      } catch (e) { console.error('Fail-track error:', e.message); }
      audit({ ip: req.ip }, 'LOGIN_FAILED', `username=${username}`);
      return res.status(401).json({ error: 'Invalid credentials' });
    };

    if (!user) return fail();
    if (user.locked_until && user.locked_until > Date.now())
      return res.status(423).json({ error: 'Account locked. Try again in 15 minutes.' });
    if (!bcrypt.compareSync(password, user.password_hash)) return fail();

    db.prepare('UPDATE users SET failed_attempts=0, locked_until=NULL WHERE id=?').run(user.id);
    const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, JWT_SECRET, { expiresIn: process.env.JWT_EXPIRES_IN || '8h' });
    audit({ user: { id: user.id, username: user.username }, ip: req.ip }, 'LOGIN_SUCCESS', user.username);
    res.json({ token, user: { id: user.id, username: user.username, email: user.email, role: user.role } });
  } catch (e) {
    console.error('Login error:', e);
    res.status(500).json({ error: 'Login failed: ' + e.message });
  }
});

authRouter.get('/me', auth, (req, res) => {
  try {
    const u = db.prepare('SELECT id,username,email,role,created_at FROM users WHERE id=?').get(req.user.id);
    if (!u) return res.status(401).json({ error: 'User not found' });
    res.json({ user: u });
  } catch (e) {
    console.error('/me error:', e);
    res.status(500).json({ error: e.message });
  }
});