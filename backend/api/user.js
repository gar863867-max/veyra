import db from '../db.js';
import { sanitizeUsername } from '../utils/sanitize.js';
import { isOwnerEmail } from '../utils/auth-roles.js';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';
import { randomUUID } from 'crypto';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

export async function getMeHandler(req, res) {
  if (!req.session?.user) return res.status(401).json({ error: 'Unauthorized' });
  const user = db.prepare(
    'SELECT id, email, username, bio, avatar_url, is_admin, email_verified, school, age, created_at FROM users WHERE id = ?'
  ).get(req.session.user.id);
  if (!user) return res.status(404).json({ error: 'User not found' });

  if (isOwnerEmail(user.email) && user.is_admin < 3) {
    db.prepare('UPDATE users SET is_admin = 3 WHERE id = ?').run(user.id);
    user.is_admin = 3;
  }

  const is_owner = isOwnerEmail(user.email);
  req.session.user.is_admin = user.is_admin;
  req.session.user.username = user.username;
  req.session.user.avatar_url = user.avatar_url;
  req.session.user.is_owner = is_owner;

  res.json({ user: { ...user, is_owner } });
}

export async function updateProfileHandler(req, res) {
  if (!req.session?.user) return res.status(401).json({ error: 'Unauthorized' });
  let { username, bio } = req.body;
  if (username !== undefined) {
    if (typeof username !== 'string') return res.status(400).json({ error: 'Invalid username' });
    username = sanitizeUsername(username);
    if (!username) return res.status(400).json({ error: 'Invalid username' });
  }
  if (bio !== undefined && (typeof bio !== 'string' || bio.length > 200))
    return res.status(400).json({ error: 'Bio too long' });

  const now = Date.now();
  db.prepare('UPDATE users SET username = ?, bio = ?, updated_at = ? WHERE id = ?')
    .run(username ?? null, bio ?? null, now, req.session.user.id);
  req.session.user.username = username;
  req.session.user.bio = bio;
  res.json({ message: 'Profile updated' });
}

export async function uploadAvatarHandler(req, res) {
  if (!req.session?.user) return res.status(401).json({ error: 'Unauthorized' });

  const contentType = req.headers['content-type'] || '';
  if (!contentType.startsWith('image/')) return res.status(400).json({ error: 'Invalid file type' });

  const ext = contentType.split('/')[1]?.replace('jpeg', 'jpg') || 'jpg';
  if (!['jpg', 'png', 'gif', 'webp'].includes(ext)) return res.status(400).json({ error: 'Unsupported format' });

  const uploadDir = path.join(__dirname, '../../uploads/avatars');
  if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });

  const filename = `${randomUUID()}.${ext}`;
  const filepath = path.join(uploadDir, filename);

  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > 5 * 1024 * 1024) {
      res.status(413).json({ error: 'File too large (max 5MB)' });
      return;
    }
    chunks.push(chunk);
  }

  fs.writeFileSync(filepath, Buffer.concat(chunks));

  const avatarUrl = `/uploads/avatars/${filename}`;
  db.prepare('UPDATE users SET avatar_url = ?, updated_at = ? WHERE id = ?')
    .run(avatarUrl, Date.now(), req.session.user.id);
  req.session.user.avatar_url = avatarUrl;

  res.json({ avatar_url: avatarUrl });
}