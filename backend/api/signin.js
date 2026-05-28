import bcrypt from 'bcrypt';
import db from '../db.js';
import { isOwnerEmail } from '../utils/auth-roles.js';
import { getClientIP } from '../utils/client-ip.js';
import { isIpBanned } from '../middleware/ip-ban.js';

const DUMMY_HASH = '$2b$10$abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ12';

export async function signinHandler(req, res) {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password are required' });

  const clientIp = getClientIP(req);
  if (clientIp && isIpBanned(clientIp)) {
    return res.status(403).json({ error: 'Access denied.' });
  }

  try {
    const user = db.prepare(
      'SELECT id, email, password_hash, username, bio, avatar_url, email_verified, ip, is_admin, banned FROM users WHERE email = ?'
    ).get(email);

    const hashToCompare = user ? user.password_hash : DUMMY_HASH;
    const passwordMatch = await bcrypt.compare(password, hashToCompare);

    if (!user || !passwordMatch) {
      await new Promise(r => setTimeout(r, Math.floor(Math.random() * 50)));
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    if (user.banned) return res.status(403).json({ error: 'This account has been banned.' });
    if (!user.email_verified) return res.status(401).json({ error: 'Please verify your email before logging in.' });

    // Also treat ADMIN_EMAIL as owner (is_admin = 3)
    const isOwner = isOwnerEmail(user.email);
    const effectiveAdmin = isOwner ? Math.max(user.is_admin || 0, 3) : (user.is_admin || 0);

    // Promote owner in DB if not already
    if (isOwner && (user.is_admin || 0) < 3) {
      db.prepare('UPDATE users SET is_admin = 3 WHERE id = ?').run(user.id);
    }

    if (clientIp) db.prepare('UPDATE users SET ip = ? WHERE id = ?').run(clientIp, user.id);

    const sessionUser = {
      id: user.id,
      email: user.email,
      username: user.username,
      bio: user.bio,
      avatar_url: user.avatar_url,
      is_admin: effectiveAdmin,
      is_owner: isOwner,
    };

    req.session.user = sessionUser;
    await new Promise((resolve, reject) => req.session.save(err => err ? reject(err) : resolve()));

    res.status(200).json({ user: sessionUser, message: 'Signin successful' });
  } catch (error) {
    console.error('Signin error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
}