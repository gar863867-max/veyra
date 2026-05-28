import db from '../db.js';
import { isOwnerEmail } from '../utils/auth-roles.js';

const PAGE_SIZE = 25;
const SEARCH_LIMIT = 100;

function requireAdmin(req, res) {
  if (!req.session?.user) {
    res.status(401).json({ error: 'Unauthorized' });
    return null;
  }
  const admin = db.prepare('SELECT is_admin FROM users WHERE id = ?').get(req.session.user.id);
  if (!admin || admin.is_admin < 1) {
    res.status(403).json({ error: 'Forbidden' });
    return null;
  }
  return admin;
}

export function getAdminUsersHandler(req, res) {
  if (!requireAdmin(req, res)) return;

  const search = (req.query.search || '').trim();
  if (search) {
    const safe = search.toLowerCase().replace(/[%_\\]/g, '');
    const pattern = `%${safe}%`;
    const rows = db.prepare(`
      SELECT id, username, email, is_admin, banned, email_verified, created_at
      FROM users
      WHERE LOWER(COALESCE(username, '')) LIKE ? OR LOWER(email) LIKE ?
      ORDER BY created_at DESC
      LIMIT ?
    `).all(pattern, pattern, SEARCH_LIMIT);
    const users = rows.map((u) => ({
      id: u.id,
      username: u.username,
      is_admin: u.is_admin,
      banned: u.banned,
      email_verified: u.email_verified,
      created_at: u.created_at,
      is_owner: isOwnerEmail(u.email),
    }));
    return res.json({ users, search: true });
  }

  const page = Math.max(1, parseInt(req.query.page, 10) || 1);
  const offset = (page - 1) * PAGE_SIZE;
  const { c: total } = db.prepare('SELECT COUNT(*) as c FROM users').get();
  const rows = db.prepare(`
    SELECT id, username, email, is_admin, banned, email_verified, created_at
    FROM users
    ORDER BY created_at DESC
    LIMIT ? OFFSET ?
  `).all(PAGE_SIZE, offset);

  const users = rows.map((u) => ({
    id: u.id,
    username: u.username,
    is_admin: u.is_admin,
    banned: u.banned,
    email_verified: u.email_verified,
    created_at: u.created_at,
    is_owner: isOwnerEmail(u.email),
  }));

  res.json({
    users,
    page,
    totalPages: Math.max(1, Math.ceil(total / PAGE_SIZE)),
    total,
  });
}

export function getAdminUserHandler(req, res) {
  if (!requireAdmin(req, res)) return;

  const user = db.prepare(`
    SELECT id, email, username, avatar_url, bio, is_admin, banned, email_verified, created_at, ip, school, age
    FROM users WHERE id = ?
  `).get(req.params.id);

  if (!user) return res.status(404).json({ error: 'Not found' });
  res.json({
    user: {
      ...user,
      is_owner: isOwnerEmail(user.email),
    },
  });
}

export function getAdminStaffHandler(req, res) {
  if (!requireAdmin(req, res)) return;

  const rows = db.prepare(`
    SELECT id, username, email, is_admin, banned, email_verified, created_at, ip
    FROM users
    WHERE is_admin >= 1
    ORDER BY is_admin DESC, created_at ASC
  `).all();

  const staff = rows.map((u) => ({
    id: u.id,
    username: u.username,
    is_admin: u.is_admin,
    banned: u.banned,
    email_verified: u.email_verified,
    created_at: u.created_at,
    ip: u.ip,
    is_owner: isOwnerEmail(u.email),
  }));

  const me = db.prepare('SELECT email FROM users WHERE id = ?').get(req.session.user.id);
  res.json({
    staff,
    is_owner: isOwnerEmail(me?.email),
  });
}
