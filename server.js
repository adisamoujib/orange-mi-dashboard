/**
 * Orange Market Intelligence Dashboard — Backend API v2
 * Auth: JWT (bcryptjs passwords) + rôles superadmin / user
 * Storage: JSON files (aucune dépendance native)
 */

require("dotenv").config();
const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { v4: uuidv4 } = require("uuid");
const path = require("path");
const fs = require("fs");

// ─── CONFIG ──────────────────────────────────────────────────────────────────

const PORT = parseInt(process.env.PORT || "3001", 10);
const JWT_SECRET = process.env.JWT_SECRET || "orange-mi-secret-changez-en-production-" + Date.now();
const JWT_EXPIRES = process.env.JWT_EXPIRES || "8h";
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, "data");

const allowedOrigins = process.env.ALLOWED_ORIGINS
  ? process.env.ALLOWED_ORIGINS.split(",").map((s) => s.trim())
  : ["*"];

if (!process.env.JWT_SECRET) {
  console.warn("⚠️  JWT_SECRET non défini dans .env — utilisation d'un secret temporaire (non persistant)");
}

// ─── FILE STORE ───────────────────────────────────────────────────────────────

fs.mkdirSync(DATA_DIR, { recursive: true });

const FILES = {
  users: path.join(DATA_DIR, "users.json"),
  activities: path.join(DATA_DIR, "activities.json"),
  monetisations: path.join(DATA_DIR, "monetisations.json"),
  audit: path.join(DATA_DIR, "audit.log"),
};

function readJson(file) {
  try {
    if (fs.existsSync(file)) return JSON.parse(fs.readFileSync(file, "utf8"));
  } catch (e) { console.error(`⚠️  Lecture ${file}:`, e.message); }
  return [];
}

function writeJson(file, data) {
  fs.writeFileSync(file, JSON.stringify(data, null, 2), "utf8");
}

function appendAudit(action, table, id, userId) {
  const line = JSON.stringify({ ts: new Date().toISOString(), action, table, id, userId }) + "\n";
  try { fs.appendFileSync(FILES.audit, line, "utf8"); } catch (_) {}
}

// ─── IN-MEMORY STORE ─────────────────────────────────────────────────────────

let users = readJson(FILES.users);
let activities = readJson(FILES.activities);
let monetisations = readJson(FILES.monetisations);

// ─── SEED SUPERADMIN ─────────────────────────────────────────────────────────

async function seedSuperAdmin() {
  if (users.length === 0) {
    const tempPassword = "Admin@Orange2026";
    const hash = await bcrypt.hash(tempPassword, 10);
    const admin = {
      id: uuidv4(),
      email: "superadmin@orange.ci",
      passwordHash: hash,
      role: "superadmin",
      collaborateur: null,
      nom: "Super Administrateur",
      active: true,
      mustChangePassword: true,
      createdAt: new Date().toISOString(),
    };
    users.push(admin);
    writeJson(FILES.users, users);
    console.log("\n" + "=".repeat(60));
    console.log("🔐 COMPTE SUPERADMIN CRÉÉ (première utilisation)");
    console.log("   Email    : superadmin@orange.ci");
    console.log("   Mot de passe : Admin@Orange2026");
    console.log("   ⚠️  CHANGEZ CE MOT DE PASSE IMMÉDIATEMENT");
    console.log("=".repeat(60) + "\n");
  }
}

// ─── APP ─────────────────────────────────────────────────────────────────────

const app = express();

app.use(helmet({ crossOriginResourcePolicy: { policy: "cross-origin" } }));
app.use(express.json({ limit: "1mb" }));

app.use(cors({
  origin: allowedOrigins.includes("*") ? true : (origin, cb) => {
    if (!origin || allowedOrigins.some((o) => origin.startsWith(o))) cb(null, true);
    else cb(new Error(`CORS: ${origin} non autorisé`));
  },
  credentials: true,
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
}));

app.use("/api/", rateLimit({ windowMs: 15 * 60 * 1000, max: 500, standardHeaders: true, legacyHeaders: false }));
app.use("/api/auth/login", rateLimit({ windowMs: 15 * 60 * 1000, max: 20, message: { error: "Trop de tentatives." } }));

// ─── AUTH MIDDLEWARE ──────────────────────────────────────────────────────────

const authenticate = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Token manquant." });
  }
  const token = authHeader.slice(7);
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (e) {
    return res.status(401).json({ error: "Token invalide ou expiré." });
  }
};

const requireAdmin = (req, res, next) => {
  if (req.user?.role !== "superadmin") {
    return res.status(403).json({ error: "Accès réservé au super administrateur." });
  }
  next();
};

// ─── HELPERS ─────────────────────────────────────────────────────────────────

const now = () => new Date().toISOString();

function generatePassword(length = 10) {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789@#";
  return Array.from({ length }, () => chars[Math.floor(Math.random() * chars.length)]).join("");
}

const makeActivity = (a, id) => ({
  id: id || uuidv4(),
  collaborateur: a.collaborateur || "",
  semaine: a.semaine || "",
  forecastDate: a.forecastDate || "",
  categorie: a.categorie || "",
  livrable: a.livrable || "",
  titre: a.titre || "",
  priorite: a.priorite || "Moyenne",
  statut: a.statut || "En cours",
  progression: Number(a.progression || 0),
  difficultes: a.difficultes || "Aucune",
  actionsCorrectives: a.actionsCorrectives || "Aucune",
  commentaires: a.commentaires || "",
  createdAt: a.createdAt || now(),
});

const makeMon = (m, id) => ({
  id: id || uuidv4(),
  titre: m.titre || "",
  description: m.description || "",
  direction: m.direction || "",
  coutExterne: Number(m.coutExterne || 0),
  coutInterne: Number(m.coutInterne || 0),
  dateRealisation: m.dateRealisation || "",
  statut: m.statut || "En cours",
  responsable: m.responsable || "",
  livrable: m.livrable || "",
  commanditaire: m.commanditaire || "",
  createdAt: m.createdAt || now(),
});

const safeUser = (u) => ({ id: u.id, email: u.email, role: u.role, collaborateur: u.collaborateur, nom: u.nom, active: u.active, mustChangePassword: u.mustChangePassword, createdAt: u.createdAt });

// ─── AUTH ROUTES ──────────────────────────────────────────────────────────────

// Public health check
app.get("/api/health", (req, res) => {
  res.json({ status: "ok", service: "Orange MI Dashboard API", version: "2.0.0", timestamp: now() });
});

// Login
app.post("/api/auth/login", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: "Email et mot de passe requis." });

  const user = users.find((u) => u.email.toLowerCase() === email.toLowerCase() && u.active);
  if (!user) return res.status(401).json({ error: "Email ou mot de passe incorrect." });

  const valid = await bcrypt.compare(password, user.passwordHash);
  if (!valid) return res.status(401).json({ error: "Email ou mot de passe incorrect." });

  const token = jwt.sign(
    { userId: user.id, email: user.email, role: user.role, collaborateur: user.collaborateur, nom: user.nom },
    JWT_SECRET,
    { expiresIn: JWT_EXPIRES }
  );

  appendAudit("LOGIN", "users", user.id, user.id);
  res.json({ token, user: safeUser(user) });
});

// Change own password
app.post("/api/auth/change-password", authenticate, async (req, res) => {
  const { oldPassword, newPassword } = req.body;
  if (!oldPassword || !newPassword) return res.status(400).json({ error: "Champs requis." });
  if (newPassword.length < 6) return res.status(400).json({ error: "Mot de passe trop court (min 6 caractères)." });

  const idx = users.findIndex((u) => u.id === req.user.userId);
  if (idx === -1) return res.status(404).json({ error: "Utilisateur non trouvé." });

  const valid = await bcrypt.compare(oldPassword, users[idx].passwordHash);
  if (!valid) return res.status(401).json({ error: "Ancien mot de passe incorrect." });

  users[idx].passwordHash = await bcrypt.hash(newPassword, 10);
  users[idx].mustChangePassword = false;
  writeJson(FILES.users, users);
  res.json({ message: "Mot de passe mis à jour." });
});

// Get own profile
app.get("/api/auth/me", authenticate, (req, res) => {
  const user = users.find((u) => u.id === req.user.userId);
  if (!user) return res.status(404).json({ error: "Utilisateur non trouvé." });
  res.json(safeUser(user));
});

// ─── USER MANAGEMENT (superadmin only) ───────────────────────────────────────

app.get("/api/users", authenticate, requireAdmin, (req, res) => {
  res.json(users.map(safeUser));
});

app.post("/api/users", authenticate, requireAdmin, async (req, res) => {
  const { email, nom, collaborateur, role } = req.body;
  if (!email || !nom) return res.status(400).json({ error: "Email et nom requis." });

  if (users.find((u) => u.email.toLowerCase() === email.toLowerCase())) {
    return res.status(409).json({ error: "Un utilisateur avec cet email existe déjà." });
  }

  const plainPassword = generatePassword();
  const hash = await bcrypt.hash(plainPassword, 10);

  const user = {
    id: uuidv4(),
    email,
    passwordHash: hash,
    role: role === "superadmin" ? "superadmin" : "user",
    collaborateur: collaborateur || null,
    nom,
    active: true,
    mustChangePassword: true,
    createdAt: now(),
  };

  users.push(user);
  writeJson(FILES.users, users);
  appendAudit("CREATE_USER", "users", user.id, req.user.userId);

  // Return user + plain password (only time it's visible)
  res.status(201).json({ user: safeUser(user), temporaryPassword: plainPassword });
});

app.put("/api/users/:id", authenticate, requireAdmin, async (req, res) => {
  const idx = users.findIndex((u) => u.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: "Utilisateur non trouvé." });

  const { nom, collaborateur, role, active, resetPassword } = req.body;

  if (nom !== undefined) users[idx].nom = nom;
  if (collaborateur !== undefined) users[idx].collaborateur = collaborateur;
  if (role !== undefined) users[idx].role = role === "superadmin" ? "superadmin" : "user";
  if (active !== undefined) users[idx].active = Boolean(active);

  let newPassword = null;
  if (resetPassword) {
    newPassword = generatePassword();
    users[idx].passwordHash = await bcrypt.hash(newPassword, 10);
    users[idx].mustChangePassword = true;
  }

  writeJson(FILES.users, users);
  appendAudit("UPDATE_USER", "users", req.params.id, req.user.userId);

  res.json({ user: safeUser(users[idx]), ...(newPassword ? { temporaryPassword: newPassword } : {}) });
});

app.delete("/api/users/:id", authenticate, requireAdmin, (req, res) => {
  if (req.params.id === req.user.userId) {
    return res.status(400).json({ error: "Vous ne pouvez pas supprimer votre propre compte." });
  }
  const before = users.length;
  users = users.filter((u) => u.id !== req.params.id);
  if (users.length === before) return res.status(404).json({ error: "Utilisateur non trouvé." });
  writeJson(FILES.users, users);
  appendAudit("DELETE_USER", "users", req.params.id, req.user.userId);
  res.status(204).end();
});

// ─── ACTIVITIES ───────────────────────────────────────────────────────────────

app.get("/api/activities", authenticate, (req, res) => {
  let data = [...activities];
  // Users only see their own activities
  if (req.user.role !== "superadmin" && req.user.collaborateur) {
    data = data.filter((a) => a.collaborateur === req.user.collaborateur);
  }
  data.sort((a, b) => (b.semaine || "").localeCompare(a.semaine || "") || (b.createdAt || "").localeCompare(a.createdAt || ""));
  res.json(data);
});

// Aggregated stats for non-admins (no personal details)
app.get("/api/activities/stats", authenticate, (req, res) => {
  const total = activities.length;
  const terminees = activities.filter((a) => a.statut === "Terminé").length;
  const enCours = activities.filter((a) => a.statut === "En cours").length;
  const bloquees = activities.filter((a) => a.statut === "Bloqué").length;
  const byCategorie = {};
  activities.forEach((a) => { byCategorie[a.categorie || "Autre"] = (byCategorie[a.categorie || "Autre"] || 0) + 1; });
  res.json({ total, terminees, enCours, bloquees, byCategorie });
});

app.post("/api/activities", authenticate, (req, res) => {
  const a = req.body;
  if (!a.titre) return res.status(400).json({ error: "titre est requis." });

  // Users can only create activities for themselves
  if (req.user.role !== "superadmin") {
    a.collaborateur = req.user.collaborateur;
  }
  if (!a.collaborateur) return res.status(400).json({ error: "collaborateur est requis." });

  const record = makeActivity(a);
  activities.push(record);
  writeJson(FILES.activities, activities);
  appendAudit("INSERT", "activities", record.id, req.user.userId);
  res.status(201).json(record);
});

app.put("/api/activities/:id", authenticate, (req, res) => {
  const idx = activities.findIndex((x) => x.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: "Activité non trouvée." });

  // Users can only edit their own activities
  if (req.user.role !== "superadmin" && activities[idx].collaborateur !== req.user.collaborateur) {
    return res.status(403).json({ error: "Vous ne pouvez modifier que vos propres activités." });
  }

  const existing = activities[idx];
  const updated = makeActivity({ ...existing, ...req.body }, existing.id);
  if (req.user.role !== "superadmin") updated.collaborateur = existing.collaborateur;
  updated.createdAt = existing.createdAt;
  activities[idx] = updated;
  writeJson(FILES.activities, activities);
  appendAudit("UPDATE", "activities", updated.id, req.user.userId);
  res.json(updated);
});

app.delete("/api/activities/:id", authenticate, (req, res) => {
  const idx = activities.findIndex((x) => x.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: "Activité non trouvée." });

  if (req.user.role !== "superadmin" && activities[idx].collaborateur !== req.user.collaborateur) {
    return res.status(403).json({ error: "Vous ne pouvez supprimer que vos propres activités." });
  }

  activities.splice(idx, 1);
  writeJson(FILES.activities, activities);
  appendAudit("DELETE", "activities", req.params.id, req.user.userId);
  res.status(204).end();
});

// ─── MONETISATIONS ────────────────────────────────────────────────────────────

app.get("/api/monetisations", authenticate, (req, res) => {
  const sorted = [...monetisations].sort((a, b) => (b.createdAt || "").localeCompare(a.createdAt || ""));
  res.json(sorted);
});

app.post("/api/monetisations", authenticate, (req, res) => {
  const m = req.body;
  if (!m.titre) return res.status(400).json({ error: "titre est requis." });
  const record = makeMon(m);
  monetisations.push(record);
  writeJson(FILES.monetisations, monetisations);
  appendAudit("INSERT", "monetisations", record.id, req.user.userId);
  res.status(201).json(record);
});

app.put("/api/monetisations/:id", authenticate, (req, res) => {
  const idx = monetisations.findIndex((x) => x.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: "Etude non trouvée." });
  const existing = monetisations[idx];
  const updated = makeMon({ ...existing, ...req.body }, existing.id);
  updated.createdAt = existing.createdAt;
  monetisations[idx] = updated;
  writeJson(FILES.monetisations, monetisations);
  appendAudit("UPDATE", "monetisations", updated.id, req.user.userId);
  res.json(updated);
});

app.delete("/api/monetisations/:id", authenticate, (req, res) => {
  const before = monetisations.length;
  monetisations = monetisations.filter((x) => x.id !== req.params.id);
  if (monetisations.length === before) return res.status(404).json({ error: "Etude non trouvée." });
  writeJson(FILES.monetisations, monetisations);
  appendAudit("DELETE", "monetisations", req.params.id, req.user.userId);
  res.status(204).end();
});

// ─── STATS & EXPORT ───────────────────────────────────────────────────────────

app.get("/api/stats", authenticate, (req, res) => {
  const terminees = activities.filter((a) => a.statut === "Terminé").length;
  const bloquees = activities.filter((a) => a.statut === "Bloqué").length;
  const totalSavings = monetisations.reduce((s, m) => s + (Number(m.coutExterne || 0) - Number(m.coutInterne || 0)), 0);
  res.json({
    activities: { total: activities.length, terminees, bloquees },
    monetisation: { totalSavings, totalEtudes: monetisations.length },
  });
});

app.get("/api/export", authenticate, requireAdmin, (req, res) => {
  const date = new Date().toISOString().slice(0, 10);
  res.setHeader("Content-Disposition", `attachment; filename="orange_mi_export_${date}.json"`);
  res.json({ exportedAt: now(), activities, monetisations, users: users.map(safeUser) });
});

// ─── ERROR HANDLER ────────────────────────────────────────────────────────────

app.use((err, req, res, _next) => { console.error(err.message); res.status(500).json({ error: "Erreur serveur interne." }); });
app.use((_req, res) => res.status(404).json({ error: "Route non trouvée." }));

// ─── START ────────────────────────────────────────────────────────────────────

seedSuperAdmin().then(() => {
  app.listen(PORT, "0.0.0.0", () => {
    console.log(`\n🚀 Orange MI Backend v2 démarré`);
    console.log(`   Port    : ${PORT}`);
    console.log(`   Données : ${DATA_DIR}`);
    console.log(`   Auth    : JWT (${JWT_EXPIRES})`);
    console.log(`   CORS    : ${allowedOrigins.join(", ")}`);
    console.log(`   Health  : http://localhost:${PORT}/api/health\n`);
  });
});
