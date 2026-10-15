const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;

if (!JWT_SECRET) {
  throw new Error("Не задан JWT_SECRET в переменных окружения");
}

if (!process.env.DATABASE_URL) {
  throw new Error("Не задан DATABASE_URL в переменных окружения");
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL.includes("localhost")
    ? false
    : { rejectUnauthorized: false }
});

app.use(express.json({ limit: "1mb" }));
app.use(express.static(path.join(__dirname, "public")));

const uploadDir = path.join(__dirname, "uploads");
fs.mkdirSync(uploadDir, { recursive: true });

const upload = multer({
  dest: uploadDir,
  limits: { fileSize: 100 * 1024 * 1024 }
});

async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      first_name VARCHAR(80) NOT NULL,
      last_name VARCHAR(80) NOT NULL,
      middle_name VARCHAR(80) NOT NULL DEFAULT '',
      password_hash TEXT NOT NULL,
      public_code VARCHAR(20) UNIQUE NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS messages (
      id SERIAL PRIMARY KEY,
      sender_id INTEGER NOT NULL REFERENCES users(id),
      receiver_id INTEGER NOT NULL REFERENCES users(id),
      body TEXT NOT NULL DEFAULT '',
      file_name TEXT,
      file_path TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);
}

function createToken(user) {
  return jwt.sign(
    { id: user.id },
    JWT_SECRET,
    { expiresIn: "7d" }
  );
}

async function auth(req, res, next) {
  try {
    const header = req.headers.authorization || "";
    const token = header.startsWith("Bearer ")
      ? header.slice(7)
      : "";

    if (!token) {
      return res.status(401).json({ error: "Нужно войти в аккаунт" });
    }

    const payload = jwt.verify(token, JWT_SECRET);
    const result = await pool.query(
      "SELECT id, first_name, last_name, middle_name, public_code FROM users WHERE id = $1",
      [payload.id]
    );

    if (!result.rows.length) {
      return res.status(401).json({ error: "Пользователь не найден" });
    }

    req.user = result.rows[0];
    next();
  } catch {
    return res.status(401).json({ error: "Недействительный токен" });
  }
}

app.post("/api/register", async (req, res) => {
  try {
    const {
      firstName,
      lastName,
      middleName = "",
      password
    } = req.body || {};

    if (
      typeof firstName !== "string" ||
      typeof lastName !== "string" ||
      typeof middleName !== "string" ||
      typeof password !== "string"
    ) {
      return res.status(400).json({ error: "Проверьте поля регистрации" });
    }

    if (
      !firstName.trim() ||
      !lastName.trim() ||
      password.length < 8 ||
      password.length > 200
    ) {
      return res.status(400).json({
        error: "Укажите имя, фамилию и пароль от 8 символов"
      });
    }

    if (
      firstName.length > 80 ||
      lastName.length > 80 ||
      middleName.length > 80
    ) {
      return res.status(400).json({ error: "Слишком длинные данные" });
    }

    const passwordHash = await bcrypt.hash(password, 12);
    let user;

    for (let attempt = 0; attempt < 5; attempt++) {
      const publicCode = crypto.randomBytes(5).toString("hex").toUpperCase();

      try {
        const result = await pool.query(
          `INSERT INTO users
           (first_name, last_name, middle_name, password_hash, public_code)
           VALUES ($1, $2, $3, $4, $5)
           RETURNING id, first_name, last_name, middle_name, public_code`,
          [
            firstName.trim(),
            lastName.trim(),
            middleName.trim(),
            passwordHash,
            publicCode
          ]
        );

        user = result.rows[0];
        break;
      } catch (error) {
        if (error.code !== "23505") throw error;
      }
    }

    if (!user) {
      return res.status(500).json({ error: "Не удалось создать код пользователя" });
    }

    res.status(201).json({
      token: createToken(user),
      user
    });
  } catch (error) {
    console.error("Ошибка регистрации:", error);
    res.status(500).json({ error: "Ошибка сервера при регистрации" });
  }
});

app.post("/api/login", async (req, res) => {
  try {
    const { publicCode, password } = req.body || {};

    if (
      typeof publicCode !== "string" ||
      typeof password !== "string"
    ) {
      return res.status(400).json({ error: "Введите код и пароль" });
    }

    const result = await pool.query(
      "SELECT * FROM users WHERE public_code = $1",
      [publicCode.trim().toUpperCase()]
    );

    const user = result.rows[0];

    if (!user || !(await bcrypt.compare(password, user.password_hash))) {
      return res.status(401).json({ error: "Неверный код или пароль" });
    }

    res.json({
      token: createToken(user),
      user: {
        id: user.id,
        first_name: user.first_name,
        last_name: user.last_name,
        middle_name: user.middle_name,
        public_code: user.public_code
      }
    });
  } catch (error) {
    console.error("Ошибка входа:", error);
    res.status(500).json({ error: "Ошибка сервера при входе" });
  }
});

app.get("/api/me", auth, (req, res) => {
  res.json({ user: req.user });
});

app.get("/api/users/search/:code", auth, async (req, res) => {
  try {
    const code = String(req.params.code).trim().toUpperCase();

    if (!/^[A-F0-9]{10}$/.test(code)) {
      return res.status(400).json({ error: "Проверьте код пользователя" });
    }

    const result = await pool.query(
      `SELECT id, first_name, last_name, middle_name, public_code
       FROM users
       WHERE public_code = $1 AND id <> $2`,
      [code, req.user.id]
    );

    if (!result.rows.length) {
      return res.status(404).json({ error: "Пользователь не найден" });
    }

    res.json({ user: result.rows[0] });
  } catch (error) {
    console.error("Ошибка поиска:", error);
    res.status(500).json({ error: "Ошибка поиска пользователя" });
  }
});

app.get("/api/messages/:userId", auth, async (req, res) => {
  try {
    const otherId = Number(req.params.userId);

    if (!Number.isInteger(otherId) || otherId <= 0) {
      return res.status(400).json({ error: "Неверный ID пользователя" });
    }

    const result = await pool.query(
      `SELECT id, sender_id, receiver_id, body, file_name, created_at
       FROM messages
       WHERE (sender_id = $1 AND receiver_id = $2)
          OR (sender_id = $2 AND receiver_id = $1)
       ORDER BY created_at ASC
       LIMIT 500`,
      [req.user.id, otherId]
    );

    res.json({ messages: result.rows });
  } catch (error) {
    console.error("Ошибка получения сообщений:", error);
    res.status(500).json({ error: "Не удалось получить сообщения" });
  }
});

app.post("/api/messages/:userId", auth, async (req, res) => {
  try {
    const receiverId = Number(req.params.userId);
    const body = typeof req.body?.body === "string"
      ? req.body.body.trim()
      : "";

    if (
      !Number.isInteger(receiverId) ||
      receiverId <= 0 ||
      receiverId === req.user.id
    ) {
      return res.status(400).json({ error: "Неверный получатель" });
    }

    if (!body || body.length > 10000) {
      return res.status(400).json({ error: "Сообщение пустое или слишком длинное" });
    }

    const result = await pool.query(
      `INSERT INTO messages (sender_id, receiver_id, body)
       SELECT $1, id, $3 FROM users WHERE id = $2
       RETURNING id, sender_id, receiver_id, body, created_at`,
      [req.user.id, receiverId, body]
    );

    if (!result.rows.length) {
      return res.status(404).json({ error: "Получатель не найден" });
    }

    res.status(201).json({ message: result.rows[0] });
  } catch (error) {
    console.error("Ошибка отправки:", error);
    res.status(500).json({ error: "Не удалось отправить сообщение" });
  }
});

app.post(
  "/api/messages/:userId/file",
  auth,
  upload.single("file"),
  async (req, res) => {
    try {
      const receiverId = Number(req.params.userId);

      if (
        !Number.isInteger(receiverId) ||
        receiverId <= 0 ||
        receiverId === req.user.id
      ) {
        if (req.file) fs.unlinkSync(req.file.path);
        return res.status(400).json({ error: "Неверный получатель" });
      }

      if (!req.file) {
        return res.status(400).json({ error: "Файл не выбран" });
      }

      const result = await pool.query(
        `INSERT INTO messages
         (sender_id, receiver_id, body, file_name, file_path)
         SELECT $1, id, '', $3, $4
         FROM users WHERE id = $2
         RETURNING id, sender_id, receiver_id, body, file_name, created_at`,
        [
          req.user.id,
          receiverId,
          path.basename(req.file.originalname).slice(0, 255),
          req.file.filename
        ]
      );

      if (!result.rows.length) {
        fs.unlinkSync(req.file.path);
        return res.status(404).json({ error: "Получатель не найден" });
      }

      res.status(201).json({ message: result.rows[0] });
    } catch (error) {
      if (req.file && fs.existsSync(req.file.path)) {
        fs.unlinkSync(req.file.path);
      }

      console.error("Ошибка загрузки файла:", error);
      res.status(500).json({ error: "Не удалось отправить файл" });
    }
  }
);

app.get("/api/files/:messageId", auth, async (req, res) => {
  try {
    const messageId = Number(req.params.messageId);

    const result = await pool.query(
      `SELECT file_name, file_path
       FROM messages
       WHERE id = $1 AND (sender_id = $2 OR receiver_id = $2)`,
      [messageId, req.user.id]
    );

    if (!result.rows.length || !result.rows[0].file_path) {
      return res.status(404).json({ error: "Файл не найден" });
    }

    const file = result.rows[0];
    const filePath = path.join(uploadDir, path.basename(file.file_path));

    if (!fs.existsSync(filePath)) {
      return res.status(410).json({ error: "Файл больше не хранится на сервере" });
    }

    res.download(filePath, file.file_name);
  } catch (error) {
    console.error("Ошибка скачивания:", error);
    res.status(500).json({ error: "Не удалось скачать файл" });
  }
});

app.get("/api/health", (req, res) => {
  res.json({ status: "ok", app: "HERNYA" });
});

app.use((error, req, res, next) => {
  if (error instanceof multer.MulterError) {
    return res.status(400).json({
      error: error.code === "LIMIT_FILE_SIZE"
        ? "Максимальный размер файла — 100 МБ"
        : "Ошибка загрузки файла"
    });
  }

  console.error("Необработанная ошибка:", error);
  res.status(500).json({ error: "Внутренняя ошибка сервера" });
});

async function start() {
  await initDB();

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`HERNYA запущена на порту ${PORT}`);
  });
}

start().catch(error => {
  console.error("Не удалось запустить HERNYA:", error);
  process.exit(1);
});