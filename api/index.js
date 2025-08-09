// index.js

const express = require("express");
const { Pool } = require("pg");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const cors = require("cors");
const multer = require("multer");

// Buat app Express
const app = express();

// Pastikan port dinamis dari environment
const port = process.env.PORT || 3000;
const SECRET_KEY = process.env.SECRET_KEY || "kunci-rahasia-super-aman";

app.use(cors());
app.use(express.json());
app.use(express.static("uploads"));

// --- Koneksi Database PostgreSQL ---
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false,
  },
});

// --- Endpoints Pengguna (Public) ---
app.post("/register", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).send("Email dan password harus diisi.");
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    await pool.query("INSERT INTO users (email, password) VALUES ($1, $2)", [
      email,
      hashedPassword,
    ]);
    res.status(201).send("Registrasi berhasil.");
  } catch (err) {
    console.error(err);
    res.status(400).send("Email sudah terdaftar.");
  }
});

app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  try {
    const result = await pool.query("SELECT * FROM users WHERE email = $1", [
      email,
    ]);
    const user = result.rows[0];

    if (!user) {
      return res.status(400).send("Email atau password salah.");
    }
    if (await bcrypt.compare(password, user.password)) {
      const token = jwt.sign({ id: user.id, email: user.email }, SECRET_KEY);
      res.json({ token });
    } else {
      res.status(400).send("Email atau password salah.");
    }
  } catch (err) {
    console.error(err);
    res.status(500).send("Error saat login.");
  }
});

// --- Endpoints Transaksi (Protected) ---
app.get("/transactions", authenticateToken, async (req, res) => {
  const userId = req.user.id;
  try {
    const result = await pool.query(
      "SELECT * FROM transactions WHERE userId = $1 ORDER BY date DESC",
      [userId]
    );
    const transactionsWithUrls = result.rows.map((t) => ({
      ...t,
      photoPath: t.photopath
        ? `https://${req.headers.host}/${t.photopath}`
        : null, // Mengubah URL menjadi dinamis
    }));
    res.json(transactionsWithUrls);
  } catch (err) {
    console.error(err);
    res.status(500).send("Error mengambil data transaksi.");
  }
});

app.post(
  "/transactions",
  authenticateToken,
  upload.single("photo"),
  async (req, res) => {
    const { description, amount, isExpense, date } = req.body;
    const userId = req.user.id;
    const photoPath = req.file ? req.file.filename : null;

    if (!description || !amount) {
      return res.status(400).send("Deskripsi dan jumlah harus diisi.");
    }

    try {
      await pool.query(
        "INSERT INTO transactions (description, amount, isExpense, date, userId, photoPath) VALUES ($1, $2, $3, $4, $5, $6)",
        [description, amount, isExpense === "1", date, userId, photoPath]
      );
      res.status(201).send("Transaksi berhasil ditambahkan.");
    } catch (err) {
      console.error(err);
      res.status(500).send("Error menambah transaksi.");
    }
  }
);

app.put(
  "/transactions/:id",
  authenticateToken,
  upload.single("photo"),
  async (req, res) => {
    const { description, amount, isExpense, date } = req.body;
    const transactionId = req.params.id;
    const userId = req.user.id;
    const photoPath = req.file ? req.file.filename : req.body.photoPath;

    try {
      const result = await pool.query(
        "UPDATE transactions SET description = $1, amount = $2, isExpense = $3, date = $4, photoPath = $5 WHERE id = $6 AND userId = $7 RETURNING id",
        [
          description,
          amount,
          isExpense === "1",
          date,
          photoPath,
          transactionId,
          userId,
        ]
      );
      if (result.rowCount === 0) {
        return res
          .status(404)
          .send("Transaksi tidak ditemukan atau Anda tidak memiliki izin.");
      }
      res.status(200).send("Transaksi berhasil diupdate.");
    } catch (err) {
      console.error(err);
      res.status(500).send("Error mengupdate transaksi.");
    }
  }
);

app.delete("/transactions/:id", authenticateToken, async (req, res) => {
  const transactionId = req.params.id;
  const userId = req.user.id;
  try {
    const result = await pool.query(
      "DELETE FROM transactions WHERE id = $1 AND userId = $2 RETURNING id",
      [transactionId, userId]
    );
    if (result.rowCount === 0) {
      return res
        .status(404)
        .send("Transaksi tidak ditemukan atau Anda tidak memiliki izin.");
    }
    res.status(200).send("Transaksi berhasil dihapus.");
  } catch (err) {
    console.error(err);
    res.status(500).send("Error menghapus transaksi.");
  }
});

// --- Jalankan Server ---
app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
