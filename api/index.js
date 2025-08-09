// file: api/index.js

const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');

const app = express();
app.use(express.json());
app.use(cors());

// Konfigurasi Database
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

// Middleware otentikasi dummy (Ganti dengan JWT asli nanti)
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (token == null || token !== 'dummy-token') {
    return res.status(401).json({ message: 'Token tidak valid.' });
  }

  // Di sini Anda bisa mengambil data pengguna dari token
  req.user = { id: 1 }; // Ganti dengan ID pengguna asli
  next();
};

// Endpoint untuk testing (opsional)
app.get('/', (req, res) => {
  res.send('API is running!');
});

// -- Endpoints Pengguna (Public) --
app.post('/register', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ message: 'Email dan password harus diisi.' });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    await pool.query('INSERT INTO users (email, password) VALUES ($1, $2)', [email, hashedPassword]);
    res.status(201).json({ message: 'Registrasi berhasil.' });
  } catch (err) {
    if (err.code === '23505') { // Error code for unique_violation
      return res.status(409).json({ message: 'Email sudah terdaftar.' });
    }
    console.error(err);
    res.status(500).json({ message: 'Error saat mendaftar.' });
  }
});

app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ message: 'Email dan password harus diisi.' });
  }

  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (result.rowCount === 0) {
      return res.status(401).json({ message: 'Email atau password salah.' });
    }

    const user = result.rows[0];
    const match = await bcrypt.compare(password, user.password);

    if (!match) {
      return res.status(401).json({ message: 'Email atau password salah.' });
    }

    res.status(200).json({ token: 'dummy-token' }); // Ganti dengan token JWT asli
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error saat login.' });
  }
});

// -- Endpoints Transaksi (Protected) --
// Tambahkan middleware 'authenticateToken' untuk melindungi endpoint
app.get('/transactions', authenticateToken, async (req, res) => {
  try {
    // Ambil semua transaksi dari tabel 'transactions'
    const result = await pool.query('SELECT * FROM transactions ORDER BY date DESC');
    res.status(200).json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error saat mengambil data transaksi.' });
  }
});

app.post('/transactions', authenticateToken, async (req, res) => {
  const { description, amount, is_expense, photo_url } = req.body;
  try {
    const result = await pool.query(
      'INSERT INTO transactions (description, amount, is_expense, photo_url) VALUES ($1, $2, $3, $4) RETURNING *',
      [description, amount, is_expense, photo_url]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error saat membuat transaksi baru.' });
  }
});

app.put('/transactions/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { description, amount, is_expense, photo_url } = req.body;
  try {
    const result = await pool.query(
      'UPDATE transactions SET description = $1, amount = $2, is_expense = $3, photo_url = $4 WHERE id = $5 RETURNING *',
      [description, amount, is_expense, photo_url, id]
    );
    if (result.rowCount === 0) {
      return res.status(404).json({ message: 'Transaksi tidak ditemukan.' });
    }
    res.status(200).json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error saat mengupdate transaksi.' });
  }
});

app.delete('/transactions/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pool.query('DELETE FROM transactions WHERE id = $1 RETURNING *', [id]);
    if (result.rowCount === 0) {
      return res.status(404).json({ message: 'Transaksi tidak ditemukan.' });
    }
    res.status(200).json({ message: 'Transaksi berhasil dihapus.' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error saat menghapus transaksi.' });
  }
});

// Tambahkan baris ini di bagian akhir file untuk Vercel
module.exports = app;
