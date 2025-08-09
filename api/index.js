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

// Tambahkan baris ini di bagian akhir file untuk Vercel
module.exports = app;