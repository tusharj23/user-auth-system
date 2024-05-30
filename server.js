const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');  // Using bcryptjs for compatibility
const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const app = express();
const port = 8080;

// Middleware
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));

// Database setup
const db = new sqlite3.Database(':memory:');
db.serialize(() => {
  db.run('CREATE TABLE users (userId TEXT PRIMARY KEY, password TEXT)');
});

// Helper function to query the database
function queryDB(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => {
      if (err) {
        reject(err);
      } else {
        resolve(rows);
      }
    });
  });
}

// Signup endpoint
app.post('/signup', async (req, res) => {
  const { userId, password } = req.body;
  if (!userId || !password) {
    return res.status(400).json({ error: 'UserId and password are required' });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    await queryDB('INSERT INTO users (userId, password) VALUES (?, ?)', [userId, hashedPassword]);
    res.status(201).json({ message: 'User registered successfully' });
  } catch (error) {
    res.status(500).json({ error: 'User registration failed' });
  }
});

// Login endpoint
app.post('/login', async (req, res) => {
  const { userId, password } = req.body;
  if (!userId || !password) {
    return res.status(400).json({ error: 'UserId and password are required' });
  }

  try {
    const users = await queryDB('SELECT * FROM users WHERE userId = ?', [userId]);
    if (users.length === 0) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    const user = users[0];
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (isPasswordValid) {
      res.status(200).json({ message: 'Login successful' });
    } else {
      res.status(400).json({ error: 'Invalid credentials' });
    }
  } catch (error) {
    res.status(500).json({ error: 'Login failed' });
  }
});

app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});
