const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const cors = require('cors');
require('dotenv').config();
const app = express();
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
// MySQL connection
const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: '123456', // your MySQL password
    database: 'auth_app'
});
 
db.connect((err) => {
    if (err) throw err;
    console.log('MySQL Connected...');
});
app.use(express.static(path.join(__dirname, '..', 'frontend')));

// Register route (with email checking)
app.post('/api/register', (req, res) => {
    const { username, email, password } = req.body;

    const checkSql = 'SELECT * FROM users WHERE email = ? OR username = ?';
    db.query(checkSql, [email, username], (err, results) => {
        if (err) return res.status(500).send('Database error');

        if (results.length > 0) {
            return res.status(400).send('Email or Username already exists');
        } else {
            bcrypt.hash(password, 10, (err, hash) => {
                if (err) return res.status(500).send('Error hashing password');

                const insertSql = 'INSERT INTO users (username, email, password) VALUES (?, ?, ?)';
                db.query(insertSql, [username, email, hash], (err, result) => {
                    if (err) return res.status(500).send('Database insert error');
                    res.send('User registered successfully!');
                });
            });
        }
    });
});

// Login route
app.post('/api/login', (req, res) => {
    const { email, password } = req.body;

    const sql = 'SELECT * FROM users WHERE email = ?';
    db.query(sql, [email], (err, results) => {
        if (err) return res.status(500).send('Database error');
        if (results.length === 0) return res.status(401).send('Email not found');

        const user = results[0];

        bcrypt.compare(password, user.password, (err, isMatch) => {
            if (err) return res.status(500).send('Error checking password');
            if (!isMatch) return res.status(401).send('Invalid credentials');

            const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET || 'secret123', { expiresIn: '1h' });
            res.json({ token });
        });
    });
});

// Middleware to verify token
function verifyToken(req, res, next) {
    const bearerHeader = req.headers['authorization'];
    if (typeof bearerHeader !== 'undefined') {
        const bearer = bearerHeader.split(' ');
        const token = bearer[1];
        jwt.verify(token, process.env.JWT_SECRET || 'secret123', (err, authData) => {
            if (err) return res.sendStatus(403);
            req.user = authData;
            next();
        });
    } else {
        res.sendStatus(403);
    }
}

// Protected dashboard route
app.get('/api/dashboard', verifyToken, (req, res) => {
    res.json({ message: `Welcome to your dashboard, user #${req.user.id}` });
});

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, '..', 'frontend', 'register.html'));
  });
const PORT = 5200;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
