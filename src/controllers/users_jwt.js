const mysql = require('mysql2');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
require('dotenv').config();


const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_DATABASE
});

db.connect((err) => {
  if (err) {
    console.error('Error connecting to the database:', err);
    throw err;
  }
  console.log('UsersJWT-Connection to the database established');
});

exports.login = (req, res) => {
  const { idUsuario, password } = req.body;
  db.query('SELECT * FROM Usuarios WHERE idUsuario = ?', [idUsuario], async (err, result) => {
    if (err) {
      console.error('Error executing query:', err);
      return res.status(500).send('Server error');
    }
    if (result.length === 0) {
      return res.status(401).send('Invalid ');
    }
    const user = result[0];
    console.log(user.password, password)
    // Verificar contraseña (con bcrypt)
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).send('Invalid credentials');
    }
    // Generar JWT
    const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.json({ 
      "mensaje": "Listo",
      token });
  });
};

// Middleware de autenticación
const authenticateJWT = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (authHeader) {
    const token = authHeader.split(' ')[1];
    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
      if (err) {
        return res.sendStatus(403); // Prohibido (token inválido)
      }
      req.user = user;
      next();
    });
  } else {
    res.sendStatus(401); // No autorizado (sin token)
  }
};

// Rutas protegidas con autenticación JWT
exports.getAllUsers = [authenticateJWT, (req, res) => {
  db.query('SELECT * FROM Usuarios', (err, result) => {
    if (err) {
      console.error('Error executing query:', err);
      return res.status(500).send('Error getting users');
    }
    res.json(result);
  });
}];

exports.addUser = (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).send('Email and password are required');
  }

  bcrypt.hash(password, 10, (err, hash) => {
    if (err) {
      console.error('Error hashing password:', err);
      return res.status(500).send('Error hashing password');
    }

    const newUser = { email, password: hash };

    db.query('SELECT COUNT(*) AS userCount FROM Usuarios', (err, result) => {
      if (err) {
        console.error('Error executing count query:', err);
        return res.status(500).send('Error checking user count');
      }

      const userCount = result[0].userCount;
      const newUserId = userCount + 1;

      db.query('INSERT INTO Usuarios (idUsuario, email, password) VALUES (?, ?, ?)', [newUserId, newUser.email, newUser.password], (err, result) => {
        if (err) {
          console.error('Error executing insert query:', err);
          return res.status(500).send('Error adding user');
        }

        // Imprimir el ID del usuario en la consola
        console.log(`Registro exitoso. Este es tu ID de usuario para iniciar sesión: ${newUserId}`);
        
        res.status(201).send('User added successfully');
      });
    });
  });
};





