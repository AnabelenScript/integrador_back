const mysql = require('mysql2');
const bcrypt = require('bcrypt');
//Cargar las variables de entorno
require('dotenv').config();
// Configuración de la conexión a la base de datos MySQL
const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_DATABASE
});

// Conexión a la base de datos
db.connect((err) => {
  if (err) {
    throw err;
  }
  console.log('Users-Conexión a la BD establecida');
});

// Obtener todos los elementos
exports.getAllUsers = (req, res) => {
  db.query('SELECT * FROM users', (err, result) => {
    if (err) {
      res.status(500).send('Error al obtener los elementos');
      throw err;
    }
    res.json(result);
  });
};

// Agregar un nuevo elemento
// Ojo aquí, para evitar el típico quién fue primero el huevo o la gallina
// Nuestro addUser sin autenticación debe considerar enviar la contraseña hasheada
// Si no se hace así tendrían el problema de que requieren un token para agregar 
// un nuevo usuario con la contraseña hasheada pero al mismo tiempo no pueden iniciar
// sesión si no hashean la contraseña antes de validar.
exports.addUser = (req, res) => {
  const newUser = req.body;
  // Hashear la contraseña antes de guardarla (bcrypt)
  bcrypt.hash(newUser.password, 10, (err, hash) => { // 10 es el número de rondas de hashing
    if (err) {
      res.status(500).send('Error al hashear la contraseña');
      return; // Stop execution if there's an error hashing
    }
    newUser.password = hash;  
    db.query('INSERT INTO users SET ?', newUser, (err, result) => {
      if (err) {
        res.status(500).send('Error al agregar el usuario');
        return; // Stop execution if there's an error inserting
      }
      res.status(201).send('Usuario agregado correctamente');
    });
  });
};

// Actualizar un elemento existente
exports.updateUser = (req, res) => {
  const userId = req.params.id;
  const updatedUser = req.body;
  db.query('UPDATE users SET ? WHERE id = ?', [updatedUser, userId], (err, result) => {
    if (err) {
      res.status(500).send('Error al actualizar el elemento');
      throw err;
    }
    res.send('Elemento actualizado correctamente');
  });
};

// Eliminar un elemento
exports.deleteUser = (req, res) => {
  const userId = req.params.id;
  db.query('DELETE FROM users WHERE id = ?', userId, (err, result) => {
    if (err) {
      res.status(500).send('Error al eliminar el elemento');
      throw err;
    }
    res.send('Elemento eliminado correctamente');
  });
};
