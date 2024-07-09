// Servidor Express simples com demonstrações de vulnerabilidades e mitigações
const express = require('express');
const bodyParser = require('body-parser');
const sqliteDb = require('better-sqlite3')('database.sqlite');
const bcrypt = require('bcrypt');
const helmet = require('helmet');
const xss = require('xss');

const app = express();

// Configurações de segurança básicas
app.use(helmet());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

// Configuração inicial do banco de dados
sqliteDb.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT
  );
  CREATE TABLE IF NOT EXISTS posts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    content TEXT,
    FOREIGN KEY (user_id) REFERENCES users(id)
  );
`);

// 1. Demonstração de Quebra de Controle de Acesso (A01:2021)
app.get('/user/:id', (req, res) => {
  // Vulnerável: Não verifica se o usuário tem permissão para acessar os dados
  const user = sqliteDb.prepare('SELECT * FROM users WHERE id = ?').get(req.params.id);
  res.json(user);
});

// Mitigação: Implementar verificação de autenticação e autorização
function authMiddleware(req, res, next) {
  // Simples middleware de autenticação (deve ser mais robusto em produção)
  if (req.headers.authorization === 'Bearer valid_token') {
    next();
  } else {
    res.status(401).json({ error: 'Não autorizado' });
  }
}

app.get('/user/:id/secure', authMiddleware, (req, res) => {
  const user = sqliteDb.prepare('SELECT id, username FROM users WHERE id = ?').get(req.params.id);
  res.json(user);
});

// 2. Demonstração de Falhas Criptográficas (A02:2021)
app.post('/register/insecure', (req, res) => {
  // Vulnerável: Armazena senha em texto plano
  const { username, password } = req.body;
  try {
    sqliteDb.prepare('INSERT INTO users (username, password) VALUES (?, ?)').run(username, password);
    res.json({ success: true });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Mitigação: Usar hash de senha
app.post('/register/secure', async (req, res) => {
  const { username, password } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    sqliteDb.prepare('INSERT INTO users (username, password) VALUES (?, ?)').run(username, hashedPassword);
    res.json({ success: true });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// 3. Demonstração de Injeção (A03:2021)
app.get('/posts/insecure', (req, res) => {
  // Vulnerável a SQL Injection
  const { userId } = req.query;
  const posts = sqliteDb.prepare(`SELECT * FROM posts WHERE user_id = ${userId}`).all();
  res.json(posts);
});

// Mitigação: Usar consultas parametrizadas
app.get('/posts/secure', (req, res) => {
  const { userId } = req.query;
  const posts = sqliteDb.prepare('SELECT * FROM posts WHERE user_id = ?').all(userId);
  res.json(posts);
});

// 4. Demonstração de Design Inseguro (A04:2021)
app.post('/post/insecure', (req, res) => {
  // Vulnerável: Não valida entrada, permitindo XSS
  const { userId, content } = req.body;
  sqliteDb.prepare('INSERT INTO posts (user_id, content) VALUES (?, ?)').run(userId, content);
  res.json({ success: true });
});

// Mitigação: Validar e sanitizar entrada
app.post('/post/secure', (req, res) => {
  const { userId, content } = req.body;
  const sanitizedContent = xss(content);
  sqliteDb.prepare('INSERT INTO posts (user_id, content) VALUES (?, ?)').run(userId, sanitizedContent);
  res.json({ success: true });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Servidor rodando na porta ${PORT}`));
