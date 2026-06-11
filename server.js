const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

const app = express();
app.use(express.json());

// In-memory storage (data reset on server restart)
let users = [];
let tasks = [];
let nextUserId = 1;
let nextTaskId = 1;
const JWT_SECRET = 'mySecretKey';

function verifyToken(req, res, next) {
  const authHeader = req.header('Authorization');
  if (!authHeader) return res.status(401).json({ message: 'No token' });
  const token = authHeader.replace('Bearer ', '');
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.userId = decoded.userId;
    next();
  } catch (err) {
    res.status(401).json({ message: 'Invalid token' });
  }
}

app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ message: 'Email and password required' });
    if (users.find(u => u.email === email)) return res.status(400).json({ message: 'User exists' });
    const hashed = await bcrypt.hash(password, 10);
    const user = { id: nextUserId++, email, passwordHash: hashed };
    users.push(user);
    const token = jwt.sign({ userId: user.id }, JWT_SECRET);
    res.status(201).json({ token, user: { id: user.id, email } });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = users.find(u => u.email === email);
    if (!user) return res.status(400).json({ message: 'Invalid credentials' });
    const valid = await bcrypt.compare(password, user.passwordHash);
    if (!valid) return res.status(400).json({ message: 'Invalid credentials' });
    const token = jwt.sign({ userId: user.id }, JWT_SECRET);
    res.json({ token, user: { id: user.id, email } });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.post('/api/tasks', verifyToken, (req, res) => {
  try {
    const { title, description, status } = req.body;
    if (!title) return res.status(400).json({ message: 'Title required' });
    const task = {
      id: nextTaskId++,
      userId: req.userId,
      title,
      description: description || '',
      status: status === 'completed' ? 'completed' : 'pending',
      createdAt: new Date()
    };
    tasks.push(task);
    res.status(201).json(task);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.get('/api/tasks', verifyToken, (req, res) => {
  try {
    let userTasks = tasks.filter(t => t.userId === req.userId);
    if (req.query.status === 'pending' || req.query.status === 'completed') {
      userTasks = userTasks.filter(t => t.status === req.query.status);
    }
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const start = (page - 1) * limit;
    const paginated = userTasks.slice(start, start + limit);
    res.json({
      tasks: paginated,
      total: userTasks.length,
      page,
      pages: Math.ceil(userTasks.length / limit)
    });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.get('/api/tasks/:id', verifyToken, (req, res) => {
  try {
    const task = tasks.find(t => t.id === parseInt(req.params.id) && t.userId === req.userId);
    if (!task) return res.status(404).json({ message: 'Task not found' });
    res.json(task);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.put('/api/tasks/:id', verifyToken, (req, res) => {
  try {
    const task = tasks.find(t => t.id === parseInt(req.params.id) && t.userId === req.userId);
    if (!task) return res.status(404).json({ message: 'Task not found' });
    if (req.body.title !== undefined) task.title = req.body.title;
    if (req.body.description !== undefined) task.description = req.body.description;
    if (req.body.status !== undefined) task.status = req.body.status;
    res.json(task);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.delete('/api/tasks/:id', verifyToken, (req, res) => {
  try {
    const index = tasks.findIndex(t => t.id === parseInt(req.params.id) && t.userId === req.userId);
    if (index === -1) return res.status(404).json({ message: 'Task not found' });
    tasks.splice(index, 1);
    res.json({ message: 'Task deleted' });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

const PORT = 5000;
app.listen(PORT, () => console.log(`Server running on http://localhost:5000`));