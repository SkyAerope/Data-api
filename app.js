const express = require('express');
const mysql = require('mysql2');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;
const DB_HOST = process.env.DB_HOST || 'localhost';
const DB_PORT = process.env.DB_PORT || 3306;
const DB_USER = process.env.DB_USER || 'root';
const DB_PASS = process.env.DB_PASS || 'root';
const DB_NAME = process.env.DB_NAME || 'test';
const secretKey = process.env.secretKey || 'your_secret_key';
const username = process.env.user || 'user';
const password = process.env.pass || 'pass';
app.use(bodyParser.json());

const pool = mysql.createPool({
  host: DB_HOST,
  port: DB_PORT,
  user: DB_USER,
  password: DB_PASS,
  database: DB_NAME,
});

// 设置用于签名和验证 JWT 的密钥
//const secretKey = 'your_secret_key';

// 身份验证中间件
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (token == null) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  jwt.verify(token, secretKey, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid token' });
    }
    req.user = user;
    next();
  });
}

// 处理POST请求，将数据写入数据库
app.post('/api/data', authenticateToken, (req, res) => {
  const requestData = req.body; // 获取请求的数据

  // 在连接池中获取一个连接
  pool.getConnection((err, connection) => {
    if (err) {
      console.error('Error connecting to database: ', err);
      return res.status(500).json({ error: 'Failed to connect to database' });
    }

    // 执行数据库插入操作
    connection.query('INSERT INTO success SET ?', requestData, (err, results) => { //数据写入success表
      connection.release(); // 释放连接

      if (err) {
        console.error('Error inserting data into database: ', err);
        return res.status(500).json({ error: 'Failed to insert data into database' });
      }

      return res.status(200).json({ message: 'Data inserted successfully' });
    });
  });
});

app.post('/api/login', (req, res) => {
  const { user, pass } = req.body;

  // 在实际应用中，你可以根据自己的用户存储方式（如数据库）来验证凭证
  if (user === username && pass === password) {
    // 用户凭证验证成功
    const user = { id: 1, username: 'your_username' };
    const token = jwt.sign(user, secretKey);

    return res.status(200).json({ token: token });
  } else {
    // 用户凭证验证失败
    return res.status(401).json({ error: 'Invalid credentials' });
  }
});

// 启动服务器监听指定的端口
app.listen(PORT, () => {
  console.log('Server is running on port 3000');
});
