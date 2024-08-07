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
const SECRET_KEY = process.env.SECRET_KEY || 'your_secret_key';
const USERNAME = process.env.USERNAME || 'user';
const PASSWORD = process.env.PASSWORD || 'pass';
app.use(bodyParser.json());

const pool = mysql.createPool({
  host: DB_HOST,
  port: DB_PORT,
  user: DB_USER,
  password: DB_PASS,
  database: DB_NAME,
});


// 身份验证中间件
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (token == null) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid token' });
    }
    req.user = user;
    next();
  });
}

// 处理POST请求，将数据写入指定的数据库表
app.post('/api/post/:tableName', authenticateToken, (req, res) => {
  const requestData = req.body; // 获取请求的数据
  let tableName = req.params.tableName; // 获取表名

  // 验证表名是否只包含字母、数字和下划线（防止SQL注入攻击）
  const isValidTableName = /^[a-zA-Z0-9_]+$/.test(tableName);

  if (!isValidTableName) {
    return res.status(400).json({ error: 'Invalid table name' });
  }

  // 在连接池中获取一个连接
  pool.getConnection((err, connection) => {
    if (err) {
      console.error('Error connecting to database: ', err);
      return res.status(500).json({ error: 'Failed to connect to database' });
    }

    // 执行数据库插入操作
    connection.query(`INSERT INTO ${tableName} SET ?`, requestData, (err, results) => { //数据写入指定表
      connection.release(); // 释放连接

      if (err) {
        console.error('Error inserting data into database: ', err);
        return res.status(500).json({
          error: 'Failed to insert data into database',
          msg: err
        });
      }

      return res.status(200).json({ message: 'Data inserted successfully' });
    });
  });
});

// 处理GET请求，从指定的数据库表中获取数据
app.get('/api/get/:tableName', authenticateToken, (req, res) => {
  let tableName = req.params.tableName; // 获取表名

  // 验证表名是否只包含字母、数字和下划线（防止SQL注入攻击）
  const isValidTableName = /^[a-zA-Z0-9_]+$/.test(tableName);

  if (!isValidTableName) {
    return res.status(400).json({ error: 'Invalid table name' });
  }

  // 在连接池中获取一个连接
  pool.getConnection((err, connection) => {
    if (err) {
      console.error('Error connecting to database: ', err);
      return res.status(500).json({ error: 'Failed to connect to database' });
    }

    // 执行数据库查询操作
    connection.query(`SELECT * FROM ${tableName}`, (err, results) => {
      connection.release(); // 释放连接

      if (err) {
        console.error('Error querying data from database: ', err);
        return res.status(500).json({
          error: 'Failed to query data from database',
          msg: err
        });
      }

      return res.status(200).json(results);
    });
  });
});

// 获取acc
app.get('/api/getacc', authenticateToken, (req, res) => {
  // 在连接池中获取一个连接
  pool.getConnection(async (err, connection) => {
    if (err) {
      console.error('Error connecting to database: ', err);
      return res.status(500).json({ error: 'Failed to connect to database' });
    }

    try {
      await connection.promise().beginTransaction();

      // 锁定表
      // await connection.promise().query('LOCK TABLES `unchecked` WRITE, `checking` WRITE');

      // 随机选择一条checkcount小于3的记录
      const [rows] = await connection.promise().query(
        'SELECT `id`, `account`, `checkcount` FROM `unchecked` WHERE `checkcount` < 3 ORDER BY RAND() LIMIT 1 FOR UPDATE'
      );

      if (rows.length === 0) {
        throw new Error('No records found');
      }

      const { id, account, checkcount } = rows[0];

      // 插入到checking表
      await connection.promise().query(
        'INSERT INTO `checking` (`account`, `checkcount`, `starttime`) VALUES (?, ?, NOW())',
        [account, checkcount]
      );

      // 从unchecked表删除该记录
      await connection.promise().query('DELETE FROM `unchecked` WHERE `id` = ?', [id]);

      // 解锁表
      // await connection.promise().query('UNLOCK TABLES');

      // 提交事务
      await connection.promise().commit();

      // 返回account的值
      res.json({ account });

    } catch (error) {
      // 如果出现错误，回滚事务，并解锁表
      await connection.promise().rollback();
      // await connection.promise().query('UNLOCK TABLES');
      console.error('Transaction error: ', error);
      // 如果从错误信息是No records found，则返回404状态码
      if (error.message === 'No records found') {
        return res.status(404).json({ error: 'No records found' });
      } else {
        return res.status(500).json({
          error: 'Transaction failed',
          msg: error.message
        });
      }
    } finally {
      // 释放连接
      connection.release();
    }
  });
});

// 提交acc
app.post('/api/postacc/:tableName', authenticateToken, (req, res) => {
  let tableName = req.params.tableName; // 获取表名
  const { account } = req.body; // 获取请求的数据中的account

  // 验证表名是否只包含字母、数字和下划线（防止SQL注入攻击）
  const isValidTableName = /^[a-zA-Z0-9_]+$/.test(tableName);

  if (!isValidTableName) {
    return res.status(400).json({ error: 'Invalid table name' });
  }

  // 在连接池中获取一个连接
  pool.getConnection(async (err, connection) => {
    if (err) {
      console.error('Error connecting to database: ', err);
      return res.status(500).json({ error: 'Failed to connect to database' });
    }

    try {
      await connection.promise().beginTransaction();

      // 检查account是否存在于checking表中
      const [rows] = await connection.promise().query(
        'SELECT `account` FROM `checking` WHERE `account` = ? FOR UPDATE',
        [account]
      );

      if (rows.length === 0) {
        throw new Error('Account not found in checking');
      }

      if (tableName !== 'delete') {
        // 将account插入到指定的表中
        await connection.promise().query(
          `INSERT INTO \`${tableName}\` (\`account\`) VALUES (?)`,
          [account]
        );
      }

      // 从checking表删除该account
      await connection.promise().query(
        'DELETE FROM `checking` WHERE `account` = ?',
        [account]
      );

      // 提交事务
      await connection.promise().commit();

      return res.status(200).json({ message: 'Data inserted successfully' });

    } catch (error) {
      // 如果出现错误，回滚事务
      await connection.promise().rollback();
      console.error('Transaction error: ', error);
      if (error.message === 'Account not found in checking') {
        return res.status(404).json({ error: 'Account not found in checking' });
      } else {
        return res.status(500).json({
          error: 'Transaction failed',
          msg: error
        });
      }
    } finally {
      // 释放连接
      connection.release();
    }
  });
});

// 处理POST请求，用户登录验证
app.post('/api/login', (req, res) => {
  const { user, pass } = req.body;

  // 在实际应用中，你可以根据自己的用户存储方式（如数据库）来验证凭证
  if (user === USERNAME && pass === PASSWORD) {
    // 用户凭证验证成功
    const user = { id: 1, username: USERNAME };
    const token = jwt.sign(user, SECRET_KEY);

    return res.status(200).json({ token: token });
  } else {
    // 用户凭证验证失败
    return res.status(401).json({ error: 'Invalid credentials' });
  }
});

// 启动服务器监听指定的端口
app.listen(PORT, () => {
  console.log('Server is running on port ' + PORT);
});
