# Data-API

这是一个使用Node.js和Express编写的API示例，用于将请求的数据写入MySQL数据库。

## 安装

1. 克隆此存储库到本地：

```bash
git clone https://github.com/SkyAerope/Data-api.git
```

2. 进入项目目录：

```bash
cd Data-api
```

3. 安装依赖：

```bash
npm install
```

## 配置
在开始使用API之前，你需要配置环境变量
```bash
cp .env.example .env
micro .env # 使用micro编辑器修改.env文件
```

## 运行
运行以下命令启动服务器：

```bash
npm start
```
服务器将在 `http://localhost:3000` 上运行。

## 使用
### 登录
使用以下示例Python代码登录并获取JSON Web Tokens（JWT）：

```python
import requests

data = {
  "user": "your_username",
  "pass": "your_password"
}

response = requests.post('http://localhost:3000/api/login', json=data)

if response.status_code == 200:
  token = response.json().get('token')
  print('Login successful. Token:', token)
else:
  print('Login failed. Error:', response.json().get('error'))
  ```
请确保将 your_username 和 your_password 替换为实际的用户名和密码。

### 写入数据
使用以下示例Python代码在获取到JWT后将数据写入数据库：

```python
import requests

data = {
  "name": "John",
  "age": 30,
  "email": "john@example.com"
}

headers = {
  'Authorization': 'Bearer <token>'
}

response = requests.post('http://localhost:3000/api/data', json=data, headers=headers)

if response.status_code == 200:
  print('Data inserted successfully')
else:
  print('Failed to insert data into database. Error:', response.json().get('error'))
```
确保将 <token> 替换为之前获取到的的JWT令牌。

## API端点
 - `POST /api/login`: 用户登录并获取JWT令牌。
 - `POST /api/data`: 将数据写入数据库。
## 注意事项
- 请确保在使用API之前将数据库连接信息正确配置到项目中。
- 在发送请求之前，根据实际情况修改Python示例代码中的URL、用户名、密码和数据对象。
- 请使用适当的方式来保护和管理JWT令牌，以确保安全性。
- 此示例提供了基本的功能和结构，你可以根据自己的需求进行扩展和定制。