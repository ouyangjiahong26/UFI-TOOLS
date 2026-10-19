const express = require('express');
const { createProxyMiddleware } = require('http-proxy-middleware');
const path = require('path');

const app = express();

app.use('/api', createProxyMiddleware({
  target: 'http://192.168.0.1:2333/api',
  changeOrigin: false,
}));

app.use('/', express.static(path.join(__dirname, '/public')));

// 只绑定回环地址，避免局域网内其他主机借本代理直接操作设备
app.listen(3000, '127.0.0.1', () => {
  console.log('Dev server running at http://localhost:3000');
});