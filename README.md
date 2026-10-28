# 零码密码与证书工具箱

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

浏览器本地运行的国密、密码学、PKI 与证书工具箱。证书、CSR、私钥和输入材料默认只在当前页面内存中处理，不上传，也不写入浏览器持久化存储。

在线使用：[https://crypto.zerocodex.top/](https://crypto.zerocodex.top/)

## 主要能力

- X.509 证书、PKCS#10 CSR、公钥和私钥识别与解析
- SM2、RSA、P-256、P-384 密钥对、CSR、自签证书与 CA 证书链生成
- 证书、CSR、公钥和私钥匹配校验
- ASN.1 DER 结构树、字节偏移、长度和十六进制联动查看
- PEM、DER、Base64、Hex 与 SM2 X/Y/D 格式转换
- SM2 签名验签、加密解密、ZA、KDF 与密钥协商
- SM3、HMAC-SM3、SM4、AES、DES、3DES 与常用 MAC 运算
- PFX/PKCS#12、JKS、CMS/PKCS#7 和加密 PKCS#8 处理
- 网站证书链、TLS 协议、HSTS、HTTP/2、CAA 与 TLCP 检测
- Base64、URL、JSON、摘要、UUID 和安全随机字符串工具
- 国密、RSA、ECC、PKCS、X.509 与后量子算法 OID 字典
- PWA 离线缓存、响应式界面和 Tauri 桌面封装

## 技术栈

- Vue 3、TypeScript、Vite
- Web Crypto、PKI.js、ASN1.js、gmkitx
- Go 静态文件与网站 TLS 检测服务
- Docker、Tauri 2

## 本地开发

环境要求：Node.js 22+、Go 1.24+。

```bash
npm ci
```

启动 Go API：

```bash
go run ./server
```

另开终端启动前端开发服务器：

```bash
npm run dev
```

Vite 会将 `/api` 请求代理到 `http://127.0.0.1:8080`。

## 测试与构建

```bash
npm test
go test ./...
npm run build
```

构建过程会生成独立工具页面、`sitemap.xml`、`robots.txt` 和 `llms.txt`。可通过环境变量覆盖公开站点地址：

```dotenv
VITE_SITE_URL=https://crypto.example.com
```

## Docker 部署

```bash
docker compose up -d --build
```

默认只监听 `127.0.0.1:8088`。可通过环境变量修改监听地址和端口：

```bash
BIND_ADDRESS=0.0.0.0 PORT=8088 docker compose up -d --build
```

生产环境建议通过 Caddy 或 Nginx 提供 HTTPS，示例位于 [`deploy/`](deploy/)。

网站 TLCP 探测需要在运行环境安装 GmSSL 或铜锁，并通过 `GMSSL_BIN` 指定可执行文件。未安装时页面会明确显示“未执行”，不会误判为目标网站不支持国密。

## 桌面版

安装 Rust MSVC 工具链和 Visual Studio C++ Build Tools 后执行：

```bash
npm run desktop:build
```

桌面安装包输出到 `src-tauri/target/release/bundle/`。

## 安全边界

- 浏览器工具默认不上传证书、私钥和输入材料。
- 网站 TLS/TLCP 检测会向服务端提交待检测的公开域名，并固定访问 443 端口。
- 服务端拒绝 IP、内网、保留地址和特殊网络地址，防止检测接口访问内部网络。
- 兼容性算法和自签证书仅适用于迁移、联调与测试，不应直接建立生产信任关系。
- 使用具体版本的 GmSSL、铜锁或硬件密码设备前，请在目标环境完成互操作验证。

安全问题请参阅 [SECURITY.md](SECURITY.md)，不要在公开 Issue 中披露敏感细节。

## 参与贡献

欢迎提交 Issue 和 Pull Request。开始前请阅读 [CONTRIBUTING.md](CONTRIBUTING.md)。

## 许可证

本项目采用 [MIT License](LICENSE)。
