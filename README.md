# auto_ssl_cert_script
项目提供了一个自动化解决方案，用于从腾讯云获取、更新和管理 SSL 证书，并将其部署到 Nginx 服务器。该系统可以自动检查现有证书的有效期，仅在需要时申请新证书，从而避免不必要的 API 调用和证书申请操作。

## 功能特点

- **自动证书管理**：自动检查、申请、下载和安装 SSL 证书
- **智能更新策略**：仅在证书有效期少于 30 天时更新证书
- **多域名支持**：可同时管理多个域名的证书
- **证书状态检查**：检查本地和腾讯云上的证书状态
- **自动 DNS 验证**：支持 DNS 自动验证方式
- **Nginx 集成**：自动重新加载 Nginx 配置
- **详细日志记录**：提供完整的操作日志

## 系统要求

- Python 3.6+
- 腾讯云账号和 API 密钥
- 腾讯云 SDK: `tencentcloud-sdk-python`
- pyOpenSSL (用于证书有效期检查)
- CentOS 7.6 或其他 Linux 发行版(用于生产环境)

## 安装

1. 克隆此仓库:

```bash
git clone https://github.com/2059674517/auto-ssl-cert.git
cd auto-ssl-cert
```

2. 安装依赖:

```bash
pip install tencentcloud-sdk-python pyopenssl
```

3. 配置脚本:
   - 在`auto_ssl_cert.py`中设置您的腾讯云 API 密钥
   - 配置您的域名和证书路径

## 必须修改的配置

在使用此脚本之前，您**必须**修改以下内容:

### 1. API 凭证 (必须)

在`auto_ssl_cert.py`文件中，找到并替换以下内容:

```python
# 配置部分 (约在第40行)
SECRET_ID = "YOUR_SECRET_ID_HERE"  # 替换为您的腾讯云SecretId
SECRET_KEY = "YOUR_SECRET_KEY_HERE"  # 替换为您的腾讯云SecretKey
```

### 2. 区域设置 (必须)

找到并修改腾讯云区域设置:

```python
# 主函数中 (约在第540行)
client = ssl_client.SslClient(cred, "your-region-here", client_profile)  # 替换为您的区域，如 ap-guangzhou
```

### 3. 域名配置 (必须)

修改域名列表以匹配您自己的域名:

```python
# 域名配置部分 (约在第550行)
domains = [
    {
        "domain": "example.com",  # 替换为您的域名
        "cert_dir": "/etc/nginx/ssl/example.com_nginx",  # 替换为您的证书目录
        "cert_path": "/etc/nginx/ssl/example.com_nginx/example.com_bundle.crt",
        "key_path": "/etc/nginx/ssl/example.com_nginx/example.com.key",
        "pem_path": "/etc/nginx/ssl/example.com_nginx/example.com_bundle.pem",
        "csr_path": "/etc/nginx/ssl/example.com_nginx/example.com.csr"
    },
    # 添加更多域名...
]
```

### 4. Nginx 路径 (必须)

修改 Nginx 重载命令以匹配您的服务器配置:

```python
# reload_nginx 函数中 (约在第500行)
methods = [
    "/path/to/nginx/binary -t && /path/to/nginx/binary -s reload"  # 替换为您的Nginx路径
]
```

## 使用方法

### 手动运行

```bash
python3 auto_ssl_cert.py
```

### 自动定时运行

使用 crontab 定时每天运行 auto_ssl_cert.sh
示例：1 1 \* \* \* /opt/script/auto_ssl_cert.sh

```bash
#!/bin/bash
# 运行SSL证书更新脚本
python3 /path/to/auto_ssl_cert.py
```

设置执行权限:

```bash
chmod +x auto_ssl_cert.sh
```

添加到 crontab，每 3 天运行一次:

```bash
# 编辑crontab
crontab -e

# 添加以下行
0 3 */3 * * /path/to/auto_ssl_cert.sh >> /var/log/ssl_renewal.log 2>&1
```

## 工作原理

该系统按照以下流程工作:

1. **检查本地证书**:

   - 检查本地证书文件是否存在
   - 如果存在，验证其有效期是否超过 30 天
   - 如果证书有效，跳过后续步骤

2. **检查腾讯云证书**:

   - 如果本地证书无效或不存在，检查腾讯云上的证书
   - 使用多种搜索策略查找匹配的证书
   - 如果找到有效证书(有效期>30 天)，下载并安装

3. **申请新证书**:

   - 如果本地和腾讯云上都没有有效证书，申请新证书
   - 进行 DNS 验证
   - 等待证书颁发
   - 下载并安装新证书

4. **重新加载 Nginx**:
   - 如果有任何证书被更新，重新加载 Nginx 配置

## 日志

脚本会生成详细的日志文件`ssl_cert_auto.log`，记录所有操作和可能的错误。

## 故障排除

如果遇到问题，请检查:

1. API 密钥是否正确
2. 域名配置是否正确
3. Nginx 路径是否正确
4. 日志文件中的错误信息
5. 确保添加了 `DvAuthMethod` 参数，这是腾讯云 API 必需的

## 安全注意事项

- **不要在公共仓库中提交包含真实 API 密钥的代码**
- 确保证书文件具有适当的权限设置
- 定期检查日志以确保系统正常运行
- 考虑使用环境变量或配置文件存储 API 密钥，而不是硬编码在脚本中

## 许可证

[MIT License](LICENSE)

## 贡献

欢迎提交问题报告和拉取请求！
