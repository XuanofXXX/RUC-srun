# 人民大学校园网自动认证脚本

基于深澜(Srun)认证系统的逆向工程实现，用于人民大学校园网的自动认证、状态监控和保活功能。

## 🚀 快速开始

### 1. 安装依赖

#### Option1 
```bash
pip install requests PyYAML
```

#### Option2 
```bash
uv sync
```

### 2. 配置凭据
**方式一：环境变量（推荐）**
```bash
export SRUN_USERNAME="你的学号"
export SRUN_PASSWORD="你的密码"
```

**方式二：配置文件**
```bash
cp config.example.yaml config.yaml
# 编辑 config.yaml 填入你的凭据
```

### 3. 使用脚本
```bash
# 检查状态并自动登录
python main.py

# 仅查看状态
python main.py status

# 保活模式（推荐用于服务器/NAS)
python main.py keep-alive
```

## 📋 功能特性

- ✅ **自动认证** - 检测离线状态并自动登录
- 📊 **状态监控** - 显示流量使用情况和余额信息
- 🔄 **保活模式** - 定时检查并自动重连
- 📝 **详细日志** - 完整的认证过程记录
- 🔒 **安全配置** - 支持环境变量和配置文件

## 🛡️ 安全说明

- **凭据保护**：绝不在代码中硬编码密码
- **版本控制**：敏感文件已加入 `.gitignore`
- **开源友好**：移除了所有个人信息

## 📄 许可证

本项目采用 [MIT License](LICENSE) 开源许可证。

**免责声明**：
- 仅用于教育和研究目的
- 请遵守相关法律法规和学校网络使用政策
- 使用本软件所产生的任何后果由使用者自行承担

## 🤝 贡献

欢迎提交 Issue 和 Pull Request！
