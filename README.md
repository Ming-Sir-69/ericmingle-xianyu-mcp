# EricMingle 闲鱼 MCP

本项目基于 GPL-3.0-only 的 xianyu-mcp-server，保持相同许可。GPL 允许包括商业用途在内的使用；无法另加非商用限制。个人维护者 EricMingle 的使用目的为个人购物，不修改 GPL 权利。维护者已确认沿用上游 GPL，允许遵守该许可证的商业使用。

## 运行

Python 3.12 / POSIX（使用 fcntl），`python -m pip install -r requirements.txt`，然后 `python deploy/xianyu_plus.py`（默认 stdio，`--http` 启用 HTTP；MCP_HOST/MCP_PORT 控制监听，默认 loopback:8000）。自行通过进程环境设置 `.env.example` 中的变量。首次登录和二维码只由本人认证。

`XIANYU_COOKIE_FILE` 指向本人私有文件，运行时设备/风控/浏览器环境状态位于同目录；这些运行数据不在仓库中。不要提交 Cookie 或二维码。默认可由上游服务完成登录；可选浏览器 SSH 集成需另外配置四个 XIANYU_BROWSER_* 变量及受限命令、known_hosts、密钥、凭据同步；本仓库不含私有网关、SSH 密钥、同步服务或 OAuth 配置。

Docker 仅提供 stdio 打包模板：`docker build -t ericmingle-xianyu-mcp .`，`docker run --rm -i --env-file .env -v mcp-xianyu-data:/app/data ericmingle-xianyu-mcp`。已有生产部署未修改，模板尚未在 NAS 进行部署验证。

扩展保留收藏、登录、固定设备身份、风控冷却、HTTP/聊天等待时限等能力。买卖操作均取决于上游工具和账号权限；本轮不进行下单支付、真实商家消息或生产改动。离线合同通过不能替代真实站点验收。

`python -m unittest discover -s tests -v` 验证离线合同（缺上游依赖会明确跳过集成测试）；`python scripts/scan_public.py .` 检查分发边界。

## 致谢与许可

[DoLovya/xianyu-mcp-server](https://github.com/DoLovya/xianyu-mcp-server)，Copyright (C) 2026 Huan Zhang，GPL-3.0-only；[DoLovya/pyxianyu](https://github.com/DoLovya/pyxianyu) 为底层运行依赖。保留上游 LICENSE 通告与官方 GPL 完整文本，见 NOTICE.md、LICENSE、licenses/。
