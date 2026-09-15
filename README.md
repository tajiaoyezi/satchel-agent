# satchel-agent

Satchel（百宝袋）的节点守护进程，装在每台被管理的服务器上，对应 mmwx 的 mmw-agent。内核是内嵌的 sing-box；与主控 `satchel` 的通信、配对、配置下发按技术方案第 06 章。

**状态：M0 骨架阶段，只有空壳，从 M2「节点与内核」开始填代码。**

与主控共用的代码（securechan、xrpc、资源类型）放在 `satchel` 仓库的 `pkg/` 下，本仓库以 Go module 依赖引用固定版本，不复制第二份（技术方案第 02 章）。

## 发布

打 tag `v*` 触发 `.github/workflows/release.yml`：构建后签名 job 停在受保护环境 `release-signing` 等仓库拥有者批准，签名程序检出 `satchel` 仓库的 `tools/sign` 来跑（一把发布密钥签三个二进制），产物与 `.sig`、`checksums.txt` 挂到 GitHub Release。

## 构建

```sh
go build ./cmd/satchel-agent
./satchel-agent --version
```

## 仓库关系

六个仓库的分工见技术方案第 02 章：`satchel`（主控、CLI、MCP）、`satchel-agent`（本仓库）、`satchel-web`（网页前端）、`satchel-plugins`（订阅解析库、家用测速端、skills）、`satchel-probe`（外置探针）、`satchel-docs`（文档站）。

## 许可证

GPL-3.0，见 LICENSE。
