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

## 内核的编译标签

内核是以 Go module 依赖引用的官方 sing-box（版本钉在 `go.mod`，不 fork、不加 `replace`）。sing-box 的 Hysteria2 建在 QUIC 上，要带编译标签 `with_quic` 才会编进去，不带时 Hysteria2 入站启动会报 `QUIC is not included in this build`。所以 vet、build、test 都带上它：

```sh
go vet -tags with_quic ./...
go test -tags with_quic ./...
```

`internal/kernel` 里有 M2 证伪点的五项测试（按凭据限速、识别连接、踢线、三维计数、重启基线，测试名都以 `TestFalsification` 开头）。默认跑快速版：时间窗与数据量都缩小，只查行为对不对。结论以完整版为准，完整版多带一个标签 `falsification`：

```sh
go test -tags with_quic,falsification -run Falsification -timeout 30m -v ./...
```

测得的数字以「结果」开头打在 `-v` 的输出里。CI 在推送到 main 与手动触发时跑完整版（`.github/workflows/ci.yml` 的 `falsification` job），不挡普通提交的检查。

## 仓库关系

六个仓库的分工见技术方案第 02 章：`satchel`（主控、CLI、MCP、skills）、`satchel-agent`（本仓库）、`satchel-web`（网页前端）、`satchel-plugins`（订阅解析库、家用测速端）、`satchel-probe`（外置探针）、`satchel-docs`（文档站）。

## 许可证

GPL-3.0，见 LICENSE。
