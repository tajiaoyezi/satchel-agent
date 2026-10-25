# satchel-agent

Satchel（百宝袋）的节点守护进程，装在每台被管理的服务器上，对应 mmwx 的 mmw-agent。内核是内嵌的 sing-box；与主控 `satchel` 的通信、配对、配置下发按技术方案第 06 章。

**状态：M2「节点与内核」进行中：已有配对与通道（websocket 模式、心跳、在线状态）；`run` 照本地的 `kernel.json` 起内核，主控经通道临时限速、踢线、列连接、拉流量快照（m2-03）。**

与主控共用的代码（securechan、xrpc、资源类型）放在 `satchel` 仓库的 `pkg/` 下，本仓库以 Go module 依赖引用，不复制第二份（技术方案第 02 章）。go.mod 用 `replace github.com/satchel/satchel => ../satchel` 指向同级检出的主控仓库：本地把两个仓库放在同一个目录下；CI 与发布线把主控仓库检出在旁边，钉在仓库根 `.satchel-ref` 写的提交上，主控的 `pkg/` 变了就改这个文件。

## 接入主控

一般不用手工做：在主控上 `satchel server add <名字>` 加服务器，再用 `satchel server install-command <名字>` 取一键安装命令（主控地址要是 https），在节点上用 root 运行。安装脚本会下载并验签 satchel-agent、执行 `join` 写配置、装好 systemd 或 OpenRC 服务。

手工接入时两步：

```sh
satchel-agent join --master-url https://panel.example.com --token <token> --master-key <主控公钥> --mode websocket
satchel-agent run
```

- `join` 把四项写进 `/etc/satchel-agent/config.yaml`（`--config` 可改），文件权限 0600、目录 0700；主控地址必须是 https，主控公钥必须能解析，这一版连接模式只支持 websocket，任何一项不合法都不写。
- `run` 按配置连 `<主控地址>/api/remote/ws`：先用主控公钥验主控的握手签名（验不过就断开，不发 token），再凭 token 认证，之后按主控给的间隔发心跳。断线从 5 秒起翻倍重连、封顶 5 分钟；认证失败等得更久，token 无效连续 10 次睡 30 分钟。收到 SIGTERM 或 SIGINT 时先断开主控、再停内核，退出码 0。

## 内核配置与限速状态

配置文件所在的目录（默认 `/etc/satchel-agent/`）里还有两个文件：

- `kernel.json`：一份 sing-box 配置，由人或测试环境放进去（主控下发入站配置要等后面的入站管理）。有它 `run` 就照它起内核，没有就只连主控；它解析不了或内核起不来时只记日志、照常连主控。改了要重启 satchel-agent 才生效。主控命令里的入站名就是这里 `inbounds[].tag`，凭据名是入站里用户的 `name`。
- `limiter-state.json`：每份「入站 × 凭据」的三份限速来源（静态、主控临时、节点规则临时）与截止时间，由 agent 自己写（权限 0600），每次改动都写；`run` 启动时先把它重放进 tracker 再起内核，已过期的丢掉。主控失联时已下发的值照常生效、按自己的截止时间到期。

截止时间是主控按自己的时钟算出的绝对时间，节点要开 NTP，否则到期会提前或推后。

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
