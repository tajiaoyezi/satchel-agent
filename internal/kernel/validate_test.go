package kernel_test

import (
	"fmt"
	"testing"

	"github.com/satchel/satchel-agent/internal/kernel"
	kt "github.com/satchel/satchel-agent/pkg/kerneltest"
)

func TestValidateNonDisruptiveAndChecks(t *testing.T) {
	// 启动真实运行中的内核与客户端连接，确认 Validate 期间连接零中断且不抢占同一端口。
	s := kt.StartServer(t)
	c := kt.StartClient(t, s.Target(), kt.UserA, kt.InVLESS)
	kt.Echo(t, c, 1)

	// 1. 校验与当前运行中内核使用完全相同端口的配置（验证 Validate 绝不绑定端口）。
	tags, err := kernel.Validate(s.Config())
	if err != nil {
		t.Fatalf("Validate 合法配置不应失败：%v", err)
	}
	if len(tags) != 2 || tags[0] != kt.InVLESS || tags[1] != kt.InHY2 {
		t.Fatalf("Validate 返回入站列表不对：%v", tags)
	}

	// 2. 未知字段被拒。
	if _, err := kernel.Validate([]byte(`{"log":{"level":"warn"},"unknown_top_key":123,"outbounds":[{"type":"direct","tag":"direct"}]}`)); err == nil {
		t.Fatal("未知顶层字段应被拒绝")
	}

	// 3. 语法错误被拒。
	if _, err := kernel.Validate([]byte(`{"log":`)); err == nil {
		t.Fatal("语法错误应被拒绝")
	}

	// 4. 重复入站 tag 被拒。
	dupCfg := []byte(`{
		"log":{"level":"warn"},
		"inbounds":[
			{"type":"direct","tag":"dup","listen":"127.0.0.1","listen_port":19001},
			{"type":"direct","tag":"dup","listen":"127.0.0.1","listen_port":19002}
		],
		"outbounds":[{"type":"direct","tag":"direct"}]
	}`)
	if _, err := kernel.Validate(dupCfg); err == nil {
		t.Fatal("重复入站 tag 应被拒绝")
	}

	// 5. 缺失磁盘 TLS 证书文件被拒。
	missingCert := []byte(fmt.Sprintf(`{
		"log":{"level":"warn"},
		"inbounds":[{
			"type":"vless","tag":"tls-in","listen":"127.0.0.1","listen_port":19003,
			"users":[{"name":"u1","uuid":"6a4f1c2e-3b5d-4e7f-8a9b-0c1d2e3f4a5b"}],
			"tls":{"enabled":true,"certificate_path":"/no/such/cert.pem","key_path":"/no/such/key.pem"}
		}],
		"outbounds":[{"type":"direct","tag":"direct"}]
	}`))
	if _, err := kernel.Validate(missingCert); err == nil {
		t.Fatal("缺失磁盘 TLS 证书应被拒绝")
	}

	// 6. 校验全部结束后原有客户端连接依旧畅通无阻。
	kt.Echo(t, c, 1)
	kt.EchoUDP(t, c, 2)
}
