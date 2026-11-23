package control

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/satchel/satchel/pkg/xrpc"

	"github.com/satchel/satchel-agent/internal/diag"
	"github.com/satchel/satchel-agent/internal/execctl"
	"github.com/satchel/satchel-agent/internal/updater"
)

func TestDiagAndExecControlMethods(t *testing.T) {
	dir := t.TempDir()
	execs := &updater.ExecCounter{}
	diagEng := diag.New(diag.Options{
		ConfigDir: dir,
		InDocker:  func() bool { return false },
		RunCmd: func(_ context.Context, name string, args ...string) ([]byte, error) {
			return []byte("ok"), nil
		},
	})
	execMgr := execctl.New(execctl.Options{
		AllowExec: true,
		DataDir:   dir,
		Execs:     execs,
	})
	t.Cleanup(func() { execMgr.Shutdown() })

	methods := Methods(Deps{
		ConfigDir: dir,
		Diag:      diagEng,
		Exec:      execMgr,
	})

	// diag.run 单项
	rawDiag, _ := json.Marshal(xrpc.DiagRunParams{Items: []string{xrpc.DiagItemClock, xrpc.DiagItemSpeedtest}})
	rep := methods.Serve(context.Background(), xrpc.Call{ID: "1", Method: xrpc.MethodDiagRun, Params: rawDiag})
	if rep.Error != nil {
		t.Fatalf("diag.run 失败：%+v", rep.Error)
	}
	var dr xrpc.DiagRunResult
	if err := json.Unmarshal(rep.Result, &dr); err != nil || len(dr.Items) != 2 {
		t.Fatalf("diag.run 结果解析失败：err=%v items=%d", err, len(dr.Items))
	}

	// diag.run 未知项应报 bad_params
	rawBad, _ := json.Marshal(xrpc.DiagRunParams{Items: []string{"nope"}})
	rep = methods.Serve(context.Background(), xrpc.Call{ID: "2", Method: xrpc.MethodDiagRun, Params: rawBad})
	if rep.Error == nil || rep.Error.Code != xrpc.CodeBadParams {
		t.Fatalf("未知诊断项应报 bad_params，得到 %+v", rep.Error)
	}

	// exec.start → exec.status
	rawStart, _ := json.Marshal(xrpc.ExecStartParams{JobID: "ctrl-j1", Command: "printf hello-ctrl", TimeoutMS: 5000})
	rep = methods.Serve(context.Background(), xrpc.Call{ID: "3", Method: xrpc.MethodExecStart, Params: rawStart})
	if rep.Error != nil {
		t.Fatalf("exec.start 失败：%+v", rep.Error)
	}

	deadline := time.Now().Add(5 * time.Second)
	for {
		rawSt, _ := json.Marshal(xrpc.ExecStatusParams{JobID: "ctrl-j1", Offset: 0})
		srep := methods.Serve(context.Background(), xrpc.Call{ID: "4", Method: xrpc.MethodExecStatus, Params: rawSt})
		if srep.Error != nil {
			t.Fatalf("exec.status 失败：%+v", srep.Error)
		}
		var st xrpc.ExecStatusResult
		if err := json.Unmarshal(srep.Result, &st); err != nil {
			t.Fatal(err)
		}
		if st.Done {
			if st.State != xrpc.ExecStateDone || st.Output != "hello-ctrl" || st.ExitCode != 0 {
				t.Fatalf("exec 终态不对：%+v", st)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("等待 exec 完成超时")
		}
		time.Sleep(20 * time.Millisecond)
	}

	// exec.cancel 对不存在任务幂等返回 canceled=false
	rawCan, _ := json.Marshal(xrpc.ExecCancelParams{JobID: "no-such"})
	rep = methods.Serve(context.Background(), xrpc.Call{ID: "5", Method: xrpc.MethodExecCancel, Params: rawCan})
	var cr xrpc.ExecCancelResult
	if rep.Error != nil || json.Unmarshal(rep.Result, &cr) != nil || cr.Canceled {
		t.Fatalf("未知 job cancel 应返回 canceled=false，得到 err=%+v res=%s", rep.Error, rep.Result)
	}
}
