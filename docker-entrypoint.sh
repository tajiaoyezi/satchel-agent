#!/bin/sh
# 节点容器入口：默认拒默认桥接网络，确保配置/状态目录权限，支持已挂载配置或环境变量自动 join 后启动 satchel-agent run。
set -eu

if [ "$#" -eq 0 ]; then
	set -- run
fi

# 非 run 子命令（如 --version / --help / __verify / join）直接交由 satchel-agent 执行。
if [ "$1" != "run" ]; then
	exec /usr/local/bin/satchel-agent "$@"
fi

check_host_network() {
	if [ "${SATCHEL_ALLOW_BRIDGE:-0}" = "1" ] || [ ! -r /proc/net/route ]; then
		return 0
	fi
	default_iface=""
	while read -r iface dest _rest; do
		if [ "$dest" = "00000000" ]; then
			default_iface="$iface"
			break
		fi
	done < /proc/net/route

	if [ -z "$default_iface" ]; then
		return 0
	fi

	idx_file="/sys/class/net/${default_iface}/ifindex"
	link_file="/sys/class/net/${default_iface}/iflink"
	if [ -r "$idx_file" ] && [ -r "$link_file" ]; then
		idx="$(cat "$idx_file")"
		link="$(cat "$link_file")"
		if [ "$idx" != "$link" ]; then
			echo "错误：satchel-agent 容器检测到默认网关网卡 (${default_iface}) 处于容器桥接网络，请改用 --network host 启动（测试环境可设置 SATCHEL_ALLOW_BRIDGE=1）" >&2
			exit 1
		fi
	fi
}

check_host_network

cfg_path="${SATCHEL_CONFIG:-/etc/satchel-agent/config.yaml}"
has_config_flag=0
prev=""
for arg in "$@"; do
	if [ "$prev" = "--config" ] || [ "$prev" = "-config" ]; then
		cfg_path="$arg"
		has_config_flag=1
		break
	fi
	case "$arg" in
		--config=*|-config=*)
			cfg_path="${arg#*=}"
			has_config_flag=1
			break
			;;
	esac
	prev="$arg"
done

cfg_dir="$(dirname "$cfg_path")"
mkdir -p "$cfg_dir" /var/lib/satchel-agent
chmod 0700 "$cfg_dir"
chmod 0755 /var/lib/satchel-agent

run_join() {
	set -- \
		--master-url "$SATCHEL_MASTER_URL" \
		--token "$SATCHEL_TOKEN" \
		--master-key "$SATCHEL_MASTER_KEY" \
		--mode "${SATCHEL_MODE:-auto}" \
		--config "$cfg_path"
	if [ -n "${SATCHEL_AGENT_TOKEN:-}" ]; then
		set -- "$@" --agent-token "$SATCHEL_AGENT_TOKEN"
	fi
	if [ -n "${SATCHEL_PULL_TOKEN:-}" ]; then
		set -- "$@" --pull-token "$SATCHEL_PULL_TOKEN"
	fi
	if [ -n "${SATCHEL_LISTEN_PORT:-}" ]; then
		set -- "$@" --listen-port "$SATCHEL_LISTEN_PORT"
	fi
	if [ -n "${SATCHEL_PULL_PORT:-}" ]; then
		set -- "$@" --pull-port "$SATCHEL_PULL_PORT"
	fi
	/usr/local/bin/satchel-agent join "$@" >&2
}

if [ ! -f "$cfg_path" ]; then
	if [ -n "${SATCHEL_MASTER_URL:-}" ] && [ -n "${SATCHEL_TOKEN:-}" ] && [ -n "${SATCHEL_MASTER_KEY:-}" ]; then
		run_join
	else
		echo "错误：未找到配置文件 ${cfg_path}；请挂载配置文件，或提供 SATCHEL_MASTER_URL、SATCHEL_TOKEN 与 SATCHEL_MASTER_KEY 自动配对" >&2
		exit 1
	fi
fi

if [ "$has_config_flag" -eq 0 ] && [ -n "${SATCHEL_CONFIG:-}" ]; then
	set -- "$@" --config "$cfg_path"
fi

exec /usr/local/bin/satchel-agent "$@"
