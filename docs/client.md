# WireGuard-GM 配置生成与客户端接入

本文档说明如何使用仓库内的 `scripts/gen-configs.sh` 一次性生成 WireGuard-GM
（SM2/SM3/SM4）服务端与多个客户端的配置，以及如何在 Linux 和 Windows 上使用
生成的配置接入隧道。

## 1. 生成脚本的作用

`scripts/gen-configs.sh` 负责把「手工敲一堆 `wg-gm genkey`、抄公钥、拼配置文件」
这件容易出错的事自动化：

- 调用 `wg-gm genkey` / `wg-gm pubkey` 为服务端和每个客户端生成 SM2 密钥对；
- 可选地调用 `wg-gm genpsk` 生成一份共享的预共享密钥（PSK）；
- 从 `SERVER_TUN_IP` 推导隧道网段，并按顺序为每个客户端分配隧道地址；
- 输出可直接被 `wg-gm setconf` 应用的 UAPI 格式配置文件；
- 输出 Linux（`up.sh` / `linux-up.sh`）与 Windows（`windows-up.ps1`）的启动脚本。

脚本本身不会修改本机网络，也不会启动任何进程，只生成一个目录。

### 配置文件格式约定

生成的 `*.conf` 使用的是 WireGuard 的
[cross-platform 配置协议](https://www.wireguard.com/xplatform/#configuration-protocol)
（UAPI）格式，而不是 `wg-quick` 的 INI 格式。其中有一条硬性限制：

> **空行表示一次 set 操作结束。**

`device/uapi.go` 中的 `IpcSetOperation` 读到空行就会立即返回，因此配置文件里若
出现空行，空行之后的所有 peer 都会被静默丢弃。生成脚本保证输出中不含空行，
`scripts/gen-configs_test.sh` 也会对此做断言。手工编辑配置时请同样注意。

## 2. 前置条件

先在仓库根目录构建两个二进制：

```bash
# 用户态守护进程（创建 TUN 设备、跑握手和数据面）
go build -o wireguard-go-gm .

# 配置工具（生成密钥、下发配置、查看状态）
go build -o wg-gm ./cmd/wg-gm
```

生成脚本要求 `wg-gm` 位于 `PATH` 中，否则会直接报错退出：

```bash
export PATH="$PWD:$PATH"
```

两个二进制的分工与上游 WireGuard 一致：`wireguard-go-gm` 对应 `wireguard-go`，
`wg-gm` 对应 `wg(8)`。区别在于本仓库的版本使用国密算法（SM2 握手、SM3 哈希、
SM4 数据加密），密钥为十六进制字符串（私钥 64 位十六进制，公钥 130 位十六进制），
与上游的 Base64 Curve25519 密钥不兼容，两者不能互通。

### Windows 额外要求

Windows 上的 TUN 设备由 [Wintun](https://www.wintun.net/) 提供，`wireguard-go-gm.exe`
在运行时通过 `golang.zx2c4.com/wintun` 动态加载它。因此必须把与目标架构匹配的
`wintun.dll`（`amd64` / `arm64` / `x86`）放在 `wireguard-go-gm.exe` 同级目录下，
否则创建接口时会失败。此外需要以管理员身份运行 PowerShell，`New-NetIPAddress`
与 `New-NetRoute` 都要求管理员权限。

## 3. 使用方式

### 直接传参

```bash
bash scripts/gen-configs.sh \
  --server-endpoint 152.67.198.96 \
  --clients win1,linux1 \
  --output-dir ./out/demo
```

### 使用配置文件

复制 `scripts/example.env` 后按需修改，再通过 `--config` 引用：

```bash
cp scripts/example.env my.env
bash scripts/gen-configs.sh --config my.env
```

命令行参数优先级高于配置文件，可以只覆盖其中一两项：

```bash
bash scripts/gen-configs.sh --config my.env --output-dir ./out/prod --preshared-key true
```

### 可用参数

| 参数 | 环境变量 | 默认值 | 说明 |
| --- | --- | --- | --- |
| `--config` | — | 无 | 要 `source` 的配置文件 |
| `--server-endpoint` | `SERVER_ENDPOINT` | 无（必填） | 客户端拨号使用的服务端地址 |
| `--server-port` | `SERVER_PORT` | `51820` | 服务端监听端口 |
| `--server-iface` | `SERVER_IFACE` | `wg0` | 接口名，同时用于生成的启动脚本 |
| `--server-tun-ip` | `SERVER_TUN_IP` | `10.10.0.1/24` | 服务端隧道地址（IPv4 CIDR，前缀 ≤ 30） |
| `--clients` | `CLIENTS` | 无（必填） | 逗号分隔的客户端名列表 |
| `--output-dir` | `OUTPUT_DIR` | 无（必填） | 输出目录，必须尚不存在 |
| `--preshared-key` | `PRESHARED_KEY` | `false` | 是否生成并使用 PSK |

约束与校验：

- 输出目录已存在时脚本会拒绝执行，避免覆盖已有密钥；
- 客户端名必须匹配 `^[A-Za-z0-9][A-Za-z0-9._-]*$`，重复的名字会被明确拒绝；
- 客户端数量不能超过所选网段可用的主机地址数；
- 客户端隧道地址从服务端地址依次加一（如 `10.10.0.1/24` 对应 `10.10.0.2`、`10.10.0.3`……）；
- 所有客户端共享同一份 PSK（若启用）。

## 4. 输出目录结构

以 `--clients win1,linux1 --output-dir ./out/demo` 为例：

```
out/demo/
├── server/
│   ├── privatekey             # 服务端 SM2 私钥（模式 600）
│   ├── publickey              # 服务端 SM2 公钥
│   ├── preshared_key          # 仅在 --preshared-key true 时生成（模式 600）
│   ├── server.conf            # 服务端完整配置，含全部 peer（模式 600）
│   ├── up.sh                  # 服务端启动脚本
│   └── clients/
│       ├── win1.peer.conf     # 单个 peer 片段，便于事后增量添加（模式 600）
│       └── linux1.peer.conf
└── clients/
    ├── win1/
    │   ├── privatekey         # 客户端私钥（模式 600）
    │   ├── publickey
    │   ├── client.conf        # 客户端配置（模式 600）
    │   ├── linux-up.sh
    │   └── windows-up.ps1
    └── linux1/
        └── ...
```

含密钥的文件权限为 `600`。请通过安全信道分发 `clients/<name>/` 目录，并在分发
后删除本地副本。

`server/clients/<name>.peer.conf` 是为后续增量添加 peer 准备的：接口已经在运行
时，可以直接下发单个 peer 而不必重放整份 `server.conf`。

## 5. 启动

### 服务端（Linux）

`server/up.sh` 会前台启动守护进程并打印后续步骤：

```bash
cd out/demo/server
cp /path/to/wireguard-go-gm /path/to/wg-gm .
./up.sh
```

在第二个终端中应用配置并配置地址：

```bash
sudo ./wg-gm setconf wg0 server.conf
sudo ip addr add 10.10.0.1/24 dev wg0
sudo ip link set wg0 up
```

之后可用 `sudo ./wg-gm show wg0` 查看握手状态。增量添加一个客户端：

```bash
sudo ./wg-gm setconf wg0 clients/newclient.peer.conf
```

### 客户端（Linux）

```bash
cd out/demo/clients/linux1
cp /path/to/wireguard-go-gm /path/to/wg-gm .
sudo ./linux-up.sh
```

脚本会启动守护进程、应用 `client.conf`、配置隧道地址，并添加一条指向服务端隧道
地址的路由。该路由使用的是 `--server-tun-ip` 推导出的地址，不是写死的
`10.10.0.1`。

### 客户端（Windows）

把 `wireguard-go-gm.exe`、`wg-gm.exe`、匹配架构的 `wintun.dll` 与生成的
`client.conf`、`windows-up.ps1` 放在同一目录，然后以管理员身份运行：

```powershell
.\windows-up.ps1
```

## 6. 验证

```bash
# 客户端 ping 服务端隧道地址
ping 10.10.0.1

# 两端查看握手时间与收发字节数
sudo ./wg-gm show wg0
```

若 `wg-gm show` 显示 peer 数量少于预期，通常说明配置文件中混入了空行（见第 1
节）；若始终没有握手，先确认服务端 UDP 端口可达、两端时间同步，并用
`LOG_LEVEL=verbose` 查看守护进程日志。

## 7. 自检

生成脚本自带端到端测试，会真实构建 `wg-gm` 并校验输出格式、权限与错误处理：

```bash
bash scripts/gen-configs_test.sh
# 或
make test-scripts
```
