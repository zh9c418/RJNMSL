# RJNMSL
我的校园网走有线的话要装一个认证客户端，我很讨厌这狗屎玩意。然后顺便测试一下现在的LLM辅助开发方式和dsv4.1的逆向/编码能力。后面的内容让DS自己开始介绍：

简体中文 | [English](README.en.md)

> **这是一个 vibecoding 项目。** 代码主要由 AI 生成，主力模型是
> **deepseek-v4.1-flash** 和 **gpt-5.6-sol**。人工负责提需求、查资料、抓包、读日志和少量修补。
> 使用前请自行审阅评估。

> [!WARNING]
> **免责声明**：本项目仅供学习研究，以及在你**自己**的网络/设备上做互操作。凭据在本机以**明文**保存（仅 ACL 限制），请自行评估风险；使用前请确认不违反你所在校园网/机构的使用规定。EAP-MD5 协议本身并不安全。

**一个用于替代 Windows 上锐捷校园网认证客户端的轻量方案。**

RJNMSL 可以让有线 802.1X 端口认证通过，而**不安装厂商内核驱动**、**不常驻 SYSTEM 认证服务**，在推荐方案下甚至**完全不加载任何抓包驱动**。

---

## 背景


不少校园网要求安装厂商客户端（锐捷 `SuService.exe` / `8021x.exe`）来做有线 802.1X 认证。该客户端会：

* 安装内核态 NDIS 抓包驱动（PCAUSA `PCASp50` / `W32N55`）并绑定到网卡，用来收发原始 EAPOL 帧；
* 常驻一个 `LocalSystem` 服务（还会在你的会话里拉起进程、写 Winlogon 等）；
* 加载抓包驱动——而游戏反作弊（腾讯 ACE、BattlEye、EAC、Vanguard, 还有embark studios最近出的elytra 等）会重点关注这类驱动。

如果你只是想让 802.1X 端口认证通过，上面这些其实都不需要。RJNMSL 提供两种做法。

---

## 两种认证方式

### 1. `eapmd5` —— Windows 原生 802.1X + 用户态 EAP-MD5 插件（推荐）

Windows 自带的认证组件（`Wired AutoConfig` / `dot3svc`）本来就会通过正常的 NDIS 栈收发 802.1X/EAPOL，唯一缺的是 **EAP-MD5** 实现——微软在 Vista 之后移除了自带的实现。RJNMSL 用一个很小的**用户态 EapHost peer method DLL**（`eapmd5.dll`）把它补上。

```
你的进程 ──► dot3svc / OneX ──► EapHost ──► eapmd5.dll   （只负责算 MD5）
                                     │
                                     └─ EAPOL 组帧由 Windows NDIS 完成
                                        （Realtek/Intel/… 网卡驱动）
```

* **不装抓包驱动、不装厂商服务**，内核里没有任何多余的东西。
* 这个 DLL 从不碰原始以太网，只填 EAP 负载。
* 对反作弊友好：全程没有任何二层注入。

### 2. `rj8021x` —— 基于 Npcap 的独立客户端

一个从零实现的 802.1X supplicant，自行通过 Npcap 收发 EAPOL 帧。支持 **EAP-MD5** 以及（需开特性开关）**EAP-PEAP/MSCHAPv2**。

* 适用于 `dot3svc` 不可用/不想用，或需要调试协议的场景。
* 需要 Npcap，且要以管理员运行。
* 因为它**确实**使用抓包驱动，所以和任何原始二层工具一样，存在反作弊方面的顾虑。

**如果你的目标是"打游戏时别被反作弊找麻烦"，请用 `eapmd5`。**

---

## 快速开始 —— `eapmd5`

环境：Windows 10/11、Rust（MSVC 工具链）、管理员权限。

```powershell
git clone https://github.com/zh9c418/RJNMSL
cd RJNMSL
cargo build --release --workspace          # 产出 target\release\eapmd5.dll

# 在管理员 PowerShell 里：
.\scripts\install.ps1
```

安装脚本会：

1. 把 `eapmd5.dll` 复制到 `System32`，并注册到
   `HKLM\SYSTEM\CurrentControlSet\Services\EapHost\Methods\49374\4`；
2. 把 `dot3svc` 设为自动启动，并安装 802.1X 档案；
3. 写入你的凭据；
4. 禁用锐捷服务 `RJSuService`（除非加 `-KeepVendorSupplicant`）；
5. 停止 Npcap（除非加 `-KeepNpcap`）。

验证：

```powershell
netsh lan show interfaces        # -> "Connected. Authentication succeeded."
```

一键回滚：

```powershell
.\scripts\uninstall.ps1 -RestoreVendorSupplicant
```

### 凭据放在哪

方法会读取 `C:\ProgramData\RJNMSL\eapmd5.ini`：

```ini
username=你的账号
password=你的密码
```

`install.ps1` 会写入该文件并把 ACL 限制为 `SYSTEM` + `Administrators`。也可以直接用 `-Username` / `-Password` 传参，或在仓库根目录放一个（已被 gitignore 的）`credentials.txt`。

---

## 快速开始 —— `rj8021x`

环境：[Npcap](https://npcap.com)、Rust（MSVC）、管理员权限。

```powershell
# Npcap 不自带导入库；在 VS x64 命令行里生成一次：
.\scripts\gen-npcap-libs.ps1

cargo build -p rj8021x --release
copy crates\rj8021x\config.toml.example config.toml   # 然后编辑
target\release\rj8021x.exe --list                     # 找到你的网卡
target\release\rj8021x.exe --config config.toml       # 管理员运行
```

更多选项见 [`crates/rj8021x/`](crates/rj8021x/) 与配置示例。PEAP 需显式开启：`cargo build -p rj8021x --release --features peap`。

---

## 目录结构

```
crates/
  eapmd5/          用户态 EapHost EAP-MD5 (Type 4) 方法   (cdylib)
  rj8021x/         基于 Npcap 的独立 802.1X 客户端       (bin)
scripts/
  install.ps1        安装 EapHost 方法 + 切换到原生 802.1X
  uninstall.ps1      完整回滚
  gen-npcap-libs.ps1 从 Npcap 运行库生成 wpcap.lib / Packet.lib
docs/
  architecture.md    原生路径原理 + EapHost ABI 注意点
  troubleshooting.md 诊断方法与已知 Windows 问题
```

---

## 注意事项

* **EAP-MD5 本身很弱**（无服务器认证、可离线字典攻击）。RJNMSL 不会让协议变强，只是给 Windows 补上 Type-4 实现。如果你能改服务端，建议迁移到 PEAP/TEAP。
* 凭据文件是**明文**（已限制 ACL）。本机管理员仍可读取。
* 用 `rj8021x` 时，请**停掉锐捷的客户端和 Windows 自带的 `dot3svc`**，否则它们会抢同一个端口。
* Windows 11 24H2 有公开报告的第三方 EAP 方法回归问题，详见 [`docs/troubleshooting.md`](docs/troubleshooting.md)。

## 许可证

GPL-3.0 —— 见 [`LICENSE`](LICENSE)。本项目用于与你自己的网络互操作，请遵守所在机构的使用规定。