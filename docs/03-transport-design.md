# 03 · Transport 设计：绕开坏掉的 WinRing0 DLL

## 目标

从用户态安全地读写 EC 端口 `0x62` / `0x66`，且**只**做这件事。

---

## 为什么不用现成的 WinRing0 DLL

上游项目附带了一份 `WinRing0x64.dll`，但它在某些机器上**根本无法初始化**：

```
InitializeOls() -> 0
GetDllStatus()  -> 3      # OLS_DLL_DRIVER_NOT_FOUND
```

而且调用 `GetDllVersion()` 会直接**访问违例**（ABI 不匹配）。

### 根因（从源码定位，不是猜的）

`WinRing0Dll/OlsDll.cpp`：

```c
DWORD Initialize()
{
    TCHAR dir[MAX_PATH];
    GetModuleFileName(NULL, dir, MAX_PATH);   // ← NULL = 宿主 EXE，不是 DLL！
    if((ptr = _tcsrchr(dir, '\\')) != NULL) *ptr = '\0';

    wsprintf(gDriverPath, _T("%s\\%s"), dir, gDriverFileName);
    //  gDriverPath = <宿主EXE目录>\WinRing0x64.sys

    if(IsFileExist(gDriverPath) == FALSE)
        return OLS_DLL_DRIVER_NOT_FOUND;      // == 3
    ...
}
```

`OlsDef.h`：`#define OLS_DLL_DRIVER_NOT_FOUND 3`

**所以 status 3 的真正含义是：DLL 在「宿主可执行文件所在目录」里找不到 `.sys`。**

不是驱动加载失败，不是签名问题，不是安全策略 —— 是**找文件的目录不对**。

### 两个解法

1. **让宿主 EXE 和 `.sys` 同目录**（本项目 `ECGuard-Deploy.ps1` 就是这么做的，
   `bridge / dll / sys` 全放在 `C:\ProgramData\ECGuard\driver`）
2. **完全绕开 DLL**，直接对内核驱动发 `DeviceIoControl`（本项目最终采用）

> 一个常见误判：把 `.sys` 放到 `System32\drivers` 里**解决不了**，
> 因为 DLL 根本不看那里。

---

## 方案：DeviceIoControl 直连

### 驱动能力来自哪里

WinRing0 内核驱动 `WinRing0x64.sys` 加载后会创建设备：

```
\Device\WinRing0_1_2_0
\DosDevices\WinRing0_1_2_0     ← 用户态用 \\.\WinRing0_1_2_0 打开
```

只要驱动在已加载状态，`CreateFileW` 就能拿到句柄，然后 `DeviceIoControl` 发命令。

### IOCTL 从哪来（三重依据）

**依据 A / B：两份独立的 OpenLibSys 头文件**

`GermanAizek/WinRing0` 与 `QCute/WinRing0` 的 `WinRing0Dll/OlsIoctl.h` 逐字节一致：

```c
#define OLS_TYPE 40000                     // 0x9C40
IOCTL_OLS_READ_IO_PORT_BYTE  = CTL_CODE(OLS_TYPE, 0x833, METHOD_BUFFERED, FILE_READ_ACCESS)
IOCTL_OLS_WRITE_IO_PORT_BYTE = CTL_CODE(OLS_TYPE, 0x836, METHOD_BUFFERED, FILE_WRITE_ACCESS)
```

`CTL_CODE(DeviceType, Function, Method, Access) =`
`(DeviceType << 16) | (Access << 14) | (Function << 2) | Method`

代入 `OLS_TYPE = 0x9C40`、`METHOD_BUFFERED = 0`：

```
READ  = (0x9C40<<16) | (1<<14) | (0x833<<2) = 0x9C4060CC
WRITE = (0x9C40<<16) | (2<<14) | (0x836<<2) = 0x9C40A0D8
```

> ⚠️ **踩过的坑**：一开始把 access 当成 `FILE_ANY_ACCESS`(0) 算成 `0x9C4020CC` /
> `0x9C4020D8`。**那是错的** —— access 位在 14–15 位，必须计入。
> 两份头文件明确写的是 `FILE_READ_ACCESS` / `FILE_WRITE_ACCESS`。

**依据 C：随附二进制的原始字节比对**

在真实的 `WinRing0x64.dll` 和 `WinRing0x64.sys` 里做 DWORD 搜索：

| 常量 | 值 | DLL | SYS |
|---|---|---|---|
| `GET_DRIVER_VERSION` | `0x9C402000` | 2 处 | 1 处 |
| `READ_MSR` | `0x9C402084` | 3 处 | 1 处 |

这在实际使用的二进制里证实了 `OLS_TYPE << 16` 编码正确。
（端口 IOCTL 常量本身没有以字面值出现，所以由头文件推导 + 上述常量交叉印证。）

**运行时佐证**：`GetDriverVersion()` 返回 `0x1020005` = **1.2.0.5**，
与头文件里 `OLS_DRIVER_MAJOR/MINOR/REVISION/RELESE = 1/2/0/5` 完全一致
→ 推导所依据的头文件版本**就是**正在跑的驱动版本。

### 结构体

```c
typedef struct _OLS_WRITE_IO_PORT_INPUT {
    ULONG PortNumber;                 // offset 0
    union {
        ULONG  LongData;
        USHORT ShortData;
        UCHAR  CharData;              // offset 4
    };
} OLS_WRITE_IO_PORT_INPUT;
```

| 操作 | IOCTL | 输入 | 输入长度 | 输出 | 输出长度 |
|---|---|---|---|---|---|
| 读端口字节 | `0x9C4060CC` | `WORD port` | 2 | `WORD value` | 2 |
| 写端口字节 | `0x9C40A0D8` | `OLS_WRITE_IO_PORT_INPUT` | `offsetof(CharData)+1 = 5` | — | 0 |

写路径长度取自 `OlsApi.cpp::WriteIoPortByteEx` 原文：

```c
length = offsetof(OLS_WRITE_IO_PORT_INPUT, CharData) + sizeof(inBuf.CharData);  // == 5
```

---

## 最小权限设计

`ecguard/winring0_dev.py` 只暴露两个方法：

```python
ALLOWED_PORTS = (0x62, 0x66)

def read_port_byte(self, port)    # 非白名单 → PortAccessDenied
def write_port_byte(self, port, value)
```

**物理内存、MSR、PCI 配置空间、任意端口、`READ_IO_PORT`（可指定宽度）全部未实现。**
代码里根本不存在可达那些能力的路径 —— 不是"禁用"，是"没写"。

---

## 安全外壳

### Poison（跨进程）

任何超时/异常 → 落盘标记 → 后续写入一律拒绝：

```
%ProgramData%\ECGuard\state\state.json
```

只读操作用 `README` 提到的 `ECSUARD_STATE_DIR` 可重定向（自检用）。

### 崩溃日志（journal）

**在写第一个字节之前**把意图落盘：

```json
{"started_at": "...", "planned_writes": [[33107,80],[33108,60],[33105,13],[33104,16]],
 "completed": false, "bytes_written": 0}
```

进程被杀死 → 留下"在途"标记 → 下次写入被拒 → 必须先只读复核再显式清除。

> **踩过的坑**：早期版本 `clear_poison()` 只清了 `poisoned`，没清这个 journal，
> 结果一个 11 天前的陈旧事务把所有写入永久堵死。现在清除时会**同时丢弃陈旧 journal**
> 并把它归档到 `transaction_history` 留审计痕迹。

### 指数退避

邮箱轮询用固定退避序列，最坏 14 次轮询 / 约 2.05 s：

```python
POLL_SCHEDULE = (0.002, 0.004, 0.008, 0.016, 0.032, 0.064, 0.128, 0.256,
                 0.256, 0.256, 0.256, 0.256, 0.256, 0.256)
```

对比：早期实现用"立即重读"循环，3 秒内能发出**约 90 次完整的 0x92 读事务**。
现在单次 `10/0D` 全流程约 90 次事务 / 1100 次端口访问。

### 驱动生命周期

```
sc create <name> type= kernel start= demand binPath= <protected>\WinRing0x64.sys
sc start
   ... 单次操作 ...
sc stop
sc delete
```

- `finally` 里执行，异常路径同样清理
- 不常驻、不自启、不建计划任务
- 每次操作后独立核实：`sc query` 无残留、`\\.\WinRing0_1_2_0` 不再可打开

### 文件位置加固

驱动放在 `C:\ProgramData\ECGuard\driver`，ACL：

```
Authenticated Users  : ReadAndExecute
Administrators       : FullControl
SYSTEM               : FullControl
```

防止普通用户替换内核驱动（否则就是一个提权面）。
启动时还会校验 DLL/SYS 的 SHA256。

---

## 异步状态机 + 判据设计（重要教训）

**EC 的状态机是异步的。**

| 寄存器 | 更新时机 |
|---|---|
| `0x83C0` 模式位 | 邮箱处理函数返回时**立即** |
| `0x8152` 结果 | **立即** |
| `0x8370` 调度状态 | 下一个周期 |
| `0x837C/0x837D` 请求电流 | 更晚 |
| 实际充电器动作 | 更晚（SMBus） |

**所以不能用即时快照判成功/失败。** 本项目一开始就犯了这个错：
`0x0E` 明明生效了（`83C0=0x02`），但因为立刻检查 `requested_current_zero` 还没变，
被判成失败并 poison —— **假阴性**。

正确判据：

```python
# 硬判据（立即，不可让步）
mode == 0x02 and mailbox_result == 0x55

# 沉降判据（轮询，最长 12 秒）
while not settled and now < deadline:
    settled = requested_current_zero and not charging and not discharging
```

`tools/stop_resume_probe.py` 和 `tools/native_enable_probe.py` 都已按此实现。
