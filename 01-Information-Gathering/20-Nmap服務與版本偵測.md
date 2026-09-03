# 第 20 章 - Nmap 服務與版本偵測

## 標籤

- #cpts
- #chapter
- #nmap
- #service-detection

## 學習目標

- 理解 `-sV` 的基本工作原理與限制。
- 知道 `nmap-service-probes`、match、softmatch、rarity 的概念。
- 掌握 `--version-intensity`、`--version-light`、`--version-all` 的取捨。
- 分辨 banner、協定回應與實際版本之間的差異。
- 把服務辨識結果正確轉成後續研究方向，而不是漏洞結論。

---

## 理論基礎

```text
-sV 的工作原理：

1. Nmap 對已知開放埠送出協定探測（nmap-service-probes 定義的 probe）
2. 比對收到的回應與 probe 資料庫的 match/softmatch 規則
3. 輸出推測的服務名稱與版本字串

nmap-service-probes 資料庫概念：
  match   → 精確比對，高可信度（confidence 10）
  softmatch → 模糊比對，需額外 probe（confidence 較低）
  rarity  → 稀有度（0-9），越高越少送對應 probe（影響速度）

--version-intensity 控制：
  0  = 只送 rarity 0 的 probe（最快，但識別率最低）
  5  = 預設值（balance speed vs accuracy）
  9  = 送全部 probe（最慢，但識別率最高）
  --version-light  = intensity 2
  --version-all    = intensity 9

關鍵限制（不能盲目信任）：
  Banner 可以被偽造（fake banner）
  反向代理 / CDN / WAF 可能回應自己的 banner
  版本 backport（系統發行版打補丁後版本字串仍舊）
  TLS 包裝會影響部分 probe 的可用性
```

---

## 基本使用

```bash
# 基本服務版本探測
nmap -sV 192.168.1.1
# -sV → 對開放埠送 probe，嘗試識別服務名稱與版本
# 預設 intensity = 5（平衡速度與準確性）
# 輸出範例：80/tcp  open  http  Apache httpd 2.4.51

# 只對特定高價值埠做版本探測（節省時間）
nmap -sV -p 80,443,8080,8443,22 192.168.1.1
# -p → 只對這些埠做 -sV
# 搭配 Naabu 輸出使用：先發現開放埠，再精準 -sV

# 輕量版本探測（intensity 2，速度快）
nmap -sV --version-light 192.168.1.1
# --version-light → intensity 2，只送最常見的 probe
# 適合：大量目標快速篩選；可能漏掉非標準服務

# 全力版本探測（intensity 9，最慢最全）
nmap -sV --version-all 192.168.1.1
# --version-all → intensity 9，送全部 probe
# 適合：少數特定高價值目標的深入分析

# 自訂強度（0-9）
nmap -sV --version-intensity 7 192.168.1.1
# --version-intensity 7 → 比預設更積極，適合識別非標準服務
```

---

## 搭配其他旗標

```bash
# 搭配 --reason 確認識別依據
nmap -sV -p 80,443 --reason 192.168.1.1
# 可看到每個埠基於什麼封包回應被判定為 open

# 搭配 -sS（SYN Scan + 版本偵測）
sudo nmap -sS -sV -p 80,443,22 192.168.1.1
# -sS → 先做 SYN Scan 確認 open 埠
# -sV → 再對 open 埠做版本探測
# 注意：-sV 會做完整連線（TCP connect）即使 -sS 發現埠，因為版本探測需要應用層互動

# 搭配 -O 做 OS 偵測（同時識別服務與作業系統）
sudo nmap -sV -O -p 80,443,22 192.168.1.1
# -O → OS detection（需要 root）
# 注意：-O 需要多種埠狀態資訊，至少一個 open + 一個 closed

# 輸出到檔案同時保留原始掃描記錄
nmap -sV -p 80,443 -oN service_scan.txt 192.168.1.1
# -oN → Normal 格式輸出到檔案（human-readable）
# 有利後續報告撰寫和證據存檔

# 全格式輸出（Normal + XML + Grepable）
nmap -sV -p 80,443 -oA service_scan 192.168.1.1
# -oA → All formats，產生 .nmap / .xml / .gnmap 三個檔案
```

---

## 輸出解讀

```text
Nmap -sV 輸出格式：
  PORT     STATE  SERVICE  VERSION
  22/tcp   open   ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.4
  80/tcp   open   http     Apache httpd 2.4.51 ((Ubuntu))
  443/tcp  open   ssl/http nginx 1.18.0

解讀三個層次：

1. 觀測（最可靠）：
   - 埠開放且 Nmap 能與之互動
   - 收到了某種應用層回應（banner 或協定回應）

2. Nmap 推測（高品質但可能有誤）：
   - 服務名稱（ssh/http/ssl...）
   - 版本字串（OpenSSH 8.2p1 / Apache 2.4.51）
   - 注意：版本字串可能是 backport 或假 banner

3. 你的推論（需要驗證）：
   - 「Apache 2.4.51 → 查 CVE 是否適用」
   - 先確認這是真正的後端服務，還是 CDN/代理層

常見陷阱：
  顯示 nginx → 可能是 CDN 或反向代理，後面是 Tomcat
  顯示 Apache 2.4.x → 版本可能已 backport 補丁，漏洞不一定適用
  顯示 OpenSSH 7.x → Debian/Ubuntu 可能已做 backport，不等於舊版漏洞存在
```

---

## 交叉驗證方法

```bash
# Web 服務：用 curl 直接看 Server Header
curl -I -k https://192.168.1.1
# -I → HEAD request（只取 Header）
# -k → 忽略 TLS 憑證錯誤
# 輸出 Server: nginx/1.18.0 可直接確認 banner

# 用 httpx 快速批次確認 Server Header
echo "192.168.1.1" | httpx -server -silent

# SSH：連線看 banner
nc 192.168.1.1 22
# 直接看 SSH 歡迎 banner（如：SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.4）

# 手動查看 SSL 憑證中的服務資訊
openssl s_client -connect 192.168.1.1:443 -brief
# -brief → 只顯示關鍵資訊（不要大量 TLS handshake 細節）
# 看 CN、SAN 確認服務對應的域名
```

---

## 決策流程

```
已知開放埠（來自 Naabu 或基本 Nmap scan）
    ↓
nmap -sV --version-intensity 5 -p <已知開放埠> <目標>
    ↓
結果分析
  有明確版本字串 → 記錄為「Nmap 推測版本」
    → 交叉驗證（curl/nc/openssl）確認
    → 若一致 → 確認版本，進入漏洞研究
    → 若不一致 → 懷疑代理/CDN/fake banner，標記需人工確認
  版本未知（unknown/generic）→ 提高 intensity 或手動 probe
  無版本資訊 → 服務識別失敗 → 手動 netcat banner grab
    ↓
版本確認後 → 查 CVE / Exploit 研究
  注意：先確認版本是否有 backport 補丁，再評估漏洞適用性
```

---

## 速查表

```bash
# 基本版本偵測
nmap -sV 192.168.1.1                               # 預設強度 5
nmap -sV -p 80,443,22 192.168.1.1                  # 指定埠
nmap -sV --version-light 192.168.1.1               # 輕量（intensity 2）
nmap -sV --version-all 192.168.1.1                 # 全力（intensity 9）
nmap -sV --version-intensity 7 192.168.1.1         # 自訂強度

# 搭配輸出
nmap -sV -p 80,443 --reason 192.168.1.1            # 附判定原因
nmap -sV -p 80,443 -oA service_scan 192.168.1.1    # 三格式輸出

# 交叉驗證
curl -I -k https://192.168.1.1                     # Web Server Header
nc 192.168.1.1 22                                  # SSH banner
openssl s_client -connect 192.168.1.1:443 -brief   # TLS 憑證
```

---

## 常見錯誤與排查

- 把 `-sV` 版本字串直接當成已驗證技術事實 → 先交叉驗證再下結論（backport 很常見）。
- 在大量未知目標全部跑高強度 `-sV` → 先 Naabu 收斂，再對高價值目標做 `-sV`。
- 忽略反向代理 / CDN 造成的 banner 誤導 → 比對 Server Header、TLS CN、`httpx` 結果。
- 找到版本直接查 CVE 就認為適用 → backport 補丁讓舊版字串仍存在，需確認實際修補狀態。

---

## 關聯筆記

- [[18-Nmap掃描生命週期與封包分析|第 18 章 - Nmap 掃描生命週期與封包分析]]
- [[19-UDP掃描深度解析|第 19 章 - UDP 掃描深度解析]]
- [[21-Nmap作業系統偵測|第 21 章 - Nmap 作業系統偵測]]
- [[22-Nmap指令碼引擎NSE|第 22 章 - Nmap 指令碼引擎 NSE]]
- [[01-Volume-1-Information-Gathering-Index|Vol.1 - Information Gathering]]
