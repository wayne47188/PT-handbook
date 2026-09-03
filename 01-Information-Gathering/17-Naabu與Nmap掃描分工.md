# 第 17 章 - Naabu 與 Nmap 掃描分工

## 標籤

- #cpts
- #chapter
- #naabu
- #nmap
- #ports

## 學習目標

- 理解 Naabu 與 Nmap 在 reconnaissance pipeline 中的不同角色。
- 知道何時做 Port Discovery，何時做 Service Enumeration。
- 理解 Top Ports、Full Port Scan、Rate、Retry 與 CDN 排除的實務取捨。
- 能把 Naabu 結果乾淨地交給 Nmap 驗證。
- 避免把快速掃描結果直接當成最終服務事實。

---

## 理論基礎

```text
Naabu 與 Nmap 的分工原則：

Naabu（快速發現層）：
  設計目標：高速、大量主機的 TCP SYN port discovery
  強項：對數千台主機掃出候選開放埠，速度遠快於 Nmap
  弱點：結果是候選清單，非完整服務事實；rate 太高易假陰性

Nmap（精準驗證層）：
  設計目標：對收斂後的目標做可信度高的服務枚舉
  強項：-sV 服務版本、NSE 腳本、--reason 封包原因、OS 偵測
  弱點：速度慢，對大量主機直接跑重型掃描會拖垮整體流程

實戰決策原則：
  Naabu 先跑（大量主機 × top ports）→ 收斂候選開放埠
  Nmap 後跑（高價值主機 × 已知埠）→ 確認服務細節
  不要一開始就對大量主機跑 Nmap -A；不要只跑 Naabu 就收工
```

---

## Naabu 使用

```bash
# 基本主機清單埠掃描（預設 top 100）
naabu -list hosts.txt -silent
# -list → 從檔案讀取主機清單（每行一個 IP 或主機名稱）
# -silent → 不輸出 banner，只輸出結果（host:port 格式）
# 預設掃描 top 100 常見埠

# 明確指定掃 top 100（等同預設，但顯式更清楚）
naabu -top-ports 100 -list hosts.txt -silent
# -top-ports 100 → 掃最常見的 100 個埠

# 擴大範圍：top 1000
naabu -top-ports 1000 -list hosts.txt -silent
# 用於環境未知時，覆蓋非標準服務埠

# 全埠掃描（高成本，用於關鍵目標）
naabu -p - -list hosts.txt -silent
# -p - → 掃全部 65535 個 TCP 埠
# 注意：耗時長且噪音大，建議只對高價值目標使用

# 指定特定埠範圍
naabu -p 80,443,8080,8443,8888,3000,5000 -list hosts.txt -silent
# -p → 指定埠清單（逗號分隔）或範圍（如 1-1024）

# 控制速率與重試（穩定性 vs 速度）
naabu -rate 1000 -retries 2 -list hosts.txt -silent
# -rate 1000 → 每秒最多送 1000 個封包（預設較高，環境不穩時降低）
# -retries 2 → 無回應時重試 2 次（降低假陰性）
# 較低 rate → 較穩定、假陰性少，但掃描時間加長

# 輸出到檔案（host:port 格式）
naabu -list hosts.txt -top-ports 100 -silent -o naabu_out.txt

# JSON 格式輸出（含更多資訊）
naabu -list hosts.txt -top-ports 100 -silent -json -o naabu_out.json
```

---

## Nmap 搭配 Naabu 使用

```bash
# 方式一：直接把 Naabu host:port 輸出餵給 Nmap
# Naabu 輸出格式：192.168.1.1:80
# Nmap 接受 -iL 主機清單，但需拆分主機與埠

# 先萃取只有 443 埠的主機名稱
grep ":443$" naabu_out.txt | cut -d: -f1 > https_hosts.txt
nmap -sV -p 443 -iL https_hosts.txt

# 對 Naabu 找到的開放埠做服務驗證
nmap -sV -p 80,443 192.168.1.1
# -sV → 服務版本偵測（版本 banner 抓取）
# -p → 只掃指定埠（節省時間）
# 適合：Naabu 已確認開放，Nmap 負責確認服務版本

# 對高價值目標加強掃描
nmap -sV --version-intensity 9 -p 80,443,8080 192.168.1.1
# --version-intensity 9 → 最高版本偵測強度（嘗試更多 probe）
# 預設強度 7，提高可識別更多非標準服務

# 搭配 --reason 理解判讀依據
nmap -sV -p 80,443 --reason 192.168.1.1
# --reason → 顯示每個埠狀態的判定原因（syn-ack / rst / no-response）
# 有助於判斷是服務真的開著，還是中間設備造成的假陽性

# 對整批 Naabu 結果做服務掃描（整合管線）
cat naabu_out.txt | httpx -silent -sc -title   # 先過 Web
grep -v "80\|443\|8080\|8443" naabu_out.txt |  # 非 Web 埠
  cut -d: -f1 | sort -u |
  xargs -I{} nmap -sV -p- {}                   # 全埠服務驗證
```

---

## 整合管線

```bash
# 完整從主機清單到服務識別管線
# 第一階段：httpx 先做 Web 盤點
httpx -l hosts.txt -sc -title -silent -o web_alive.txt

# 第二階段：Naabu 快速找所有開放埠
naabu -list hosts.txt -top-ports 1000 -rate 1000 -retries 2 -silent -o naabu_out.txt

# 第三階段：從 Naabu 結果抽出非 Web 埠做 Nmap 驗證
awk -F: '{print $1}' naabu_out.txt | sort -u > hosts_with_ports.txt
# 對每個主機，用 Naabu 找到的埠跑 Nmap
while IFS= read -r host; do
  ports=$(grep "^${host}:" naabu_out.txt | cut -d: -f2 | tr '\n' ',' | sed 's/,$//')
  nmap -sV -p "${ports}" --reason "${host}" -oN "nmap_${host}.txt"
done < hosts_with_ports.txt
```

---

## 決策流程

```
大量主機清單（hosts.txt）
    ↓
[第一輪] naabu -top-ports 100 -rate 1000
    ↓
候選開放埠清單（naabu_out.txt）
    ↓
分類
  80/443/8080/8443 → httpx 做 Web 盤點
  其他埠（22/25/3389/5432/...）→ 進入 Nmap 驗證
  無結果 → 考慮全埠掃描（-p -）或放棄
    ↓
[第二輪] nmap -sV -p <naabu找到的埠> <高價值主機>
    ↓
服務版本確認 → 後續漏洞研究 / 進一步枚舉
```

---

## 速查表

```bash
# Naabu 基本
naabu -list hosts.txt -silent                            # 預設 top 100
naabu -top-ports 1000 -list hosts.txt -silent            # top 1000
naabu -p - -list hosts.txt -silent                       # 全埠（謹慎）
naabu -rate 1000 -retries 2 -list hosts.txt -silent      # 穩定模式
naabu -list hosts.txt -top-ports 100 -silent -o out.txt  # 存檔

# Nmap 搭配使用
nmap -sV -p <埠> <主機>                                  # 服務版本驗證
nmap -sV -p <埠> --reason <主機>                         # 附帶判定原因
nmap -sV --version-intensity 9 -p <埠> <主機>            # 強化版本偵測
```

---

## 常見錯誤與排查

- 一開始就對大量主機跑重型 Nmap（-A 或全埠）→ 嚴重拖慢整體流程，先用 Naabu 收斂。
- 只跑 Naabu 就做結論 → 假陽性和假陰性都可能存在；Nmap 驗證是必要的。
- 全埠掃描濫用（-p -）在低價值目標 → rate 過高 + 大量主機 = 大量噪音與偵測風險。
- 沒有控速（-rate 過高）→ 高速環境可能 miss 回應；降低 -rate 並加 -retries。

---

## 關聯筆記

- [[15-dnsx|第 15 章 - dnsx]]
- [[16-httpx|第 16 章 - httpx]]
- [[18-Nmap掃描生命週期與封包分析|第 18 章 - Nmap 掃描生命週期與封包分析]]
- [[01-Volume-1-Information-Gathering-Index|Vol.1 - Information Gathering]]
