# 第 24 章 - Recon 流程管線整合

## 標籤

- #cpts
- #chapter
- #recon
- #pipeline

## 學習目標

- 把 Vol.1 前面章節串成一條可執行的 reconnaissance pipeline。
- 理解從 Seed Domain 到高價值服務清單的收斂流程。
- 知道何時使用被動來源、何時進入主動驗證。
- 建立去重、驗證、排序與證據保存的一致方法。
- 將工具輸出轉換成可直接支援後續漏洞研究的目標集。

---

## 理論基礎

```text
Recon Pipeline 的核心原則：

目標：把海量候選資產收斂成少量高品質高價值目標
方法：每一層回答一個清楚的問題，輸出更乾淨的輸入給下一層

Pipeline 五個階段：
  1. 外圍關聯（WHOIS/ASN/BGP）
     問題：這個組織控制哪些 IP 範圍與網域？
     
  2. 被動名稱蒐集（Subfinder/Assetfinder/CT/Amass）
     問題：有哪些可能的子網域候選？
     
  3. 解析驗證（dnsx + Wildcard 過濾）
     問題：這些候選名稱哪些真的可解析？哪些是 Wildcard 假陽性？
     
  4. Web 探測（httpx）
     問題：可解析主機中哪些有 Web 服務？狀態碼/標題/技術是什麼？
     
  5. 埠探測與服務驗證（Naabu + Nmap）
     問題：非 Web 主機開了哪些埠？服務是什麼？

每一層都要控制噪音：
  歷史資料（CT/Amass 過期記錄）→ dnsx 驗證過濾
  Wildcard 假陽性 → -wd 或 WILDCARD_IP 手動過濾
  CDN/WAF 前端 → httpx Server Header 標記
  快速 Port 假陽性 → Nmap 二次驗證
```

---

## 完整管線範例

```bash
# ═══════════════════════════════════════════════════════
# 階段 1：外圍關聯
# ═══════════════════════════════════════════════════════

# WHOIS 查詢（定義組織與網域關係）
whois example.com | grep -E "Registrar|Name Server|Registrant Org"

# ASN 查詢（找到組織控制的 IP 範圍）
whois -h whois.cymru.com " -v 93.184.216.34"  # 從已知 IP 找 ASN
# 或用 amass intel 補充
amass intel -asn 15169 -o asn_ranges.txt
# -asn → 從 ASN 號碼取得相關網域與 IP 範圍


# ═══════════════════════════════════════════════════════
# 階段 2：被動名稱蒐集（低互動、廣度優先）
# ═══════════════════════════════════════════════════════

# Subfinder（多來源被動蒐集）
subfinder -d example.com -silent -o subfinder_out.txt
# -d → 目標主網域；-silent → 只輸出結果；-o → 存檔

# Assetfinder（補充 Subfinder 遺漏）
assetfinder --subs-only example.com > assetfinder_out.txt
# --subs-only → 只輸出子網域（排除關聯網域）

# Certificate Transparency（crt.sh API）
curl -s "https://crt.sh/?q=%.example.com&output=json" | \
  jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u > ct_out.txt
# 萬用字元前綴去除（\*\.），排序去重

# 合併全部候選名稱
cat subfinder_out.txt assetfinder_out.txt ct_out.txt | sort -u > all_candidates.txt
echo "[+] 候選名稱總數：$(wc -l < all_candidates.txt)"


# ═══════════════════════════════════════════════════════
# 階段 3：解析驗證與 Wildcard 過濾
# ═══════════════════════════════════════════════════════

# 先偵測 Wildcard
WILDCARD_IP=$(dig @8.8.8.8 "randXYZ12345.example.com" +short 2>/dev/null)
# 用隨機主機名稱查詢；有回應 = Wildcard 環境

if [ -n "$WILDCARD_IP" ]; then
  echo "[!] 發現 Wildcard IP: ${WILDCARD_IP}，將過濾"
  dnsx -l all_candidates.txt -a -resp -silent | \
    grep -v "\[${WILDCARD_IP}\]" | \
    awk '{print $1}' > hosts_live.txt
else
  echo "[+] 無 Wildcard，直接解析"
  dnsx -l all_candidates.txt -a -resp -silent -o resolved.txt
  awk '{print $1}' resolved.txt > hosts_live.txt
fi

echo "[+] 可解析主機數：$(wc -l < hosts_live.txt)"


# ═══════════════════════════════════════════════════════
# 階段 4：Web 探測與盤點
# ═══════════════════════════════════════════════════════

# httpx Web 盤點
httpx -l hosts_live.txt -sc -title -server -tech-detect -silent \
  -json -o web_inventory.json
# -sc → 狀態碼；-title → 頁面標題；-server → Server Header
# -tech-detect → 技術指紋；-json → JSON 輸出

# 從 JSON 分群高價值目標
jq -r 'select(."status-code" == 200) | .url' web_inventory.json > web_200.txt
jq -r 'select(.title | ascii_downcase | contains("login")) | .url' web_inventory.json > web_login.txt
jq -r 'select(.title | ascii_downcase | contains("admin")) | .url' web_inventory.json > web_admin.txt

echo "[+] HTTP 200：$(wc -l < web_200.txt)"
echo "[+] 登入頁：$(wc -l < web_login.txt)"
echo "[+] 管理後台：$(wc -l < web_admin.txt)"


# ═══════════════════════════════════════════════════════
# 階段 5：埠探測與服務驗證
# ═══════════════════════════════════════════════════════

# Naabu 快速埠發現（對所有可解析主機）
naabu -list hosts_live.txt -top-ports 1000 -rate 1000 -retries 2 \
  -silent -o naabu_out.txt
# 輸出格式：host:port

# 分離 Web 埠（已由 httpx 處理）與非 Web 埠
grep -vE ":(80|443|8080|8443)$" naabu_out.txt > non_web_ports.txt

# 從非 Web 開放埠提取唯一主機
cut -d: -f1 non_web_ports.txt | sort -u > non_web_hosts.txt

# Nmap 對高價值主機做服務驗證
# （批次：每個主機用 Naabu 找到的埠）
while IFS= read -r host; do
  ports=$(grep "^${host}:" naabu_out.txt | cut -d: -f2 | tr '\n' ',' | sed 's/,$//')
  if [ -n "$ports" ]; then
    sudo nmap -sV -p "${ports}" --reason \
      -oA "nmap_${host//\//_}" "${host}" 2>/dev/null
  fi
done < non_web_hosts.txt
```

---

## 結果整理與優先排序

```bash
# 統計各類高價值目標數量
echo "=== Recon 結果摘要 ==="
echo "候選名稱：$(wc -l < all_candidates.txt)"
echo "可解析主機：$(wc -l < hosts_live.txt)"
echo "有 Web 服務：$(jq -s 'length' web_inventory.json)"
echo "登入頁：$(wc -l < web_login.txt)"
echo "管理後台：$(wc -l < web_admin.txt)"
echo "非 Web 開放埠：$(wc -l < non_web_ports.txt)"

# 優先排序原則
# P1（最高優先）：
#   - 管理後台（/admin / management / console）
#   - 登入頁（/login / signin / auth）
#   - VPN / SSO / 跳板主機
grep -iE "vpn|sso|rdp|citrix|portal" web_inventory.json | jq -r '.url'

# P2（次優先）：
#   - API 服務（標題/路徑含 api / swagger / graphql）
#   - 開發/測試環境（dev/staging/test）
grep -iE "api|swagger|graphql|dev\.|staging\.|test\." web_inventory.json | jq -r '.url'

# P3（一般）：
#   - 一般公開網站
#   - 非標準服務（高埠）
```

---

## 決策流程

```
Seed Domain（例如 example.com）
    ↓
[被動] Subfinder + Assetfinder + CT → 合併去重
    ↓
Wildcard 偵測
  有 Wildcard → 記錄 IP，加入 grep -v 過濾
  無 Wildcard → 直接進下一步
    ↓
dnsx 批次解析驗證 → 輸出 hosts_live.txt
    ↓
並行執行：
  [Web] httpx -sc -title -server -tech-detect → web_inventory.json
    → jq 分群（200/login/admin/api）→ 優先排序
  [埠] naabu -top-ports 1000 → naabu_out.txt
    → 分離非 Web 埠 → Nmap -sV --reason → 服務確認
    ↓
輸出資產地圖（結構化清單）
  欄位：資產/IP / 來源 / 解析時間 / 服務狀態 / 是否第三方 / 優先級
    ↓
高優先 Web 目標 → 內容列舉 / 身份驗證測試 / 漏洞研究
高優先非 Web 目標 → 協定分析 / NSE / 手動驗證
```

---

## 速查表

```bash
# 被動蒐集
subfinder -d example.com -silent -o sub.txt
assetfinder --subs-only example.com > asset.txt
curl -s "https://crt.sh/?q=%.example.com&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u > ct.txt
cat sub.txt asset.txt ct.txt | sort -u > candidates.txt

# 解析驗證
WILDCARD_IP=$(dig "randXYZ.example.com" +short)
dnsx -l candidates.txt -a -resp -silent | grep -v "\[${WILDCARD_IP}\]" | awk '{print $1}' > hosts.txt

# Web 盤點
httpx -l hosts.txt -sc -title -server -tech-detect -json -silent -o web.json
jq -r 'select(."status-code"==200)|.url' web.json
jq -r 'select(.title|ascii_downcase|contains("login"))|.url' web.json

# 埠發現
naabu -list hosts.txt -top-ports 1000 -rate 1000 -silent -o ports.txt

# 服務驗證
sudo nmap -sV -p <埠> --reason -oA nmap_scan <目標>
```

---

## 常見錯誤與排查

- 一開始就大範圍主動掃描，沒有前置收斂 → 先被動蒐集，再逐步進入主動探測。
- 工具輸出沒有去重與交叉驗證 → 每層都要 sort -u；dnsx 驗證是必要的。
- 沒有標記來源與信度 → 「這個主機從哪個工具找到的？是否已 DNS 驗證？」要可追溯。
- 對第三方代管（CDN/SaaS）結果沒有標記 → CNAME 指向 CDN 的應標記，不直接掃。
- 沒有把結果整理成優先排序清單 → Recon 的最終輸出是一份清單，不是一堆文字檔。

---

## 關聯筆記

- [[09-DNS列舉方法論|第 9 章 - DNS 列舉方法論]]
- [[13-Subfinder|第 13 章 - Subfinder]]
- [[15-dnsx|第 15 章 - dnsx]]
- [[16-httpx|第 16 章 - httpx]]
- [[17-Naabu與Nmap掃描分工|第 17 章 - Naabu 與 Nmap 掃描分工]]
- [[23-Nmap輸出證據與自動化|第 23 章 - Nmap 輸出證據與自動化]]
- [[01-Volume-1-Information-Gathering-Index|Vol.1 - Information Gathering]]
