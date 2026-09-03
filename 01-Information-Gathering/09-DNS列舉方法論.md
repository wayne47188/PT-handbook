# 第 9 章 - DNS 列舉方法論

## 標籤

- #cpts
- #chapter
- #dns
- #enumeration

## 學習目標

- 建立從 Seed Domain 到完整候選資產清單的 DNS Enumeration 流程。
- 理解 Passive Sources、Brute Force、Permutation、Reverse DNS 與 Recursive Enumeration 的分工。
- 掌握 Resolver 選擇、驗證、去重與 Wildcard 排除的基本方法。
- 避免把工具輸出直接等同於真實資產。
- 將列舉結果轉換為可交給 `dnsx`、`httpx` 與埠掃描流程的高品質清單。

---

## 理論基礎

```text
DNS Enumeration 是方法論，不是單一工具

四大資料來源：
  1. 被動來源（Passive）   → CT Log、搜尋引擎、公開資料集、程式碼平台、歷史存檔
  2. 主動猜測（Active）    → 字典暴力列舉、命名規則 Permutation
  3. 解析驗證（Validate）  → DNS 查詢過濾候選名稱 → 實際可解析清單
  4. 遞迴擴展（Recursive） → 從已知子網域衍生更多候選（發現新 Zone 委派）

三大噪音來源（必須處理）：
  Wildcard DNS     → 任何隨機名稱都能解析 → 假陽性爆炸
  第三方代管       → CNAME 指向 CDN / SaaS → 不在授權範圍
  歷史殘留資料     → CT Log 或公開資料集的過期記錄 → 名稱存在但服務不在線

高品質輸出的必要欄位：
  子網域名稱 / 來源類型 / 解析結果 / CNAME 或供應商 / Wildcard 狀態 / 驗證時間 / 下一步
```

---

## Step 1：確認 Wildcard 行為

```bash
# 在做任何批次列舉前，先確認目標是否有 Wildcard DNS

# 取得目標的權威 NS
dig ns example.com +short
# 例如回傳：ns1.example.com.  ns2.example.com.

# 向權威 NS 查詢兩個隨機不存在的名稱
dig @ns1.example.com randomabc1111.example.com +short
dig @ns1.example.com xyznotreal9999.example.com +short
# 預期（無 Wildcard）：無輸出（NXDOMAIN）
# 若兩個都回傳相同 IP → 有 Wildcard DNS

# 記錄 Wildcard IP（後續要從結果中過濾掉）
WILDCARD_IP="<回傳的 IP>"
# 後續列舉結果中凡是解析到這個 IP 的名稱，視為 Wildcard 假陽性
```

---

## Step 2：被動來源蒐集候選名稱

```bash
# CT Log（憑證透明度，見第 10 章詳細說明）
curl -s "https://crt.sh/?q=%25.example.com&output=json" \
  | jq -r '.[].name_value' \
  | sed 's/\*\.//g' \
  | sort -u > candidates_ct.txt
# %25 → URL encode 的 %，代表萬用字元（%25.example.com = *.example.com）
# jq -r '.[].name_value' → 萃取名稱欄位
# sed 's/\*\.//g' → 移除 Wildcard 前綴（*.example.com → example.com）
# sort -u → 去重排序

# 檢查 candidates_ct.txt
wc -l candidates_ct.txt
# 確認候選數量，決定後續驗證策略
```

---

## Step 3：主動暴力列舉

```bash
# 使用 subfinder（整合多個被動來源）
subfinder -d example.com -silent -o candidates_subfinder.txt
# -d → 指定目標網域
# -silent → 只輸出結果，不顯示 banner
# -o → 輸出到檔案

# 使用 amass（被動模式，不主動掃描目標）
amass enum -passive -d example.com -o candidates_amass.txt
# enum → 列舉子模式
# -passive → 只用被動來源（不主動 DNS 查詢目標）
# -d → 目標網域

# 合併所有候選名稱並去重
cat candidates_ct.txt candidates_subfinder.txt candidates_amass.txt \
  | sort -u > candidates_all.txt
# sort -u → 字母排序並去除重複行
wc -l candidates_all.txt
# 確認合併後的候選總數
```

---

## Step 4：DNS 解析驗證與 Wildcard 過濾

```bash
# 用 dnsx 批次驗證所有候選名稱
dnsx -l candidates_all.txt -a -resp -silent -o resolved.txt
# -l → 從檔案讀取候選名稱列表
# -a → 查詢 A 記錄（IPv4）
# -resp → 輸出包含解析結果（IP）
# -silent → 不顯示 banner 與進度
# -o → 輸出到檔案
# 輸出格式：sub.example.com [1.2.3.4]

# 若有 Wildcard，過濾掉解析到 Wildcard IP 的結果
grep -v "${WILDCARD_IP}" resolved.txt > resolved_clean.txt
# grep -v → 反向比對（排除含 Wildcard IP 的行）

# 只取主機名稱（去掉 IP 欄位）供後續使用
awk '{print $1}' resolved_clean.txt > hosts_live.txt
# awk '{print $1}' → 取第一欄（主機名稱）
```

---

## Step 5：CNAME 追蹤與供應商標記

```bash
# 對已解析主機查 CNAME，識別第三方代管
while read host; do
  cname=$(dig "$host" cname +short)
  if [ -n "$cname" ]; then
    echo "$host → $cname"
  fi
done < hosts_live.txt > cname_map.txt
# cname=$(dig "$host" cname +short) → 逐行查 CNAME
# -n "$cname" → 若有回傳才輸出
# 結果存入 cname_map.txt 供後續供應商分類

# 從 CNAME 識別常見供應商
grep -i "cloudfront.net\|azurefd.net\|s3.amazonaws.com\|github.io\|fastly.net" cname_map.txt
# 識別 CDN / SaaS 代管
# cloudfront.net → AWS CloudFront
# azurefd.net    → Azure Front Door
# s3.amazonaws.com → AWS S3（可能有接管風險）
# github.io      → GitHub Pages（可能有接管風險）
```

---

## Step 6：遞迴擴展

```bash
# 從已知子網域歸納命名規則，衍生更多候選
# 例如發現：api-dev.example.com、api-staging.example.com
# → 規則：api-{env}.example.com

# 手動查看已知子網域的命名模式
sort hosts_live.txt | head -30
# 找出環境標記（dev/staging/prod）、區域標記（us/eu/ap）、功能標記

# 用 altdns 做 Permutation 擴展（需安裝）
altdns -i hosts_live.txt -w /usr/share/wordlists/altdns_words.txt -o permutations.txt
# -i → 已知子網域清單
# -w → Permutation 字典
# -o → 輸出候選名稱

# 驗證 Permutation 結果
dnsx -l permutations.txt -a -resp -silent | grep -v "${WILDCARD_IP}" >> resolved_clean.txt
# 把 Permutation 找到的結果合併進主清單
```

---

## Step 7：輸出高品質候選清單

```bash
# 最終清單準備：只含可解析、非 Wildcard、含來源標記的主機
# 送入 httpx 驗證 Web 服務
httpx -l hosts_live.txt -silent -status-code -title -o web_alive.txt
# -l → 主機名稱列表
# -silent → 不顯示 banner
# -status-code → 輸出 HTTP 狀態碼
# -title → 輸出頁面標題
# -o → 結果存檔

# 送入 naabu / nmap 做埠掃描
naabu -list hosts_live.txt -top-ports 1000 -silent -o open_ports.txt
# -list → 主機列表
# -top-ports 1000 → 掃描 Top 1000 埠
# -silent → 精簡輸出
```

---

## 決策流程

```
Seed Domain（目標根網域）
    ↓
Step 1：Wildcard 偵測（dig @ns 隨機名稱）
  有 Wildcard → 記錄 Wildcard IP，後續過濾
  無 Wildcard → 直接進行列舉
    ↓
Step 2：被動來源蒐集
  CT Log（crt.sh）+ Subfinder + Amass 合併去重
    ↓
Step 3：主動猜測補強
  字典暴力（gobuster dns / shuffledns）
  Permutation（altdns）
    ↓
Step 4：批次 DNS 解析驗證（dnsx）
  解析失敗 → 丟棄（可能是歷史資料）
  解析成功但 IP = Wildcard IP → 丟棄（假陽性）
  解析成功且 IP ≠ Wildcard IP → 進入下一步
    ↓
Step 5：CNAME 追蹤與供應商標記
  指向第三方（CDN/SaaS）→ 標記，不列入直接掃描
  指向自有 IP → 進入埠掃描清單
    ↓
Step 6：遞迴擴展（從已知命名規則 Permutation）
  找到新主機 → 回到 Step 4 驗證
    ↓
Step 7：輸出
  httpx 驗證 Web / naabu 埠掃描 / Nmap 精細掃描
```

---

## 速查表

```bash
# Wildcard 偵測
dig ns example.com +short                                  # 取得 NS
dig @ns1.example.com randomabc1111.example.com +short      # 偵測 Wildcard

# 被動來源
curl -s "https://crt.sh/?q=%25.example.com&output=json" \
  | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u > ct.txt
subfinder -d example.com -silent -o subfinder.txt

# 合併去重
cat ct.txt subfinder.txt | sort -u > candidates.txt

# 批次驗證
dnsx -l candidates.txt -a -resp -silent -o resolved.txt
grep -v "WILDCARD_IP" resolved.txt > resolved_clean.txt

# 手動快速驗證單一候選
host vpn.example.com
dig vpn.example.com +short
```

---

## 常見錯誤與排查

- 跳過 Wildcard 偵測直接列舉 → 結果包含大量假陽性，浪費後續驗證時間。
- 把被動來源的歷史資料直接當成現役資產 → 必須通過 DNS 解析驗證後才算真實。
- 沒有標記 CNAME 供應商就送進掃描 → 可能掃到授權範圍外的 CDN 基礎設施。
- 只做一次被動蒐集就停止 → 不同資料來源有互補性，CT Log + Subfinder + Amass 各有死角。
- 把工具輸出「子網域數量多」當成偵察品質指標 → 高品質輸出比數量更重要。

---

## 關聯筆記

- [[05-DNS區域傳送AXFR與IXFR|第 5 章 - DNS 區域傳送]]
- [[06-DNS記錄深度解析|第 6 章 - DNS 記錄深度解析]]
- [[07-dig深度解析|第 7 章 - dig 深度解析]]
- [[08-host與nslookup|第 8 章 - host 與 nslookup]]
- [[10-憑證透明度|第 10 章 - 憑證透明度]]
- [[11-子網域列舉|第 11 章 - 子網域列舉]]
- [[15-dnsx|第 15 章 - dnsx]]
- [[01-Volume-1-Information-Gathering-Index|Vol.1 - Information Gathering]]
