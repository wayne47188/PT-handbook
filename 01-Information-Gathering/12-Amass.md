# 第 12 章 - Amass

## 標籤

- #cpts
- #chapter
- #amass
- #subdomain

## 學習目標

- 理解 Amass 在資產關聯分析與子網域列舉中的定位。
- 熟悉 `enum`、`intel` 與被動/主動模式的用途差異。
- 知道如何從 Domain、Organization、ASN、CIDR 等入口擴展資產。
- 理解 Data Source、API Key、遞迴列舉與輸出整理的實務重點。
- 避免把 Amass 圖模型輸出直接當成已驗證事實。

---

## 理論基礎

```text
Amass 的核心定位：資產關聯分析，不只是列出子網域

兩個主要子命令：
  amass intel → 情報蒐集模式
                從組織名稱、ASN、CIDR、反向 WHOIS 擴展候選範圍
                用於：發現與目標相關的其他網域、網段
  amass enum  → 列舉模式
                針對特定網域做子網域發現
                被動（-passive）→ 只用外部資料來源，風險低
                主動（-active）→ 直接查詢 DNS，覆蓋率更高

與其他工具的差異：
  Amass vs Subfinder → Amass 有關聯圖分析；Subfinder 更輕快
  Amass vs Assetfinder → Amass 功能更完整；Assetfinder 適合快速補集

API Key 的重要性：
  未配置 API Key → 很多來源無法查詢，結果大幅減少
  配置 ~/.config/amass/datasources.yaml → 最大化來源覆蓋率
```

---

## amass intel（情報蒐集）

```bash
# 從組織名稱查找關聯網域
amass intel -org "Example Corp"
# -org → 從公開 WHOIS 資料查詢組織名稱相關記錄
# 輸出：與該組織相關的網域名稱
# 注意：組織名稱可能模糊，需人工過濾不相關結果

# 從 ASN 反推關聯資產
amass intel -asn 64500
# -asn → 從指定 ASN 查詢其宣告的 IP Prefix 與相關網域
# 用途：確認目標自有 ASN 範圍（詳見第 3 章 ASN 偵察）

# 從 IP 範圍反推相關網域
amass intel -cidr 203.0.113.0/24
# -cidr → 從 IP 段反查相關 WHOIS 與 PTR 記錄
# 有助於發現同段內的其他目標資產

# 顯示輸出來源（判讀可信度）
amass intel -org "Example Corp" -src
# -src → 每筆結果顯示資料來源
# 多來源同時出現 → 可信度較高
```

---

## amass enum（子網域列舉）

```bash
# 被動列舉（推薦先用這個）
amass enum -passive -d example.com
# -passive → 只用外部被動資料來源，不直接查詢目標 DNS
# 風險低、速度快，適合前期擴圖
# 結果受 API Key 配置影響

# 被動列舉並輸出到檔案
amass enum -passive -d example.com -o amass_passive.txt
# -o → 輸出純名稱到檔案（方便後續去重與驗證）

# 顯示來源與解析 IP（人工判讀模式）
amass enum -passive -src -ip -d example.com
# -src → 顯示每筆結果的資料來源
# -ip → 顯示解析到的 IP 位址
# 有助於快速識別高可信度結果與第三方代管

# 主動列舉（更高覆蓋率，需授權）
amass enum -active -d example.com -o amass_active.txt
# -active → 直接對 DNS 做查詢（包括暴力列舉）
# 覆蓋率較被動高，但對目標周邊基礎設施有更多直接請求
# 確認已在授權範圍內才使用

# 批次列舉多個網域
amass enum -passive -df domains.txt -o amass_multi.txt
# -df → 從檔案讀取多個目標網域（每行一個）
# 適合大型評估中有多個根網域的情況

# 遞迴列舉（從已知子網域繼續擴展）
amass enum -active -d example.com -max-depth 3
# -max-depth → 遞迴擴展深度（預設值視版本而定）
# 從已知子網域繼續發現更深層名稱空間
```

---

## 輸出整合

```bash
# 將 Amass 結果整合進整體候選清單
cat amass_passive.txt amass_active.txt | sort -u >> candidates_all.txt
# sort -u → 去重後附加到整體候選清單

# JSON 輸出（詳細資訊，方便後處理）
amass enum -passive -d example.com -json amass_output.json
# -json → JSON 格式輸出（含名稱、來源、IP、ASN 等關聯資訊）

# 從 JSON 萃取名稱
jq -r '.name' amass_output.json | sort -u
# .name → 萃取 name 欄位（子網域名稱）
# sort -u → 去重

# 從 JSON 萃取來源（判斷可信度）
jq -r '"\(.name) [\(.sources[])]"' amass_output.json 2>/dev/null | head -20
# .sources[] → 展開來源陣列
# 多個來源出現同一名稱 → 可信度較高
```

---

## 決策流程

```
目標已知（Seed Domain / Org / ASN）
    ↓
是否需要從組織/ASN 擴展其他網域？
  是 → amass intel -org "..." 或 -asn ASN_NUMBER
       整理出所有相關根網域清單
  否 → 直接進入列舉
    ↓
amass enum -passive -d example.com -o output.txt
  → 被動模式先跑（低風險，快速取得候選）
    ↓
評估結果品質
  結果太少（API Key 不足）→ 配置 datasources.yaml 後重跑
  結果足夠 → 整合進多工具候選清單
    ↓
需要更高覆蓋率且已確認授權？
  是 → amass enum -active -d example.com（主動模式）
    ↓
整合進整體子網域列舉流程（第 11 章）
→ 合併去重 → dnsx 驗證 → httpx / naabu
```

---

## 速查表

```bash
# intel 情報蒐集
amass intel -org "Example Corp"        # 從組織名稱擴展
amass intel -asn 64500                 # 從 ASN 擴展
amass intel -cidr 203.0.113.0/24       # 從 IP 段擴展

# enum 子網域列舉
amass enum -passive -d example.com -o amass_passive.txt
amass enum -active -d example.com -o amass_active.txt
amass enum -passive -src -ip -d example.com      # 顯示來源與 IP
amass enum -passive -df domains.txt -o amass_multi.txt
amass enum -passive -d example.com -json amass.json

# 後處理
jq -r '.name' amass.json | sort -u               # 萃取名稱
cat amass_passive.txt | sort -u >> candidates.txt # 整合候選清單
```

---

## 常見錯誤與排查

- 沒配置 API Key 卻用結果數量評價工具好壞 → Amass 許多來源需要 API Key，未配置時結果品質大幅下降；配置 `~/.config/amass/datasources.yaml` 才能發揮全部潛力。
- 把圖模型中所有節點當成已確認資產 → Amass 的關聯線索（ASN 相關網域、間接關聯）不等於可掃描目標，必須通過 DNS 驗證。
- 沒保留資料來源資訊就丟進後續 → 用 `-src` 或 JSON 模式保留來源，方便判斷可信度與排查問題。
- 被動與主動模式混用但沒記錄 → 在報告或筆記中明確標記使用哪種模式。

---

## 關聯筆記

- [[03-ASN與BGP資產發現|第 3 章 - ASN 與 BGP 資產發現]]
- [[09-DNS列舉方法論|第 9 章 - DNS 列舉方法論]]
- [[11-子網域列舉|第 11 章 - 子網域列舉]]
- [[13-Subfinder|第 13 章 - Subfinder]]
- [[15-dnsx|第 15 章 - dnsx]]
- [[01-Volume-1-Information-Gathering-Index|Vol.1 - Information Gathering]]
