# 第 13 章 - Subfinder

## 標籤

- #cpts
- #chapter
- #subfinder
- #projectdiscovery

## 學習目標

- 理解 Subfinder 在被動子網域列舉中的定位。
- 熟悉 `-d`、`-dL`、`-silent`、`-json`、`-cs` 等常用參數用途。
- 知道 Provider Config 與 API Key 如何影響結果品質。
- 理解它與 `dnsx`、`httpx`、`naabu` 的流程整合方式。
- 避免把快速輸出直接當成最終資產清單。

---

## 理論基礎

```text
Subfinder 的定位：被動前段蒐集工具

特色：
  - 整合多個公開被動資料來源（CT Log / DNS 資料庫 / 搜尋引擎 / 爬蟲資料）
  - 輸出乾淨，易於接入 ProjectDiscovery 生態（dnsx / httpx / naabu）
  - 速度快、設定簡單，適合快速取得第一批候選名稱

與其他被動工具比較：
  Subfinder vs Amass   → Subfinder 更輕快，Amass 有關聯圖分析
  Subfinder vs CT Log  → Subfinder 整合多來源；CT Log 擁有歷史深度
  Subfinder vs Assetfinder → 功能更完整，輸出控制更好

API Key 配置位置：
  ~/.config/subfinder/provider-config.yaml
  未配置 → 部分來源無法使用，覆蓋率下降

最佳使用方式：
  subfinder（被動蒐集）→ dnsx（DNS 驗證）→ httpx（Web 驗證）→ naabu（埠掃描）
```

---

## 單一網域列舉

```bash
# 基本被動列舉
subfinder -d example.com
# -d → 指定目標網域
# 輸出：每行一個子網域候選名稱（含 banner）

# 只輸出名稱（適合管線）
subfinder -d example.com -silent
# -silent → 不輸出 banner 與進度，只輸出名稱
# 輸出可直接 pipe 給其他工具

# 輸出到檔案
subfinder -d example.com -silent -o subfinder_out.txt
# -o → 輸出到指定檔案
# -silent + -o 是標準管線用法

# 顯示每筆結果的資料來源（可信度判讀）
subfinder -d example.com -cs -silent
# -cs → 顯示 Source 欄位（例如：certspotter、crtsh、dnsdumpster）
# 多來源同時命中的名稱，可信度通常較高
# 格式：sub.example.com [certspotter,crtsh]

# JSON 輸出（含完整來源資訊，適合後處理）
subfinder -d example.com -json -silent -o subfinder.json
# -json → JSON 格式輸出
# 每筆記錄含：host、source、input 欄位
```

---

## 批次與進階用法

```bash
# 批次列舉多個網域
subfinder -dL domains.txt -silent -o subfinder_multi.txt
# -dL → 從檔案讀取多個目標網域（每行一個）
# 適合大型評估中有多個根網域

# 指定要使用的來源（加速或針對特定來源）
subfinder -d example.com -sources crtsh,certspotter -silent
# -sources → 只使用指定的資料來源（逗號分隔）
# 適合已知某些來源對目標特別有效時

# 限制並發請求數
subfinder -d example.com -t 10 -silent
# -t → 並發請求數量（預設 10）
# 降低可減少來源封鎖風險

# 指定輸出格式
subfinder -d example.com -oJ subfinder.json   # JSON
subfinder -d example.com -oD subfinder.txt    # 純文字
# -oJ → JSON；-oD → 純文字（與 -json / -o 效果相似）
```

---

## 整合管線

```bash
# 標準 ProjectDiscovery 管線
subfinder -d example.com -silent | \
  dnsx -a -resp -silent | \
  awk '{print $1}' | \
  httpx -silent -status-code -title
# subfinder → 被動候選名稱
# dnsx -a -resp → DNS 驗證（取 A 記錄 + IP）
# awk '{print $1}' → 只取主機名稱
# httpx → Web 服務驗證（狀態碼 + 標題）

# 加入 Wildcard 過濾
WILDCARD_IP=$(dig @ns1.example.com "randxyz999.example.com" +short)

subfinder -d example.com -silent | \
  dnsx -a -resp -silent | \
  grep -v "\[${WILDCARD_IP}\]" | \
  awk '{print $1}' > hosts_live.txt
# grep -v → 排除 Wildcard IP 的假陽性結果

# 多工具合併流程
subfinder -d example.com -silent -o sub_subfinder.txt
assetfinder --subs-only example.com > sub_assetfinder.txt
cat sub_subfinder.txt sub_assetfinder.txt | sort -u > candidates.txt
dnsx -l candidates.txt -a -resp -silent -o resolved.txt
```

---

## 決策流程

```
Seed Domain
    ↓
subfinder -d example.com -silent -o subfinder_out.txt
    ↓
結果數量合理（>50）？
  太少 → 檢查 provider-config.yaml 是否配置 API Key
          加 -cs 確認有哪些來源有回應
  合理 → 繼續
    ↓
合併其他被動來源（assetfinder / amass / CT）
    ↓
dnsx 批次驗證 + Wildcard 過濾
    ↓
httpx / naabu 服務驗證
```

---

## 速查表

```bash
# 基本
subfinder -d example.com -silent                       # 基本被動列舉
subfinder -d example.com -silent -o out.txt            # 輸出到檔案
subfinder -d example.com -cs -silent                   # 顯示來源
subfinder -d example.com -json -silent -o out.json     # JSON 輸出
subfinder -dL domains.txt -silent -o multi_out.txt     # 批次列舉

# 管線
subfinder -d example.com -silent | dnsx -a -resp -silent
subfinder -d example.com -silent | dnsx -a -resp -silent | awk '{print $1}' | httpx -silent -status-code
```

---

## 常見錯誤與排查

- 沒配置 provider-config.yaml 就用結果數量評價工具 → 許多來源需要 API Key，未配置時覆蓋率大幅下降，配置後結果通常翻倍以上。
- 把 `-silent` 輸出直接當最終清單 → Subfinder 輸出仍是「候選名稱」，必須通過 dnsx 驗證才算可用資產。
- 不保留來源資訊（`-cs`）→ 後續無法判斷哪些結果可信度較高，難以排查問題。
- 沒接 dnsx 直接送服務掃描 → 大量不可解析名稱進入掃描會浪費時間並製造噪音。

---

## 關聯筆記

- [[09-DNS列舉方法論|第 9 章 - DNS 列舉方法論]]
- [[11-子網域列舉|第 11 章 - 子網域列舉]]
- [[12-Amass|第 12 章 - Amass]]
- [[14-Assetfinder|第 14 章 - Assetfinder]]
- [[15-dnsx|第 15 章 - dnsx]]
- [[16-httpx|第 16 章 - httpx]]
- [[01-Volume-1-Information-Gathering-Index|Vol.1 - Information Gathering]]
