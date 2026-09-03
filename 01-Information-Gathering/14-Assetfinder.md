# 第 14 章 - Assetfinder

## 標籤

- #cpts
- #chapter
- #assetfinder
- #subdomain

## 學習目標

- 理解 Assetfinder 在被動子網域蒐集中的定位。
- 熟悉 `--subs-only` 的典型用途與限制。
- 知道它與 Subfinder、Amass 的差異與互補方式。
- 理解如何把快速被動結果整合進驗證管線。
- 避免因工具簡單而過度信任輸出品質。

---

## 理論基礎

```text
Assetfinder 的定位：輕量快速的被動補集工具

特色：
  - 語法極簡，幾乎無需配置
  - 查詢多個公開來源（crt.sh / certspotter / hackertarget 等）
  - 速度快，適合快速補充被動候選
  - 不需要 API Key（但因此覆蓋率相對有限）

與其他工具比較：
  Assetfinder vs Subfinder → Assetfinder 更簡單；Subfinder 功能更完整
  Assetfinder vs Amass     → Assetfinder 只做名稱蒐集；Amass 有關聯圖分析

最佳使用方式：
  作為被動來源補集（與 Subfinder / CT Log 合併），不應單獨使用

典型貢獻場景：
  → 在小型目標或特定來源上抓到其他工具未命中的歷史名稱
  → 快速取得初步候選，節省偵察前段時間
```

---

## 基本用法

```bash
# 基本查詢（含相關資產，可能含非子網域結果）
assetfinder example.com
# 輸出：所有與 example.com 相關的公開名稱
# 可能包含：
#   example.com 本身
#   sub.example.com（子網域）
#   other-domain.com（相關資產，非子網域）
# → 需要後處理過濾

# 只輸出子網域格式（推薦用法）
assetfinder --subs-only example.com
# --subs-only → 只保留以 .example.com 結尾的子網域
# 排除 example.com 本身與其他不相關名稱
# 輸出更乾淨，直接可以進入驗證流程

# 輸出到檔案
assetfinder --subs-only example.com > assetfinder_out.txt
# > → 重定向到檔案
# 供後續合併使用

# 直接接入管線
assetfinder --subs-only example.com | dnsx -a -resp -silent
# 快速管線：被動蒐集 → DNS 驗證
```

---

## 整合多工具補集

```bash
# 標準補集流程：與 Subfinder 合併
subfinder -d example.com -silent > sub_subfinder.txt
assetfinder --subs-only example.com > sub_assetfinder.txt

# 合併並去重
cat sub_subfinder.txt sub_assetfinder.txt | sort -u > candidates_passive.txt
# sort -u → 兩個工具的死角互補，合併後去重

# 加入 CT Log
curl -s "https://crt.sh/?q=%25.example.com&output=json" \
  | jq -r '.[].name_value' | sed 's/\*\.//g' >> candidates_passive.txt
sort -u candidates_passive.txt -o candidates_passive.txt

# 最終批次驗證
dnsx -l candidates_passive.txt -a -resp -silent -o resolved.txt
```

---

## 決策流程

```
需要被動子網域候選？
    ↓
已有 Subfinder 輸出？
  是 → 額外加跑 Assetfinder 補集
        assetfinder --subs-only example.com > assetfinder_out.txt
        cat subfinder_out.txt assetfinder_out.txt | sort -u > candidates.txt
  否 → 先跑 Subfinder，再用 Assetfinder 補
    ↓
合併進整體候選清單（加 CT Log / Amass）
    ↓
dnsx 批次驗證 + Wildcard 過濾
    ↓
送入後續服務驗證（httpx / naabu）
```

---

## 速查表

```bash
# 基本
assetfinder example.com                            # 含相關資產
assetfinder --subs-only example.com                # 只輸出子網域
assetfinder --subs-only example.com > out.txt      # 輸出到檔案

# 管線
assetfinder --subs-only example.com | dnsx -a -resp -silent

# 補集合併
cat subfinder_out.txt assetfinder_out.txt | sort -u > candidates.txt
```

---

## 常見錯誤與排查

- 不用 `--subs-only` 導致輸出混入非子網域結果 → 一律加 `--subs-only`，輸出更乾淨。
- 把 Assetfinder 當成完整子網域方案 → 它是補集工具，必須與 Subfinder / Amass / CT 合用。
- 直接把結果送掃描器，沒過 dnsx 驗證 → 會把大量不可解析的歷史名稱帶進掃描，浪費資源。
- 用結果數量評價工具好壞 → Assetfinder 本來就比 Subfinder 少，它的價值在於補差集，不在於數量。

---

## 關聯筆記

- [[11-子網域列舉|第 11 章 - 子網域列舉]]
- [[12-Amass|第 12 章 - Amass]]
- [[13-Subfinder|第 13 章 - Subfinder]]
- [[15-dnsx|第 15 章 - dnsx]]
- [[01-Volume-1-Information-Gathering-Index|Vol.1 - Information Gathering]]
