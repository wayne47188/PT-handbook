# 第 23 章 - Nmap 輸出證據與自動化

## 標籤

- #cpts
- #chapter
- #nmap
- #evidence
- #automation

## 學習目標

- 理解 Nmap 不同輸出格式的用途。
- 知道如何保存證據、重現關鍵結果並支援後續自動化。
- 掌握正常輸出、grepable、XML 與其他格式的使用場景。
- 避免只保留人類可讀輸出而失去機器處理價值。
- 建立可追溯的掃描記錄方法。

---

## 理論基礎

```text
為什麼輸出格式很重要？

Recon 不只是當下看結果：
  → 後續需要追溯：「當時掃到的是什麼服務？」
  → 後續需要自動化處理：把開放埠清單餵給下一個工具
  → 報告需要證據：掃描命令、時間、目標、結果、原因

Nmap 四種輸出格式：
  -oN → Normal（人類可讀，適合快速瀏覽與報告附件）
  -oX → XML（機器可讀，適合自動化、資料庫匯入、長期存檔）
  -oG → Grepable（舊格式，適合簡單 grep 處理）
  -oA → All formats（同時產生 .nmap/.xml/.gnmap，實務最推薦）

好的 evidence handling 原則：
  保留完整命令（含所有旗標）
  記錄掃描時間（script 命令加 date 前綴）
  保留 --reason 欄位（解釋判定依據）
  XML 格式供後續工具處理
  每個目標獨立命名輸出檔（不要全部覆蓋同一個檔案）
```

---

## 輸出格式使用

```bash
# 正常文字格式（人類閱讀）
nmap -sV -p 80,443 -oN scan_192.168.1.1.txt 192.168.1.1
# -oN scan_192.168.1.1.txt → 輸出 normal 格式到指定檔案
# 適合：快速回顧、報告附件、命令列輸出截圖替代

# XML 格式（機器處理）
nmap -sV -p 80,443 -oX scan_192.168.1.1.xml 192.168.1.1
# -oX → XML 格式，包含所有掃描資訊的結構化資料
# 適合：後續腳本解析（Python/Ruby）、Metasploit 匯入、資料庫整合

# Grepable 格式（簡單字串處理）
nmap -sV -p 80,443 -oG scan_192.168.1.1.gnmap 192.168.1.1
# -oG → Grepable 格式，每行包含一個主機的摘要
# 適合：grep/awk 快速過濾，但功能比 XML 少

# 同時輸出全部格式（最推薦）
nmap -sV -p 80,443 -oA scan_192.168.1.1 192.168.1.1
# -oA scan_192.168.1.1 → 產生三個檔案：
#   scan_192.168.1.1.nmap（正常文字）
#   scan_192.168.1.1.xml（XML）
#   scan_192.168.1.1.gnmap（Grepable）
# 實務上最實用；後續需要哪種格式都有

# 完整版本（含 reason，最高品質證據）
sudo nmap -sS -sV -O --reason -oA scan_192.168.1.1 192.168.1.1
# --reason → 每個埠狀態附帶判定原因（syn-ack/rst/no-response）
# 報告品質更高，有助於向客戶解釋掃描結果
```

---

## 後處理與自動化

```bash
# 從 XML 萃取開放埠（Python）
python3 -c "
import xml.etree.ElementTree as ET
tree = ET.parse('scan_192.168.1.1.xml')
for host in tree.findall('.//host'):
    for port in host.findall('.//port[@protocol=\"tcp\"]'):
        state = port.find('state')
        if state is not None and state.get('state') == 'open':
            print(f'{port.get(\"portid\")}')
"

# 從 Grepable 格式快速抓開放埠
grep "open" scan_192.168.1.1.gnmap | awk -F/ '{print $1}' | awk '{print $NF}'

# 用 grep 快速篩選特定狀態（從 .nmap 文字輸出）
grep "open" scan_192.168.1.1.nmap        # 只看開放埠
grep "filtered" scan_192.168.1.1.nmap    # 只看 filtered 埠
grep "http\|https" scan_192.168.1.1.nmap # 找 Web 相關服務

# 使用 ndiff 比較兩次掃描結果（發現變化）
ndiff scan_before.xml scan_after.xml
# ndiff → Nmap 附帶工具，比較兩個 XML 輸出的差異
# 用途：確認修復是否有效、追蹤攻擊面變化

# 使用 xsltproc 把 XML 轉成 HTML 報告
xsltproc scan_192.168.1.1.xml -o scan_report.html
# 產生可直接在瀏覽器開啟的 HTML 格式報告
```

---

## 證據保存最佳實踐

```bash
# 在命令前加時間戳記（便於追溯）
date && sudo nmap -sS -sV -O --reason -oA scan_$(date +%Y%m%d_%H%M%S)_192.168.1.1 192.168.1.1
# date → 在終端顯示執行時間（會被截圖/錄影到）
# 檔名含時間戳記 → 同一目標多次掃描不會互相覆蓋

# 建立結構化掃描目錄
mkdir -p evidence/nmap/{initial,service,targeted}
sudo nmap -sS --top-ports 100 -oA evidence/nmap/initial/quick_scan 192.168.1.0/24
sudo nmap -sV -sC -oA evidence/nmap/service/service_scan 192.168.1.1
# 分目錄保存不同階段的掃描結果

# 保留完整命令到 log 檔
echo "$(date): nmap -sV -p 80,443 --reason 192.168.1.1" >> evidence/commands.log
# 有執行歷史不代表有命令記錄；主動記錄到檔案更可靠

# 掃描後立即確認輸出
cat scan_192.168.1.1.nmap | head -50    # 快速預覽結果
wc -l scan_192.168.1.1.nmap             # 確認輸出有內容（非空檔）
```

---

## 各格式用途比較

```text
格式         | 用途                     | 優點              | 缺點
-oN (.nmap)  | 人類閱讀 / 報告附件      | 直觀易讀          | 不利於自動化
-oX (.xml)   | 自動化 / 長期存檔        | 結構完整 / 可解析 | 需要 XML parser
-oG (.gnmap) | 快速 grep/awk 處理       | 簡單快速          | 資訊較少
-oA          | 以上三種同時保留         | 最全面            | 產生三個檔案

建議預設：
  一般掃描 → -oA <prefix>（三格式都保留）
  快速查看 → -oN（或直接看終端）
  後續腳本 → -oX（解析最方便）
  回顧比較 → ndiff <xml1> <xml2>
```

---

## 決策流程

```
準備執行 Nmap 掃描
    ↓
選擇輸出格式
  快速探索 / 不需存檔 → 只看終端（不加 -o）
  一般掃描 → -oA <有意義的前綴名稱>
  需要後續腳本處理 → 確保 -oX 包含在內
  需要高品質報告證據 → 加 --reason（建議預設加）
    ↓
命名規則
  包含：目標 IP / 主機名稱 + 掃描類型 + 日期（可選）
  範例：service_scan_192.168.1.1_20250101
    ↓
掃描後
  確認輸出檔案非空
  關鍵發現記錄到 commands.log 或 notes
  需要比較前後差異 → ndiff
```

---

## 速查表

```bash
# 輸出格式
nmap -oN output.txt target                # 正常文字
nmap -oX output.xml target               # XML
nmap -oG output.gnmap target             # Grepable
nmap -oA output target                   # 三種格式同時（推薦）
nmap --reason -oA output target          # 附理由（最高品質）

# 後處理
grep "open" output.nmap                  # 找開放埠
ndiff before.xml after.xml              # 比較掃描差異
xsltproc output.xml -o report.html      # 轉 HTML 報告

# 記錄命令
echo "$(date): <命令>" >> commands.log   # 保留命令歷史
```

---

## 常見錯誤與排查

- 只看終端不保存輸出 → 幾天後無法重現或引用掃描結果，後果嚴重。
- 只保留 `-oN` 文字格式 → 無法自動化處理，後續整合很痛苦。
- 沒保留命令與時間 → 報告無法說明「此結果來自哪次掃描」。
- 預設開啟 `--packet-trace` → 輸出量暴增，真正需要時才開。
- 所有掃描存到同一個輸出前綴 → 後來的覆蓋前面；命名要帶目標資訊。

---

## 關聯筆記

- [[18-Nmap掃描生命週期與封包分析|第 18 章 - Nmap 掃描生命週期與封包分析]]
- [[22-Nmap指令碼引擎NSE|第 22 章 - Nmap 指令碼引擎（NSE）]]
- [[24-Recon流程管線整合|第 24 章 - Recon 流程管線整合]]
- [[01-Volume-1-Information-Gathering-Index|Vol.1 - Information Gathering]]
