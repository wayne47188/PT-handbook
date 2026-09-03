# 第 100 章 - CPTS 考試流程

## 標籤

- #cpts
- #chapter
- #exam
- #workflow

## 學習目標

- 將整本 Handbook 的方法整合成 CPTS 考試工作流。
- 知道如何在時間壓力下做範圍理解、優先排序、證據蒐集與報告收斂。
- 平衡 reconnaissance、exploitation、privilege escalation、AD 與 reporting。
- 避免在單一路徑卡死太久。
- 以交付導向而非技巧導向完成考試。

---

## 理論基礎

```text
CPTS 考試的核心問題：

不是「每個技巧都做一次」
而是「在有限時間內，產出可報告、可辯護、可追溯的技術結論」

五種常見失敗模式：

  失敗 1：一開始沒有建立清楚地圖
    → 直接 exploit 不認識的資產，浪費時間在錯誤目標
    → 對策：前 1-2 小時只做 Recon，畫出資產地圖

  失敗 2：在低價值路徑上花太久
    → 一個 exploit 卡 2 小時，錯過其他入口
    → 對策：設定時間閾值，卡住超過 30 分鐘就換路徑

  失敗 3：沒同步做證據整理
    → 最後才發現「有做出來，但沒有足夠證據寫報告」
    → 對策：每個成功步驟立即 tee 輸出，同步更新草稿

  失敗 4：最後報告與技術證據脫節
    → 報告結論找不到對應的截圖或命令輸出
    → 對策：finding 草稿全程維護，不要最後才開始寫

  失敗 5：技術成功但報告品質不足
    → 拿到 root 但寫不出可辯護的 finding
    → 對策：每次成功後立即填入 finding 草稿模板

交付導向原則：
  技術成功（shell / flags）≠ 考試成功
  技術成功 + 可追溯報告 = 考試成功
```

---

## 工作流五個迴圈

```text
迴圈 1：建立外部與內部資產地圖
  → Nmap / httpx / dnsx / amass
  → 目標：畫出所有可達服務的地圖
  → 輸出：IP / 埠 / 服務版本 / 主機名稱 / 網段

迴圈 2：找最短可行路徑取得新身份或主機
  → 不求完美，求最快能取得新視角的路徑
  → 優先：已驗證弱點 > 版本型 CVE > 設定弱點 > 暴力破解
  → 時間閾值：單一路徑超過 30 分鐘無進展 → 換目標

迴圈 3：每拿到新視角就重排優先級
  → 新 shell → 重新做本機 / AD enumeration
  → 問：這個新位置帶來了什麼新的攻擊面？
  → 更新資產地圖，標記已控制的主機

迴圈 4：同步保存證據與 finding 草稿
  → 每次成功步驟 → 立即 tee 輸出
  → 立即填入 finding 草稿（資產/觀測/驗證/影響）
  → 截圖命名：YYYY-MM-DD_目的_目標.png

迴圈 5：在接近結束前收斂 narrative 與 remediation
  → 保留最後 4-6 小時給報告收斂
  → 串接 finding 成 attack narrative
  → 補齊修補建議，確認每個 finding 有對應證據
```

---

## 各階段標準工作內容

```bash
# ===== 階段 1：Recon & Enumeration（資產地圖）=====

# 外部快速掃描（先廣後深）
nmap -sV -sC --open -oA evidence/recon/nmap_initial <target_range>
# --open → 只顯示開放埠，減少雜訊
# -oA   → 同時輸出 .nmap / .xml / .gnmap

# Web 服務快速枚舉
httpx -l targets.txt -title -status-code -tech-detect -o evidence/recon/httpx_all.txt
# -title       → 擷取頁面標題（快速識別應用類型）
# -tech-detect → 識別後端技術（Laravel / WordPress / ASP.NET 等）
# -status-code → 快速篩選 200 / 301 / 403

# DNS 枚舉
dnsx -d target.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
     -o evidence/recon/dnsx_subdomains.txt
# -d → 目標域名  -w → 字典  -o → 輸出檔案

# 常見失敗：在 Recon 階段就開始 exploit 特定服務
# 對策：先把所有服務列出來，再選優先目標

# ===== 階段 2：Exploitation（取得新能力）=====

# 每次 exploit 嘗試都記錄
date && curl -s "https://target.com/vuln_endpoint?payload=test" \
     2>&1 | tee -a evidence/exploit/exploit_attempts.log
# date → 記錄時間戳   tee -a → 追加模式，不覆蓋舊記錄

# 取得 shell 後立即記錄身份與環境
whoami && id && hostname && ip addr
# 這四行輸出是提權 finding 的基礎證據

# 常見失敗：卡在單一 exploit 路徑不換
# 對策：30 分鐘無進展 → 記錄嘗試狀態，換下一個目標

# ===== 階段 3：PrivEsc / Pivot（放大控制面）=====

# 本機枚舉（快速，先覆蓋廣度）
# Linux：
sudo -l                         # sudo 規則（最高價值）
find / -perm -4000 2>/dev/null  # SUID 二進位
crontab -l; ls -la /etc/cron*/  # Cron 定時任務
# Windows：
whoami /priv                    # 特權清單（SeImpersonatePrivilege 等）
net user; net localgroup administrators  # 帳號枚舉

# AD 枚舉（取得網域帳號後）
# BloodHound 蒐集（最快取得完整 AD 地圖）
python3 bloodhound.py -u <user> -p <pass> -d <domain> -c all --zip
# -c all → 蒐集所有類型的 AD 關係資料
# --zip  → 壓縮成單一檔案，方便上傳 BloodHound GUI

# 常見失敗：沒有根據新資訊重排優先級
# 對策：每次取得新 shell 都重新執行基礎枚舉

# ===== 階段 4：Evidence & Findings（同步整理）=====

# 每個成功步驟立即保存
<command> 2>&1 | tee evidence/exploit/<category>_<target>_<timestamp>.txt
# 命名包含：類別 / 目標 / 時間，避免覆蓋

# Finding 草稿同步填寫（邊測試邊更新）
# 資產：[IP / 主機名稱]
# 觀測：[sudo -l 輸出 / 截圖參照]
# 驗證：[最小化驗證步驟]
# 影響：[技術 + 業務影響]
# 狀態：Verified / Inconclusive / Rejected

# ===== 階段 5：Report（收斂）=====

# 收斂前先盤點
# □ 每個 finding 都有對應的 evidence 檔案？
# □ 每個 finding 都填了 Remediation？
# □ Finding 之間是否有 Attack Narrative 可以串接？
# □ Executive Summary 是否反映了最高風險路徑？
```

---

## 時間分配建議

```text
假設 10 天考試時間（CPTS 實際為 10 天測試 + 2 天報告）：

Day 1-2：Recon & 資產地圖
  → 全面枚舉，畫出所有服務與可能入口
  → 不要在此階段做 exploit

Day 3-5：Exploitation & Initial Foothold
  → 依優先級依序嘗試入口
  → 每 30 分鐘無進展換目標
  → 同步更新 finding 草稿

Day 6-8：PrivEsc / Pivot & AD
  → 每個新 shell 立即做枚舉
  → 優先尋找橫向移動路徑
  → BloodHound 分析 AD 控制路徑

Day 9-10（測試期最後）：
  → 補充未驗證的 finding
  → 確認所有關鍵路徑都有截圖

Day 11-12（報告期）：
  → 整理 finding 輸出格式
  → 串接 Attack Narrative
  → 撰寫 Executive Summary

常見時間分配失誤：
  → 花 80% 時間技術，剩 20% 寫報告 → 報告品質不足
  → 對策：從 Day 1 就同步維護 finding 草稿，報告期只做「整理」而非「寫作」
```

---

## 決策流程

```
開始 → 建立資產地圖（Recon）
    ↓
選擇最高價值入口（優先：已驗證弱點 > 版本 CVE > 設定弱點）
    ↓
嘗試入口（最多 30 分鐘）
  成功 → 記錄 + 填 finding 草稿 → 取得新視角後重排優先級
  失敗 → 記錄嘗試狀態 → 換下一個目標
    ↓
取得 Shell / 新帳號
  → 立即枚舉（sudo / SUID / cron / BloodHound）
  → 同步保存所有輸出（tee）
  → 填入 finding 草稿
    ↓
尋找提權 / 橫向移動路徑
  → 參照 Handbook 對應章節
  → 每個成功步驟立即記錄
    ↓
接近時間結束（保留 4-6 小時給報告收斂）
  → 盤點 finding 清單
  → 串接 Attack Narrative
  → 補充 Remediation
  → 撰寫 Executive Summary
```

---

## 速查表

```bash
# 考試開始前建立目錄結構
mkdir -p evidence/{recon,services,web,exploit,privesc,loot,screenshots}
export HISTTIMEFORMAT="%Y-%m-%d %T "       # 命令歷史加時間戳
export HISTFILE=evidence/bash_history.txt  # 命令歷史保存到 evidence

# 取得 Shell 後立即執行
whoami && id && hostname && ip addr        # 基礎身份與網路資訊
sudo -l                                    # 最高優先的提權線索
uname -a                                   # 系統版本

# Finding 草稿快速模板
# 資產：
# 觀測：
# 驗證步驟：
# 技術影響：
# 業務影響：
# 狀態：Verified / Inconclusive / Rejected

# 時間管理
# 單一路徑 > 30 分鐘無進展 → 換目標，記錄「Inconclusive - 時間限制」
# 最後 4-6 小時保留給報告收斂，不再做新的 exploit 嘗試
```

---

## 常見錯誤與排查

- 在單點 exploit 卡太久 → 設定 30 分鐘閾值，無進展就記錄狀態並換目標。
- 沒有根據新資訊重排優先級 → 每次取得新 shell / 帳號都重新評估哪條路最短。
- 證據與 finding 分離 → 每個成功步驟立即 tee 輸出，不要等到最後才補截圖。
- 直到最後才開始想報告 → Finding 草稿全程同步維護，報告期只做整理，不從零開始寫。

---

## 關聯筆記

- [[24-Recon流程管線整合|第 24 章 - Recon 流程管線整合]]
- [[95-證據蒐集|第 95 章 - 證據蒐集]]
- [[96-弱點驗證|第 96 章 - 弱點驗證]]
- [[97-報告撰寫|第 97 章 - 報告撰寫]]
- [[99-攻擊敘事|第 99 章 - 攻擊敘事]]
- [[12-Volume-12-Reporting-CPTS-Index|Vol.12 - Reporting, Documentation and CPTS Exam]]
