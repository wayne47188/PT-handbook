# 第 35A 章 - 應用程式探索與 CMS 列舉

## 標籤

- #cpts
- #chapter
- #web
- #enumeration
- #cms

## 學習目標

- 能用 Nmap + EyeWitness/Aquatone 快速盤點大型環境的 Web 攻擊面。
- 能識別 WordPress、Joomla、Drupal 並做版本/外掛列舉。
- 知道如何針對不同 CMS 找對應的高價值測試點。

---

## 理論基礎：大型環境的 Web 盤點流程

```
Scope → Nmap Web Port 掃描 → 截圖報告（EyeWitness/Aquatone）
    → 高價值主機分群 → CMS 指紋辨識 → 深入列舉
```

高價值主機特徵：命名含 dev/test/admin/jenkins/gitlab、已知平台（Splunk/PRTG/Tomcat）、CMS 且可公開登入。

---

## 方法一：Web Port 掃描

```bash
# 快速掃常見 Web Port（從 scope_list）
nmap -p 80,443,8000,8080,8180,8888,10000 --open -oA web_discovery -iL scope_list
# -p 80,443,...  → 常見 Web Port
# --open         → 只顯示開放 Port
# -oA web_discovery → 輸出三種格式（.nmap/.xml/.gnmap）
# -iL scope_list    → 從清單讀取目標

# 補版本偵測（確認是什麼服務）
nmap -sV -p 80,443,8080 --open TARGET_SUBNET
# -sV → 服務版本偵測
# 看 Server banner、版本號、產品名稱

# 輸出 URL 清單（供後續工具使用）
awk '/80\/tcp open/{print "http://"$1}' web_discovery.gnmap > urls.txt
awk '/443\/tcp open/{print "https://"$1}' web_discovery.gnmap >> urls.txt
```

---

## 方法二：EyeWitness 截圖報告

```bash
# 從 Nmap XML 生成截圖報告
eyewitness --web -x web_discovery.xml -d eyewitness_out
# --web             → Web 截圖模式
# -x web_discovery.xml → Nmap XML 輸出
# -d eyewitness_out → 輸出目錄
# 生成 HTML 報告，每個主機一張截圖

# 從 URL 清單
eyewitness --web -f urls.txt -d eyewitness_out --threads 10
# -f urls.txt  → URL 清單輸入
# --threads 10 → 10 個並發執行緒

# 常見截圖排序優先級
# 1. 有登入頁面的主機
# 2. 命名含 admin/jenkins/gitlab/dev 的
# 3. 顯示版本或錯誤的主機
# 4. 一般前台頁面（最後看）
```

---

## 方法三：Aquatone 截圖

```bash
# 從 Nmap XML 輸入
cat web_discovery.xml | aquatone -nmap -out aquatone_out
# -nmap → 接受 Nmap XML 格式
# -out  → 輸出目錄

# 從 URL 清單
cat urls.txt | aquatone -out aquatone_out -threads 10
# -threads → 並發數（預設 6）

# 輸出：aquatone_out/aquatone_report.html → 截圖報告
```

---

## 方法四：WordPress 列舉

```bash
# WPScan - WordPress 專用掃描器
wpscan --url http://TARGET
# 基本掃描：版本、主題、外掛、使用者列舉

# 詳細列舉外掛（含停用的）
wpscan --url http://TARGET --enumerate ap
# --enumerate ap → all plugins（所有外掛）
# --enumerate vp → vulnerable plugins（只看有已知漏洞的）
# --enumerate at → all themes
# --enumerate u  → users（使用者列舉）

# 完整列舉
wpscan --url http://TARGET --enumerate u,ap,at,tt,cb,dbe
# u   → users
# ap  → all plugins
# at  → all themes
# tt  → timthumbs（縮圖處理器）
# cb  → config backups（設定檔備份）
# dbe → db exports（資料庫匯出）

# 加 API token（更多已知漏洞資料）
wpscan --url http://TARGET --api-token YOUR_TOKEN --enumerate vp

# 密碼爆破（找到使用者後）
wpscan --url http://TARGET -U admin -P /usr/share/wordlists/rockyou.txt
# -U → 指定使用者名稱
# -P → 密碼字典

# 手動 WordPress 線索
curl http://TARGET/robots.txt
curl http://TARGET/wp-login.php -I      # 200 → WP 確認
curl http://TARGET/readme.html           # 版本號
curl http://TARGET/wp-content/plugins/  # 目錄列表
# 原始碼搜尋：grep "generator" → <meta name="generator" content="WordPress 5.8">
```

---

## 方法五：Joomla 列舉

```bash
# droopescan（支援 Joomla/Drupal/SilverStripe）
droopescan scan joomla -u http://TARGET
# scan joomla → Joomla 掃描模式
# 輸出：版本、元件、主題、使用者

# 手動 Joomla 線索
curl http://TARGET/robots.txt
curl http://TARGET/administrator/                          # 管理面
curl http://TARGET/README.txt                              # 版本
curl http://TARGET/administrator/manifests/files/joomla.xml | grep version
# joomla.xml → XML manifest 含明確版本號

# 確認 Joomla
curl http://TARGET -s | grep -i "joomla"
# 原始碼通常有 "Joomla!" 字串

# joomscan（替代工具）
joomscan -u http://TARGET
# 輸出：版本、元件、弱點、目錄
```

---

## 方法六：Drupal 列舉

```bash
# droopescan（Drupal 支援最佳）
droopescan scan drupal -u http://TARGET
# 輸出：版本範圍、已安裝主題、外掛

# 手動 Drupal 線索
curl http://TARGET/CHANGELOG.txt     # 版本（Drupal 7/8 有此檔）
curl http://TARGET/core/CHANGELOG.txt  # Drupal 9+
curl http://TARGET/user/login        # 登入頁
curl http://TARGET/node/1            # 第一個節點（確認 Drupal）

# 版本特徵
# Drupal 7：/CHANGELOG.txt、/misc/drupal.js
# Drupal 8/9：/core/CHANGELOG.txt、/core/misc/drupal.js

# 找可利用模組
curl http://TARGET/modules/
# Drupalgeddon2（CVE-2018-7600）影響 Drupal < 7.58 / 8.3.9
# 找到版本後查 searchsploit
searchsploit drupal 7
```

---

## 高價值目標優先級

```
發現主機後排序
    ↓
高優先級
    ├─ 命名含 dev/test/staging → 通常無嚴格防護
    ├─ jenkins/gitlab/bitbucket → 程式碼儲存庫、CI/CD
    ├─ splunk/prtg/nagios → 監控平台（常有預設憑證）
    ├─ tomcat/jboss/weblogic → Java 應用（管理面）
    └─ CMS + 可公開登入 → 常有弱密碼
    ↓
中優先級
    ├─ WordPress/Joomla/Drupal（一般站）
    └─ 自訂應用但可登入
    ↓
低優先級
    └─ 純靜態頁面、CDN 後方無功能的前台
```

---

## 速查表

```bash
# Nmap Web 掃描
nmap -p 80,443,8000,8080,8888,10000 --open -oA web_discovery -iL scope_list

# EyeWitness
eyewitness --web -x web_discovery.xml -d eyewitness_out

# WordPress
wpscan --url http://TARGET --enumerate u,ap,at
wpscan --url http://TARGET -U admin -P rockyou.txt

# Joomla
droopescan scan joomla -u http://TARGET
curl http://TARGET/administrator/manifests/files/joomla.xml | grep version

# Drupal
droopescan scan drupal -u http://TARGET
curl http://TARGET/CHANGELOG.txt

# 通用線索
curl http://TARGET/robots.txt
curl http://TARGET/readme.html
curl http://TARGET/sitemap.xml
```

---

## 關聯筆記

- [[35-Web列舉|第 35 章 - Web 列舉]]
- [[36-Web請求分析|第 36 章 - Web 請求分析]]
- [[04-Volume-4-Web-Index|Vol.4 - Web Information Gathering and Attacks]]
