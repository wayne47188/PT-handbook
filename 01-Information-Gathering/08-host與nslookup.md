# 第 8 章 - host 與 nslookup

## 標籤

- #cpts
- #chapter
- #host
- #nslookup
- #dns

## 學習目標

- 理解 `host` 與 `nslookup` 在 DNS 偵察工作流中的定位。
- 掌握兩者的語法差異與適用場景。
- 知道何時用 `host`/`nslookup` 做快速驗證，何時升級到 `dig`。
- 正確解讀兩工具的輸出格式。

---

## 理論基礎

```text
三工具定位比較：

host     → 最簡潔，適合快速單次驗證；輸出清晰易讀
            優點：語法短、輸出直覺
            缺點：無法看 status code、flags 等完整協定細節

nslookup → 互動式或單次查詢；跨平台（Linux/Windows 皆有）
            優點：跨平台一致性（Windows 環境常用）
            缺點：互動模式容易出錯，輸出含雜訊（Non-authoritative answer）

dig      → 完整協定視角；適合排錯、Wildcard 偵測、證據保留
            優點：status code、flags、全部區塊可見
            缺點：語法較長，+short 外輸出較冗長

工作流定位：
  快速確認單一主機是否可解析 → host
  跨平台驗證（Windows 目標環境）→ nslookup
  Wildcard 排查 / 委派追蹤 / 證據保留 → dig
```

---

## host 指令

```bash
# 基本正向解析（A 記錄）
host example.com
# 輸出：example.com has address 93.184.216.34
# 若有多個 IP → 每行一條
# 若無法解析 → "Host example.com not found: 3(NXDOMAIN)"

# 指定查詢類型
host -t mx example.com
# -t mx → 查 MX 記錄
# 輸出：example.com mail is handled by 10 mail.example.com.

host -t txt example.com
# -t txt → 查 TXT 記錄（SPF/DKIM/DMARC）

host -t ns example.com
# -t ns → 查 NS 記錄（取得權威名稱伺服器）

host -t aaaa example.com
# -t aaaa → 查 IPv6 地址

host -t soa example.com
# -t soa → 查 SOA 記錄

host -t caa example.com
# -t caa → 查 CAA 憑證授權記錄

# 反向解析（PTR）
host 203.0.113.10
# 自動識別 IP → 做反向查詢
# 輸出：10.113.0.203.in-addr.arpa domain name pointer mail.example.com.

# Zone Transfer（AXFR）
host -l example.com ns1.example.com
# -l → 列出 Zone 所有記錄（需要 NS 允許）
# ns1.example.com → 指定向哪台 NS 發送 AXFR 請求
# 成功 → 輸出所有 Zone 記錄（A、CNAME、MX 等）
# 失敗 → "Transfer failed." 或連線拒絕

# 指定 Resolver
host example.com 8.8.8.8
# 最後加 IP → 使用指定 DNS 伺服器查詢（不加 @ 符號，與 dig 語法不同）
```

---

## nslookup 指令

```bash
# 單次查詢（非互動式）
nslookup example.com
# 輸出含兩部分：
#   Server / Address → 使用的 resolver
#   Non-authoritative answer → 快取回應（正常，代表非直接從 NS 取得）
#   Name / Address → 查詢結果

# 指定查詢類型（單次）
nslookup -type=mx example.com
# -type=mx → 指定 MX 記錄
# 等同於：nslookup -query=mx example.com（兩種寫法皆可）

nslookup -type=txt example.com
# -type=txt → TXT 記錄（SPF / DKIM / DMARC）

nslookup -type=ns example.com
# -type=ns → NS 記錄

nslookup -type=soa example.com
# -type=soa → SOA 記錄

nslookup -type=any example.com
# -type=any → 嘗試查所有記錄（不保證完整，多數 resolver 已限制）

# 指定 Resolver（單次）
nslookup example.com 8.8.8.8
# 格式：nslookup 查詢對象 resolver
# 向 8.8.8.8 查詢（不加 @ 符號）

# 反向解析（PTR）
nslookup 203.0.113.10
# 直接給 IP → nslookup 自動做 PTR 查詢

# 互動模式（謹慎使用）
nslookup
# 進入互動提示符 >
# > server 8.8.8.8      ← 切換 resolver
# > set type=mx         ← 設定記錄類型
# > example.com         ← 查詢
# > exit                ← 退出
# 注意：互動模式輸出格式與非互動不同，常有雜訊，腳本中避免使用
```

---

## 輸出差異對照

```bash
# 查詢 MX 記錄的輸出比較

# host：
host -t mx example.com
# example.com mail is handled by 10 mail.example.com.
# 清晰，直接顯示優先級與主機名稱

# nslookup：
nslookup -type=mx example.com
# Server:   192.168.1.1
# Address:  192.168.1.1#53
# Non-authoritative answer:
# example.com  mail exchanger = 10 mail.example.com.
# 含雜訊（Server 行、Non-authoritative 行）需手動過濾

# dig：
dig example.com mx +short
# 10 mail.example.com.
# 最乾淨，適合管線

# dig（完整）：
dig example.com mx
# 有 ANSWER SECTION、AUTHORITY SECTION、Query time 等
# 適合排錯與證據保留
```

---

## 決策流程

```
需要 DNS 驗證
    ↓
目標是快速確認單一主機可解析？
  是 → host sub.example.com
        → 有 address → 可解析，記錄 IP
        → not found / NXDOMAIN → 不可解析
  否 → 需要查特定記錄類型？
        是 → host -t TYPE example.com
              或 nslookup -type=TYPE example.com（跨平台場景）
  ↓
需要 Zone Transfer 嘗試？
  是 → host -l example.com ns1.example.com
        → 成功 → 直接取得 Zone 所有記錄
        → 失敗 → 改用 dig axfr 或 nmap NSE 再試
  ↓
結果可疑 / 需要完整協定細節？
  是 → 升級到 dig（加 @server、完整輸出、+trace）
  ↓
排查 Wildcard？
  是 → dig @ns1 asdf-random.example.com +short（host 無法直接偵測）
```

---

## 速查表

```bash
# host 基本
host example.com                      # 正向解析（A 記錄）
host 203.0.113.10                     # 反向解析（PTR）
host -t mx example.com                # MX 記錄
host -t txt example.com               # TXT 記錄（SPF/DMARC）
host -t ns example.com                # NS 記錄
host -t aaaa example.com              # IPv6 記錄
host -t caa example.com               # CAA 記錄
host -l example.com ns1.example.com   # Zone Transfer
host example.com 8.8.8.8              # 指定 Resolver

# nslookup 基本
nslookup example.com                  # 正向解析
nslookup -type=mx example.com         # MX 記錄
nslookup -type=txt example.com        # TXT 記錄
nslookup -type=ns example.com         # NS 記錄
nslookup -type=soa example.com        # SOA 記錄
nslookup 203.0.113.10                 # 反向解析
nslookup example.com 8.8.8.8          # 指定 Resolver
```

---

## 常見錯誤與排查

- 用 `host` 或 `nslookup` 做 Wildcard 判斷 → 這兩個工具沒有直接的 Wildcard 偵測機制，需改用 `dig @ns`。
- `nslookup` 互動模式在腳本中使用 → 互動模式輸出格式不穩定，腳本中一律用非互動模式（加 `-type=` 參數）。
- `host -l` 失敗就放棄 Zone Transfer → 失敗代表該 NS 有 ACL 限制；仍應嘗試 `dig axfr @ns2.example.com example.com`（換其他 NS）。
- 看到 `Non-authoritative answer` 就擔心資料不準確 → 這是正常現象，代表資料來自快取 resolver，不代表錯誤；若需要確認，改用 `@ns1.example.com` 直查。

---

## 關聯筆記

- [[07-dig深度解析|第 7 章 - dig 深度解析]]
- [[05-DNS區域傳送AXFR與IXFR|第 5 章 - DNS 區域傳送]]
- [[09-DNS列舉方法論|第 9 章 - DNS 列舉方法論]]
- [[01-Volume-1-Information-Gathering-Index|Vol.1 - Information Gathering]]
