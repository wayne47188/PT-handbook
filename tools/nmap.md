# nmap

## 標籤

- #cpts
- #tools
- #nmap

## 定位

`nmap` 是服務驗證、版本辨識、NSE、OS fingerprint 與證據保存的核心工具。它不只是掃埠器，而是一套分階段的網路探測框架。

## 最適合回答的問題

- 這台主機哪些埠在目前探測條件下是 `open/closed/filtered`
- 這些埠後面大概是什麼服務
- 某個服務是否值得進一步做 NSE 或研究
- 封包層觀測與工具判讀是否一致

## 常用模式

| 類型 | 範例 | 用途 |
|---|---|---|
| Host discovery | `nmap -sn target` | 只看主機存活 |
| Basic scan | `nmap -sS target` | 基本 TCP 掃描 |
| Service detect | `nmap -sV target` | 服務/版本辨識 |
| UDP | `nmap -sU -p 53,161 target` | 重點 UDP 驗證 |
| NSE | `nmap --script default,safe target` | 腳本型資訊蒐集 |
| Evidence | `nmap --reason -oA scan target` | 保存多格式證據 |

## 高價值旗標

- `-sS`, `-sT`, `-sU`
- `-sV`, `-O`
- `--reason`, `--packet-trace`
- `--script`, `--script-help`
- `-oA`

## 常見誤判

- `open` 不等於完整服務辨識已成立。
- `-sV` 推測不等於實際版本事實。
- `open|filtered` 在 UDP 很常見，不等於弱點。
- 代理、NAT、WAF、SYN proxy 會改變判讀。

## 適合搭配

- `naabu` 做前段 port discovery
- `httpx` 驗證 Web 類服務
- `tcpdump` / Wireshark 做封包交叉驗證

## 關聯筆記

- [[../01-Information-Gathering/17-Naabu與Nmap掃描分工|第 17 章 - Naabu 與 Nmap 掃描分工]]
- [[../01-Information-Gathering/18-Nmap掃描生命週期與封包分析|第 18 章 - Nmap 掃描生命週期與封包分析]]
- [[../01-Information-Gathering/22-Nmap指令碼引擎NSE|第 22 章 - Nmap 指令碼引擎（NSE）]]
