# Appendix A - Linux Command Reference

## 標籤

- #cpts
- #appendix
- #linux
- #reference

## 用途

本附錄整理在 CPTS 流程中最常反覆使用的 Linux 指令，不取代正文章節，只作為快速查表。

## Text Processing

| 指令 | 用途 | 備註 |
|---|---|---|
| `grep` | 字串搜尋與過濾 | 常搭配 `-i`, `-r`, `-E` |
| `awk` | 欄位處理與條件輸出 | 適合日誌與掃描輸出整理 |
| `sed` | 取代、刪除、擷取行 | 常用於快速清洗資料 |
| `cut` | 依分隔符取欄位 | 適合簡單欄位拆分 |
| `sort` | 排序 | 常搭配 `-u` 去重 |
| `uniq` | 相鄰重複去重 | 通常接在 `sort` 後 |
| `jq` | JSON 處理 | Web/API 輸出很常用 |
| `xargs` | 將輸入轉成命令參數 | 適合批次處理 |

## File and Binary Inspection

| 指令 | 用途 | 備註 |
|---|---|---|
| `find` | 搜尋檔案、權限與大小 | 提權與枚舉高頻使用 |
| `locate` | 快速查檔案名稱 | 依賴索引，不保證即時 |
| `file` | 判斷檔案類型 | 分析未知 binary 很有用 |
| `strings` | 抽可列印字串 | 找線索、憑證、路徑 |
| `xxd` | 十六進位檢視 | 小型檔案與編碼分析方便 |

## Network and Transfer

| 指令 | 用途 | 備註 |
|---|---|---|
| `curl` | HTTP/TLS 請求與下載 | 偵察與 API 測試核心工具 |
| `wget` | 下載檔案 | 受限環境常見 |
| `nc` | TCP/UDP 互動與簡易 listener | 視版本能力而異 |
| `socat` | 較進階的通道與 relay | shell 穩定化很實用 |

## 常見組合

```bash
# 去重
sort file.txt | uniq

# JSON 抽欄位
jq -r '.[] | .host' results.json

# 找 SUID
find / -perm -4000 -type f 2>/dev/null
```

## 關聯筆記

- [[F-Appendix-CPTS-Cheatsheets|Appendix F - CPTS Cheatsheets]]
- [[G-Appendix-Obsidian-Folder-Structure|Appendix G - Obsidian Folder Structure]]
