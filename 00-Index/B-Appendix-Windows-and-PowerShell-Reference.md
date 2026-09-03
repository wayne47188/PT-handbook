# Appendix B - Windows and PowerShell Reference

## 標籤

- #cpts
- #appendix
- #windows
- #powershell
- #reference

## 用途

本附錄整理 Windows 與 PowerShell 常見枚舉、檔案處理與連線檢查指令。

## File and Content

| 指令 | 用途 | 備註 |
|---|---|---|
| `Get-ChildItem` | 列目錄與檔案 | `ls`, `dir` 別名常見 |
| `Get-Content` | 讀取檔案內容 | 等同 `cat` 類用途 |
| `Select-String` | 搜尋字串 | PowerShell 版 `grep` |

## Network and Connectivity

| 指令 | 用途 | 備註 |
|---|---|---|
| `Get-NetTCPConnection` | 檢查 TCP 連線 | 看本機埠與狀態 |
| `Test-NetConnection` | 測試連線與埠 | 比 `ping` 更實用 |
| `Resolve-DnsName` | DNS 查詢 | 常用於內部枚舉 |

## Web and Transfer

| 指令 | 用途 | 備註 |
|---|---|---|
| `Invoke-WebRequest` | HTTP 請求與下載 | PowerShell 常用下載方式 |
| `certutil` | 下載、編碼、憑證處理 | 常見於檔案傳輸場景 |
| `bitsadmin` | 背景傳輸 | 較舊但仍可能存在 |

## 常見組合

```powershell
# 搜尋設定中的關鍵字
Get-ChildItem -Recurse | Select-String "password"

# 測試遠端服務
Test-NetConnection 10.10.10.10 -Port 445

# 下載檔案
Invoke-WebRequest -Uri http://10.10.10.1/tool.exe -OutFile tool.exe
```

## 關聯筆記

- [[F-Appendix-CPTS-Cheatsheets|Appendix F - CPTS Cheatsheets]]
- [[81-Windows安全模型|第 81 章 - Windows 安全模型]]
