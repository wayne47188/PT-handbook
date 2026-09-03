# Appendix E - Tool Matrix

## 標籤

- #cpts
- #appendix
- #tools
- #matrix

## 用途

本附錄將整本 Handbook 常見工具按階段整理成高階矩陣。

## Matrix

| 階段 | 工具 | 主要用途 | 輸出 | 注意事項 |
|---|---|---|---|---|
| Recon | `whois`, `dig`, `subfinder`, `amass` | 發現資產與關聯 | 網域、子網域、ASN | 被動與主動要分清 |
| Validation | `dnsx`, `httpx`, `naabu`, `nmap` | 驗證名稱、Web、埠與服務 | 可解析主機、Web 指紋、開放埠 | 工具推測不能直當事實 |
| Vuln Assessment | Nessus, OpenVAS, Web Scanners | 找候選弱點 | 候選 finding | 一定要人工驗證 |
| Common Services | `smbclient`, `showmount`, `snmpwalk` | 協定枚舉 | 共享、export、系統資訊 | 重點在權限與價值 |
| AD | LDAP/Kerberos/SMB 工具 | 建立攻擊路徑 | 物件、關係、票證線索 | 要收斂到控制鏈 |
| Pivoting | SSH, Chisel, Ligolo-ng, ProxyChains | 建 tunnel 與路由 | 可達內網服務 | 路由與 DNS 最常出錯 |
| Reporting | 結構化筆記、XML/JSON 輸出 | 保存證據與 finding | 可追溯證據集 | 報告不是工具原文貼上 |

## 關聯筆記

- [[F-Appendix-CPTS-Cheatsheets|Appendix F - CPTS Cheatsheets]]
- [[24-Recon流程管線整合|第 24 章 - Recon 流程管線整合]]
