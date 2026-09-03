# HTB CPTS Handbook

## 標籤
- #cpts
- #handbook
- #index

## 定位

這份 Handbook 依據 [HTB-CPTS-Handbook-Outline.md](/home/wayne/personal-knowledge/HTB-CPTS-Handbook-Outline.md) 建立，目標不是翻譯 HTB 課程，而是整理成可長期維護、可在 Obsidian 中持續擴充的 CPTS 滲透測試知識庫。

目前先完成整體骨架、卷別索引與章節規格，後續可依建議順序逐章補完內容。

## 使用原則

- 明確區分觀測結果、工具推測、作者推論與已驗證事實。
- 侵入性操作必須標示授權、影響與風險。
- 掃描器結果不能直接視為漏洞證據，必須驗證。
- 每章都應包含學習目標、核心概念、實戰範例、排錯、攻防觀點與 CPTS 重點。

## 建議撰寫順序

1. 先完成 Vol.1 的 Chapter 19-24。
2. 再依 CPTS 課程主軸補完 Vol.2-Vol.11。
3. 每完成一章，同步更新 Cheatsheet、關聯筆記與相關索引。
4. 每 5-10 章做一次術語、工具版本與交叉連結審查。
5. 最後完成 Reporting 與 Exam Workflow，收斂成可實戰使用的手冊。

## 卷別索引

- [[01-Information-Gathering/01-Volume-1-Information-Gathering-Index|Vol.1 - Information Gathering]]
- [[02-Footprinting/02-Volume-2-Footprinting-Index|Vol.2 - Footprinting]]
- [[03-Vulnerability-Assessment/03-Volume-3-Vulnerability-Assessment-Index|Vol.3 - Vulnerability Assessment]]
- [[04-Web/04-Volume-4-Web-Index|Vol.4 - Web Information Gathering and Attacks]]
- [[05-Common-Services/05-Volume-5-Common-Services-Index|Vol.5 - Attacking Common Services]]
- [[06-Shells-Payloads/06-Volume-6-Shells-and-Payloads-Index|Vol.6 - Shells and Payloads]]
- [[07-Password-Attacks/07-Volume-7-Password-Attacks-Index|Vol.7 - Password Attacks]]
- [[08-Pivoting/08-Volume-8-Pivoting-Index|Vol.8 - Pivoting, Tunneling and Port Forwarding]]
- [[09-Active-Directory/09-Volume-9-Active-Directory-Index|Vol.9 - Active Directory Enumeration and Attacks]]
- [[10-Windows-Privilege-Escalation/10-Volume-10-Windows-Privilege-Escalation-Index|Vol.10 - Windows Privilege Escalation]]
- [[11-Linux-Privilege-Escalation/11-Volume-11-Linux-Privilege-Escalation-Index|Vol.11 - Linux Privilege Escalation]]
- [[12-Reporting-CPTS/12-Volume-12-Reporting-CPTS-Index|Vol.12 - Reporting, Documentation and CPTS Exam]]

## 附錄與模板

- [[00-Index/98-章節模板|單章模板]]
- [[00-Index/99-Appendices|附錄索引]]

## 參考資料

- [[tools/00-Tools-Index|工具索引]]
- [[protocols/00-Protocols-Index|協定索引]]
- [[knowledge/00-Knowledge-Index|知識點索引]]
- [[cheatsheets/00-Cheatsheets-Index|Cheatsheet 索引]]

## 後續擴充建議

- 在 `tools/` 建立各工具專頁，例如 `nmap.md`、`httpx.md`、`amass.md`。
- 在 `protocols/` 建立 DNS、SMB、LDAP、Kerberos 等協定基礎頁。
- 在 `knowledge/` 整理通用概念，例如 `false-positive.md`、`scope-and-roe.md`、`evidence-handling.md`。
- 在 `cheatsheets/` 維護可直接帶進 Lab 或考試的精簡指令集。
