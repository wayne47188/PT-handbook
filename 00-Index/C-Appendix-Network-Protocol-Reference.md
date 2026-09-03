# Appendix C - Network Protocol Reference

## 標籤

- #cpts
- #appendix
- #network
- #protocols

## 用途

本附錄是 CPTS 常見協定的超精簡索引，用來提醒測試時該從哪一層思考問題。

## Layered View

| 協定 | 主要用途 | CPTS 測試重點 |
|---|---|---|
| Ethernet / ARP | 區域網路尋址 | 內網枚舉、ARP 探測 |
| IPv4 / IPv6 | 網路層傳輸 | 路由、ACL、可達性 |
| ICMP | 診斷與錯誤訊號 | 存活探測、UDP 判讀 |
| TCP | 連線導向傳輸 | 掃描、重傳、握手 |
| UDP | 無連線傳輸 | `open|filtered` 與協定特性 |
| DNS | 名稱解析 | 資產發現、服務風險 |
| HTTP / TLS | Web 與加密傳輸 | Web 架構、Header、證書 |
| SMB | 檔案與管理 | 共享、身份、橫向 |
| LDAP | 目錄查詢 | AD 架構與身分線索 |
| Kerberos | 票證認證 | AD 身份與票證路徑 |

## 使用原則

- Port 只是線索，不是服務證明。
- 同一服務常跨多層協定。
- 工具結果要回到協定語意解讀。

## 關聯筆記

- [[D-Appendix-Common-Ports|Appendix D - Common Ports]]
- [[24-Recon流程管線整合|第 24 章 - Recon 流程管線整合]]
