# DNS

## 標籤

- #cpts
- #protocols
- #dns

## 定位

DNS 是資產發現、委派、郵件與身份服務線索的核心協定，也是許多誤判來源。

## 核心元件

- Stub Resolver
- Recursive Resolver
- Authoritative Server
- Root / TLD / Delegation
- Cache / TTL / Negative Cache

## CPTS 高價值問題

- 哪些名稱與記錄構成攻擊面
- 哪些結果來自 cache、wildcard 或第三方平台
- 哪些服務風險屬於 DNS 本身（AXFR、open recursion）

## 常見記錄

- `A`, `AAAA`, `CNAME`
- `MX`, `TXT`, `NS`
- `SOA`, `PTR`, `SRV`, `CAA`

## 常見誤判

- 可解析不等於服務可達
- `CNAME` 指到第三方不等於第三方全屬目標
- `NXDOMAIN` 只代表當前解析路徑下不存在

## 關聯筆記

- [[../01-Information-Gathering/04-DNS架構與解析流程|第 4 章 - DNS 架構與解析流程]]
- [[../01-Information-Gathering/06-DNS記錄深度解析|第 6 章 - DNS 記錄深度解析]]
