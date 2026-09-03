# httpx

## 標籤

- #cpts
- #tools
- #httpx

## 定位

`httpx` 是 Web 資產探測與 profiling 工具，適合把「可解析主機」收斂成「值得深入研究的 Web 服務」。

## 最適合回答的問題

- 哪些主機有 HTTP/HTTPS
- 回什麼狀態碼、標題、長度、重導與 TLS 線索
- 哪些站點看起來像登入頁、管理面、API 或共享錯誤頁

## 常用模式

| 範例 | 用途 |
|---|---|
| `httpx -l hosts.txt` | 基本 Web 探測 |
| `httpx -l hosts.txt -sc -title -server -cl` | 基本分群 |
| `httpx -l hosts.txt -follow-redirects` | 看實際落點 |
| `httpx -l hosts.txt -tech-detect` | 技術指紋 |
| `httpx -l hosts.txt -json` | 後續自動化 |

## 常見誤判

- 指紋結果是推測，不是已驗證技術棧。
- 共用前端/WAF/CDN 可能讓很多主機看起來一樣。
- 單看 status code 容易把統一錯誤頁當成真站點。

## 適合搭配

- `dnsx` 做主機解析驗證
- `nmap` 驗證非 Web 埠
- proxy/browser 做進一步手動流程分析

## 關聯筆記

- [[../01-Information-Gathering/16-httpx|第 16 章 - httpx]]
- [[../04-Web/35-Web列舉|第 35 章 - Web 列舉]]
