# dnsx

## 標籤

- #cpts
- #tools
- #dnsx

## 定位

`dnsx` 是名稱解析與 DNS 驗證層工具，最適合放在名稱發現與服務探測之間做降噪。

## 最適合回答的問題

- 哪些候選主機真的可解析
- 解析到什麼 `A/AAAA/CNAME/MX/TXT`
- 是否疑似 wildcard 污染

## 常用模式

| 範例 | 用途 |
|---|---|
| `dnsx -l hosts.txt` | 基本解析 |
| `dnsx -l hosts.txt -a -aaaa -cname -mx -txt` | 多記錄類型 |
| `dnsx -l hosts.txt -wd example.com` | Wildcard 檢測 |
| `dnsx -l hosts.txt -json` | 結構化輸出 |
| `dnsx -l hosts.txt -r resolvers.txt` | 自訂 resolver 集合 |

## 常見誤判

- 可解析不等於可利用。
- 指到第三方平台的 `CNAME` 不等於自有主機。
- Resolver 品質差會讓結果非常不穩。

## 適合搭配

- `subfinder`, `amass`, `assetfinder`
- `httpx`
- `dig` 做人工交叉驗證

## 關聯筆記

- [[../01-Information-Gathering/15-dnsx|第 15 章 - dnsx]]
- [[../01-Information-Gathering/07-dig深度解析|第 7 章 - dig 深度解析]]
