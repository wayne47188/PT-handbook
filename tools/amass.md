# amass

## 標籤

- #cpts
- #tools
- #amass

## 定位

`amass` 的優勢在關聯分析與較大範圍的資產擴圖，不只列子網域，也能從組織、ASN、CIDR 與圖模型找路徑。

## 最適合回答的問題

- 組織還有哪些關聯網域與網路邊界
- 某網域的被動與主動子網域覆蓋面
- 哪些結果可回溯到哪些來源

## 常用模式

| 範例 | 用途 |
|---|---|
| `amass intel -org "Org"` | 組織視角擴圖 |
| `amass intel -asn 64500` | ASN 關聯視角 |
| `amass enum -passive -d example.com` | 被動列舉 |
| `amass enum -active -d example.com` | 主動列舉 |
| `amass enum -src -ip -d example.com` | 顯示來源與 IP |

## 常見誤判

- 圖模型關聯不等於已驗證資產。
- API key 配置不足時，輸出量與品質會明顯下降。
- 主動模式與被動模式的風險不可混為一談。

## 適合搭配

- `subfinder` / `assetfinder` 做被動補集
- `dnsx` 做解析驗證
- `httpx` / `naabu` 做後續分流

## 關聯筆記

- [[../01-Information-Gathering/12-Amass|第 12 章 - Amass]]
- [[../01-Information-Gathering/09-DNS列舉方法論|第 9 章 - DNS 列舉方法論]]
