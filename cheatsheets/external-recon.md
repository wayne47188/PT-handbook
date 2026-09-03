# External Recon

## 標籤

- #cpts
- #cheatsheets
- #recon

```bash
whois example.com
dig ns example.com +short
dig mx example.com +short
subfinder -silent -d example.com
assetfinder --subs-only example.com
amass enum -passive -d example.com
dnsx -l hosts.txt -wd example.com
httpx -l resolved.txt -sc -title -tech-detect
naabu -list resolved.txt -top-ports 100
nmap -sV -oA scan target
```

## 關聯筆記

- [[../01-Information-Gathering/24-Recon流程管線整合|第 24 章 - Recon 流程管線整合]]
