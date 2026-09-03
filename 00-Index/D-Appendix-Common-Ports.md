# Appendix D - Common Ports

## 標籤

- #cpts
- #appendix
- #ports
- #reference

## 用途

常見 port 只提供初始假設，不代表服務一定存在或版本一定正確。

## Common Ports

| Port | 常見服務 | 備註 |
|---|---|---|
| 21/tcp | FTP | 檔案傳輸與匿名風險 |
| 22/tcp | SSH | Linux/Unix 管理入口 |
| 25/tcp | SMTP | 郵件路由與帳號枚舉 |
| 53/tcp/udp | DNS | 解析與服務風險 |
| 80/tcp | HTTP | Web 明文服務 |
| 88/tcp/udp | Kerberos | AD 身份核心 |
| 110/tcp | POP3 | 郵件收取 |
| 111/tcp/udp | RPCbind | NFS 與 RPC 線索 |
| 123/udp | NTP | 常見 UDP 服務 |
| 135/tcp | MS RPC | Windows 服務基礎 |
| 139/tcp | NetBIOS/SMB | 舊式 SMB 線索 |
| 143/tcp | IMAP | 郵件存取 |
| 389/tcp/udp | LDAP | 目錄服務 |
| 443/tcp | HTTPS | Web/TLS 服務 |
| 445/tcp | SMB | 檔案與管理面 |
| 587/tcp | SMTP Submission | 郵件提交 |
| 636/tcp | LDAPS | 加密 LDAP |
| 1433/tcp | MSSQL | 資料庫 |
| 2049/tcp/udp | NFS | Unix/Linux 共享 |
| 3306/tcp | MySQL | 資料庫 |
| 3389/tcp | RDP | Windows 遠端管理 |
| 5432/tcp | PostgreSQL | 資料庫 |
| 5900/tcp | VNC | 遠端桌面 |
| 5985/5986 | WinRM | Windows 遠端管理 |

## 關聯筆記

- [[C-Appendix-Network-Protocol-Reference|Appendix C - Network Protocol Reference]]
- [[05-Volume-5-Common-Services-Index|Vol.5 - Attacking Common Services]]
