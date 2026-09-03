# Appendix F - CPTS Cheatsheets

## 標籤

- #cpts
- #appendix
- #cheatsheet

## External Recon

```bash
whois example.com
dig ns example.com +short
subfinder -silent -d example.com
dnsx -l hosts.txt -wd example.com
httpx -l resolved.txt -sc -title
```

## Web Enumeration

```text
Manual browse -> Proxy capture -> JS analysis -> path enumeration -> request analysis
```

## Common Services

```bash
nmap -sV target
nmap --script default,safe target
smbclient -L //target -N
showmount -e target
snmpwalk -v2c -c public target
```

## AD Enumeration

```text
Without creds: DNS + LDAP rootDSE + SMB + Kerberos
With creds: users/groups/computers/SPN/GPO/ACL -> attack path analysis
```

## Pivoting

```bash
ssh -D 1080 -N user@pivot
ssh -L 8080:10.10.10.20:80 user@pivot
```

## Windows/Linux Privilege Escalation

```text
Windows: identity -> services/tasks/registry -> creds -> kernel last
Linux: id/sudo -> suid/caps -> writable paths -> containers/kernel last
```

## Evidence and Reporting

```text
Raw command/request + time + target + output + validation + remediation note
```

## 關聯筆記

- [[A-Appendix-Linux-Command-Reference|Appendix A - Linux Command Reference]]
- [[B-Appendix-Windows-and-PowerShell-Reference|Appendix B - Windows and PowerShell Reference]]
- [[E-Appendix-Tool-Matrix|Appendix E - Tool Matrix]]
