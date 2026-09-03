# LDAP

## 標籤

- #cpts
- #protocols
- #ldap

## 定位

LDAP 是目錄查詢協定，在 AD 與其他目錄系統中負責結構化物件與身份資料的存取。

## 測試重點

- naming context
- rootDSE 可見性
- 匿名查詢邊界
- 目錄結構、使用者、群組、OU、GPO 等物件關係

## 高價值問題

- 低權即可見的高價值關係
- 匿名洩漏過多架構資訊
- ACL/委派與控制鏈分析材料

## 常見誤判

- LDAP 可連線不等於目錄配置有弱點
- rootDSE 資訊線索與可利用缺陷要分開

## 關聯筆記

- [[../09-Active-Directory/72-無憑證AD列舉|第 72 章 - 無憑證 AD 列舉]]
- [[../09-Active-Directory/73-有憑證AD列舉|第 73 章 - 有憑證 AD 列舉]]
