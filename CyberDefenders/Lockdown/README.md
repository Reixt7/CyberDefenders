# Lockdown Lab — Comprehensive Incident Response & Forensics Writeup

## Part 1: Network Forensics (PCAP Analysis)

### 1. After flooding the IIS host with rapid-fire probes, the attacker reveals their origin. Which IP address generated this reconnaissance traffic?

Любая разведка сопровождается огромным количеством запросов на установление соединения. Использован следующий фильтр Wireshark:

`tcp.flags.syn == 1 && tcp.flags.ack == 0`

Данный фильтр исключает ответные пакеты `SYN, ACK` от веб-сервера.

![Reconnaissance Traffic](IMG/Pasted%20image%2020260919230443.png)

В результатах виден IP-адрес `10.0.2.4`, который с высокой интенсивностью отправляет TCP SYN-пакеты на разные порты IIS-сервера.

**Ответ:** `10.0.2.4`

---

### 2. The attacker is carrying out targeted enumeration against the HTTP service on the IIS host. Based on the HTTP request headers, which tool is being used?

После обнаружения открытого 80-го порта (HTTP) атакующий приступил к исследованию прикладного уровня (L7). Применён фильтр:

`ip.src == 10.0.2.4 && http`

![HTTP Enumeration Tool](IMG/Pasted%20image%2020260919212812.png)

В заголовках HTTP-запросов (`User-Agent`) зафиксирован идентификатор сканера Nmap.

**Ответ:** `Nmap`

---

### 3. While reviewing the SMB traffic, you observe two consecutive Tree Connect requests that expose the first shares the intruder probes on the IIS host. Which two full UNC paths are accessed?

При попытке подключения к сетевой папке отправляется `Tree Connect Request` (числовой код операции `3`):

`ip.src == 10.0.2.4 && smb2.cmd == 3`

![SMB Tree Connect](IMG/Pasted%20image%2020260919213702.png)

**Ответ:** `\\10.0.2.15\Documents`, `\\10.0.2.15\IPC$`

---

### 4. Inside the share, the attacker plants a web-accessible payload that will grant remote code execution. What is the filename of the malicious file they uploaded?

Загрузка файла на сетевую папку отслеживается командой SMB `CREATE` / Write (код `9`):

`ip.src == 10.0.2.4 && smb2.cmd == 9`

![Payload Upload](IMG/Pasted%20image%2020260919223013.png)

**Ответ:** `shell.aspx`

---

### 5. The newly planted shell calls back to the attacker over an uncommon but firewall-friendly port. Which listening port did the attacker use for the reverse shell?

Для поиска инициации исходящего соединения (обратного вызова веб-шелла к атакующему) применён фильтр:

`ip.dst == 10.0.2.4 && tcp.flags.syn == 1 && tcp.flags.ack == 0`

![Reverse Shell Connection](IMG/Pasted%20image%2020260919230207.png)

**Ответ:** `4443`

---

### Реконструкция цепочки атаки (Attack Timeline):
1. **Разведка (Reconnaissance):** Сканирование портов хоста `10.0.2.15`, выявление портов 80 (HTTP) кадр 105 и 445 (SMB) кадры 2355–2357.
   ![Recon Timeline](IMG/Pasted%20image%2020260919221444.png)
2. **Доставка (Delivery):** Загрузка веб-шелла `shell.aspx` в доступную сетевую папку `/Documents/` кадр 3505.
   ![Delivery Timeline](IMG/Pasted%20image%2020260919231028.png)
3. **Активация (Execution):** Обращение к шеллу через HTTP-запрос `GET /Documents/shell.aspx` кадр 3573.
4. **Удаленный доступ (RCE):** Установление reverse shell соединения с IIS-сервера на IP `10.0.2.4` (порт `4443`) кадр 3585.

---

## Part 2: Memory Forensics (Volatility 3)

### 6. Your memory snapshot captures the system’s kernel in situ, providing vital context for the breach. What is the kernel base address in the dump?

Плагин `windows.info` извлекает основные метаданные операционной системы из дампа памяти. Значение адреса базового ядра находится в строке `Kernel Base`:

`vol -f /media/sf_Kali/269-lockdown/memdump.mem windows.info`

![Kernel Base Address](IMG/Pasted%20image%2020260922192506.png)

**Ответ:** `0xf80079213000`

---

### 7. A trusted service launches an unfamiliar executable residing outside the usual IIS stack, signalling a persistence implant. What is the final full on-disk path of that executable?

Просмотр аргументов командной строки запущенных процессов выполняется плагином `windows.cmdline`:

`vol -f memdump.mem windows.cmdline`

![Persistence Executable Path](IMG/Pasted%20image%2020260924135112.png)

Файл расположен в директории автозапуска `Startup`. Легитимные системные службы и процессы IIS не запускают бинарные файлы из таких путей, что подтверждает закрепление (Persistence).

**Ответ:** `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\updatenow.exe`

---

### 8. The reverse shell’s outbound traffic is handled by a built-in Windows process that also spawns the implanted executable. What is the name of this process, and what PID does it run under?

Анализ иерархии процессов (`windows.pstree`) показывает, что рабочий процесс IIS (`w3wp.exe`) является родительским для импланта `updatenow.exe` (PID 900) и обрабатывает сетевой трафик веб-шелла.

![Process Tree Analysis](IMG/Pasted%20image%2020260924174242.png)

**Ответ:** `w3wp.exe`, `4332`

---

## Part 3: Malware Sample Analysis & Threat Intelligence

### 9. Static inspection reveals the binary has been packed to hinder analysis. Which packer was used to obfuscate it?

Статический анализ бинарного файла выполнен с помощью утилиты `strings` без запуска образца. В структуре PE-файла найдены сигнатуры упаковщика (`UPX0`, `UPX1`, `3.91UPX!`):

`strings /media/sf_Kali/269-lockdown/updatenow.exe`

![UPX Signature](IMG/Pasted%20image%2020260924182942.png)[cite: 4]

**Ответ:** `UPX`

---

### 10. Threat-intel analysis shows the malware beaconing to its command-and-control host. Which fully qualified domain name (FQDN) does it contact?

С файла снята упаковочная защита UPX для получения чистого бинарника]:

`upx -d /media/sf_Kali/269-lockdown/updatenow.exe -o unp_updatenow.exe`

Для проведения CTI-анализа вычислен MD5-хеш распакованного файла:

`md5sum unp_updatenow.exe`

![File MD5 Hash](IMG/Pasted%20image%2020260924184338.png)[cite: 4]

Сопоставление хеша в VirusTotal (разделы `DNS Resolutions` и `SMTP Communications`) выявило домен C2-сервера:

![VirusTotal C2 FQDN](IMG/Pasted%20image%2020260924184404.png)

**Ответ:** `cp8nl.hyperhost.ua`

---

### 11. Open-source intel associates that hash with a well-known commodity RAT. To which malware family does the sample belong?

Анализ агрегированных данных детекции и сигнатур во вкладке `Community` на VirusTotal (включая отчёты песочницы ANY.RUN) подтверждает принадлежность образца к семейству стилеров/RAT:

![VirusTotal Malware Family Attribution](IMG/Pasted%20image%2020260924184651.png)

**Ответ:** `Agent Tesla`