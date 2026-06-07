# DFIR INCIDENT REPORT  
## Case: Obsecure – Hack The Box

**Difficulty:** Easy  
**Category:** Forensics / Network / Web  
**Incident Type:** Webshell Intrusion & Post-Exploitation  
**Data Source:** PCAP, Malicious PHP Script  

---

## 1 Executive Summary

Một hệ thống web production đã bị kẻ tấn công lợi dụng **lỗ hổng upload file tùy ý** để tải lên một **webshell PHP (support.php)**. Sau khi phát hiện sự cố, dịch vụ HTTP đã bị tắt, chỉ còn lại **log mạng (PCAP)** trong khoảng **2 phút trước thời điểm phát hiện**.

Qua phân tích webshell và lưu lượng mạng, xác định attacker đã:
- Thực thi lệnh hệ thống từ xa thông qua webshell
- Liệt kê người dùng và thư mục
- Truy cập thư mục home của developer
- Trích xuất file cơ sở dữ liệu KeePass (`pwdb.kdbx`)
- Crack mật khẩu KeePass và thu được flag

---

## 2 Incident Overview

| Thuộc tính | Mô tả |
|----------|------|
| Vector tấn công | Arbitrary File Upload |
| Payload | PHP Webshell |
| Kênh C2 | HTTP POST |
| Kỹ thuật mã hóa | Base64 + Repeating-key XOR + Gzip |
| Dữ liệu bị truy cập | File KeePass |
| Mức độ ảnh hưởng | Medium |

---

## 3 Scope & Impact Assessment

###  Tài nguyên bị ảnh hưởng
- Web server (PHP)
- User directory `/home/developer`
- File nhạy cảm: `pwdb.kdbx`

###  Tác động
- Remote Command Execution
- Data Exfiltration
- Credential compromise

 Không phát hiện:
- Persistence
- Privilege escalation
- Lateral movement

---

## 4 Evidence Collection

| Artifact | Mô tả |
|--------|------|
| PCAP | Log mạng 2 phút trước sự cố |
| support.php | Webshell độc hại |
| Decoded payload | Lệnh attacker |
| pwdb.kdbx | KeePass database |

---

## 5 Malware / Webshell Analysis

###  5.1 Webshell Behavior Overview

File `support.php` sử dụng các kỹ thuật:
- Obfuscation bằng `create_function`
- Mã hóa dữ liệu bằng **Repeating-key XOR**
- Giao tiếp qua HTTP POST (`php://input`)

---

###  5.2 Cryptographic Logic

**Hàm mã hóa chính:**

- Hàm `x($t, $k)`:
  - XOR từng byte dữ liệu với key `$k`
  - Repeating-key XOR (đối xứng)

**Chuỗi xử lý dữ liệu:**

```text
Client → Base64 → XOR → PHP
PHP → XOR → Gzip → Response
```

---

###  5.3 Input Processing

- Webshell đọc input từ:
```php
@file_get_contents("php://input")
```

- Trích xuất payload giữa hai chuỗi marker `$kh` và `$kf`
- Giải mã:
  1. Base64 decode
  2. XOR với key `$k`
- Thực thi lệnh
- Thu output bằng output buffer

---

## 6 Network Traffic Analysis (PCAP)

###  6.1 HTTP Stream Reconstruction

- Dùng Wireshark → **Follow HTTP Stream**
- Thu được dữ liệu mã hóa:

```text
Input:
6f8af44abea0QKwu/Xr7GuFo50p4HuAZHBfnqhv7/+ccFfisfH4bYOSMRi0eGPgZuRd6SPsdGP//c+dVM7gnYSWvlINZmlWQGyDpzCowpzczRely/Q351039f4a7b5
```

---

###  6.2 Decryption Process

- Không thể decode trực tiếp
- Áp dụng lại logic hàm `x()`:
  - Base64 decode
  - XOR ngược với key

---

## 7 Attacker Command Reconstruction

Sau khi giải mã các stream:

###  Stream 1
- Thu thập thông tin hệ thống:
```bash
id
uid=...
```

---

###  Stream 23–25
- Hành vi attacker:

```text
ls -lah /home
cd /home/developer
dump pwdb.kdbx
```

---

## 8 Timeline of Events

| Thời điểm | Hành động | Bằng chứng |
|--------|----------|-----------|
| T0 | Webshell nhận POST request | PCAP |
| T1 | Attacker chạy `id` | Stream 1 |
| T2 | Liệt kê `/home` | Stream 23 |
| T3 | Truy cập `/home/developer` | Stream 24 |
| T4 | Dump KeePass DB | Stream 25 |

---

## 9 Credential Compromise

###  9.1 KeePass Extraction
- Dữ liệu dump được lưu thành:
```text
pwdb.kdbx
```

###  9.2 Password Cracking
- Chuyển sang hash:
```bash
keepass2john pwdb.kdbx
```

- Crack bằng Hashcat
- Mở KeePass thành công

---

## 10 Flag Recovered

```text
HTB{pr0tect_y0_shellZ}
```

---

## 11 Root Cause Analysis

###  Nguyên nhân gốc
- Lỗ hổng upload file tùy ý
- Không kiểm soát file PHP upload
- Không sandbox web process

###  Điểm yếu chính
- Không WAF
- Không giám sát outbound traffic
- Không kiểm tra nội dung POST bất thường

---

## 12 Remediation & Recommendations

###  Khắc phục
- Disable upload PHP
- Validate MIME & extension
- Chạy webserver với user hạn chế quyền
- Giám sát HTTP POST bất thường

###  Phòng thủ lâu dài
- IDS/IPS
- File Integrity Monitoring
- Centralized logging

---

## 13 MITRE ATT&CK Mapping

| Technique | ID |
|---------|----|
| Exploit Public-Facing Application | T1190 |
| Web Shell | T1505.003 |
| Obfuscated Files or Information | T1027 |
| Command Execution | T1059 |
| Credential Access | T1555 |

---

## 14 Conclusion

Incident Obsecure minh họa rõ ràng cách một **webshell PHP được obfuscate** có thể bị phân tích ngược thông qua **DFIR workflow**: từ mã độc → PCAP → decrypt payload → tái dựng timeline → đánh giá tác động. Đây là một kịch bản thực tế sát môi trường SOC khi dịch vụ đã bị shutdown và **log mạng là nguồn bằng chứng duy nhất**.
