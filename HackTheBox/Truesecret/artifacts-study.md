# DFIR INCIDENT REPORT  
## Case: TrueSecret – Hack The Box

**Difficulty:** Easy  
**Category:** Forensics / Memory Analysis  
**Incident Type:** Advanced Persistent Threat (APT) – Custom C2  
**Primary Evidence:** Memory Dump (RAM)  
**Tools Used:** Volatility 2, VeraCrypt, Custom Decrypt Script  

---

## 1 Executive Summary

Trong quá trình điều tra sau khi bắt giữ thủ lĩnh một nhóm APT, lực lượng chức năng đã thu được **memory dump** từ máy tính đang hoạt động của đối tượng. Phân tích bộ nhớ cho thấy nhóm APT này sử dụng một **máy chủ Command & Control (C2) tùy chỉnh**, kết hợp mã hóa volume bằng TrueCrypt nhằm che giấu mã nguồn và dữ liệu nhạy cảm.

Mặc dù sử dụng nhiều lớp bảo vệ, attacker đã mắc sai lầm nghiêm trọng khi **không xóa sạch thông tin nhạy cảm khỏi RAM**, cho phép quá trình memory forensics trích xuất mật khẩu TrueCrypt, truy cập mã nguồn C2 và đảo ngược thuật toán mã hóa giao tiếp.

---

## 2 Incident Overview

| Thuộc tính | Mô tả |
|----------|------|
| Threat Actor | APT Group |
| Initial Evidence | Memory Dump |
| Malware Type | Custom C2 Server |
| Encryption Used | TrueCrypt + DES |
| Key Storage | In-memory |
| Impact Level | High (C2 infrastructure exposure) |

---

## 3 Scope & Impact Assessment

###  Tài nguyên bị ảnh hưởng
- Máy tính của thủ lĩnh APT
- Bộ nhớ RAM tại thời điểm thu giữ

###  Tác động
- Lộ mã nguồn C2
- Lộ giao thức giao tiếp C2
- Lộ key & IV mã hóa
- Có thể giải mã toàn bộ session đã thu thập

---

## 4 Evidence Collected

| Artifact | Mô tả |
|--------|------|
| TrueSecrets.raw | Memory dump |
| ZIP backup | Trích xuất từ RAM |
| TrueCrypt container (.tc) | Volume mã hóa |
| Agent server source | Mã nguồn C2 |
| Session data | Giao tiếp C2 |

---

## 5 Memory Forensics Analysis

###  5.1 Profile Identification

- Sử dụng Volatility 2
- Profile phù hợp:

```text
Win7SP1x86_23418
```

---

###  5.2 Process Enumeration

Lệnh:

```bash
vol -f TrueSecrets.raw --profile=Win7SP1x86_23418 pslist
```

Các process đáng chú ý:

| Process | Nhận định |
|-------|-----------|
| TrueCrypt.exe | Volume mã hóa |
| DumpIt.exe | Tool dump RAM |
| 7zFM.exe | Giải nén backup |
| WiMPrvSE.exe | Thường bị giả mạo |

---

###  5.3 Command Line Analysis

Lệnh:

```bash
vol -f TrueSecrets.raw --profile=Win7SP1x86_23418 cmdline
```

Phát hiện:
- `7zFM.exe` được dùng để mở **file ZIP backup**
- ZIP chứa dữ liệu nhạy cảm liên quan đến C2

---

## 6 File Extraction from Memory

###  6.1 Dump ZIP File

- Trích xuất ZIP trực tiếp từ RAM
- Thu được các file:
  - `.dat`
  - `.vacb`

---

###  6.2 Recover TrueCrypt Container

- Giải nén tiếp các artifact
- Thu được file:

```text
*.tc
```

=> TrueCrypt encrypted volume

---

## 7 Credential Recovery

###  7.1 Extract TrueCrypt Passphrase

- Sử dụng plugin Volatility:

```bash
vol -f TrueSecrets.raw --profile=Win7SP1x86_23418 truecryptpassphrase
```

- Passphrase thu được:

```text
X2Hk2XbEJqWYsh8VdbSYg6WpG9g7
```

---

###  7.2 Mount Encrypted Volume

- Dùng **VeraCrypt 1.25**
- Mount thành công container `.tc`

Kết quả:
- Truy cập được thư mục **agent server**
- Thu được mã nguồn C2

---

## 8 C2 Malware Analysis

###  8.1 Encryption Mechanism

- Thuật toán: **DES**
- Đặc điểm:
  - Key cố định
  - IV cố định
- Output:
  - Ciphertext Base64

=> Thiết kế mã hóa yếu, dễ đảo ngược

---

###  8.2 Decryption

- Viết script giải mã dựa trên:
  - DES
  - Key & IV thu được từ source code
- Giải mã thành công file session
- Thu được dữ liệu & flag

---

## 9 Attack Flow Reconstruction

```text
1. APT triển khai C2 server tùy chỉnh
2. Mã nguồn & session được lưu trong TrueCrypt container
3. Container được mở trong lúc hệ thống đang chạy
4. Memory dump được thu thập
5. Passphrase TrueCrypt bị trích xuất từ RAM
6. Analyst truy cập C2 source & giải mã session
```

---

## 10 Root Cause Analysis

###  Sai lầm của attacker
- Không xóa key & passphrase khỏi RAM
- Dùng DES với key & IV cố định
- Lưu source code C2 trong volume đang mount

###  Điểm thành công của DFIR
- Thu thập RAM kịp thời
- Áp dụng memory forensics đúng plugin
- Kết hợp phân tích mã hóa và reverse logic

---

## 11 MITRE ATT&CK Mapping

| Technique | ID |
|--------|----|
| Custom C2 Protocol | T1094 |
| Encrypted Channel | T1573 |
| Data Encrypted for Impact | T1486 |
| Credential in Memory | T1003 |
| Obfuscated Files or Information | T1027 |

---

## 12 Lessons Learned & Recommendations

###  Phòng thủ
- Luôn thu thập **memory dump** trong incident response
- Không tin tưởng mã hóa volume nếu key tồn tại trong RAM
- Giám sát process mount TrueCrypt/VeraCrypt

###  DFIR Insight
> **RAM luôn là điểm yếu lớn nhất của attacker.  
Nếu hệ thống đang chạy, bí mật luôn tồn tại trong bộ nhớ.**

---

## 13 Conclusion

Challenge TrueSecret minh họa rõ ràng giá trị cốt lõi của **memory forensics trong điều tra APT**. Dù attacker sử dụng nhiều lớp mã hóa, việc thu thập và phân tích RAM đúng thời điểm đã cho phép trích xuất toàn bộ chuỗi bí mật: từ mật khẩu TrueCrypt, mã nguồn C2 cho tới thuật toán mã hóa và dữ liệu phiên giao tiếp.
