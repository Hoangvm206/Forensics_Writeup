#  DFIR INCIDENT REPORT  
## Case: RedTrails – Hack The Box

**Difficulty:** Medium 
**Category:** Forensics / Network Analysis / Redis / Malware  
**Incident Type:** Unauthorized Redis Access → Malware Deployment (Cryptojacking)  
**Primary Evidence:** Network Capture (PCAP), ELF Binary  
**Tools Used:** Wireshark, CyberChef, Ghidra  

---

## 1 Executive Summary

Cuộc điều tra phát hiện một **Redis instance bị truy cập trái phép** mặc dù đã được cấu hình mật khẩu. Kẻ tấn công đã lợi dụng Redis để thực thi payload độc hại thông qua **RESP protocol**, sử dụng **Base64 + eval** nhằm che giấu mã độc.

Quá trình phân tích cho thấy cuộc tấn công diễn ra theo **hai giai đoạn**:
1. Thực thi payload ban đầu và để lại flag fragment trong traffic Redis
2. Tải và thực thi một **ELF binary độc hại**, được mã hóa bằng key và IV hard-code, cuối cùng triển khai **cryptominer (ethminer)**

---

## 2 Incident Overview

| Thuộc tính | Mô tả |
|---------|------|
| Initial Vector | Unauthorized Redis Access |
| Protocol | RESP (Redis Serialization Protocol) |
| Payload | Obfuscated Script + ELF Binary |
| Malware Type | Cryptominer |
| Impact Level | Medium |
| Persistence | Unknown |

---

## 3 Scope & Impact Assessment

###  Tài nguyên bị ảnh hưởng
- Redis instance exposed ra Internet
- Hệ thống host chạy Redis
- Tài nguyên CPU bị khai thác để đào coin

###  Tác động
- Thực thi lệnh trái phép trên Redis
- Tải và chạy mã độc
- Tiêu tốn tài nguyên hệ thống (cryptojacking)

---

## 4 Evidence Collected

| Artifact | Mô tả |
|-------|------|
| PCAP File | Giao tiếp Redis bất thường |
| RESP Packets | Payload và dữ liệu flag |
| ELF Binary | Malware được tải xuống |
| Decompiled Code | Key/IV mã hóa |

---

## 5 Network Traffic Analysis

###  5.1 Obfuscated Payload Discovery

- Trong **stream 1**, phát hiện payload:
  - Chuỗi Base64 bị chia nhỏ
  - Payload kết thúc bằng `eval`
- Chuỗi bị **reverse thứ tự ký tự** trước khi decode

=> Đây là kỹ thuật **obfuscation nhằm tránh phát hiện**.

---

###  5.2 Payload Reconstruction

- Ghép lại các đoạn chuỗi
- Reverse lại payload
- Decode Base64

=> Thu được **FLAG – Part 1**:

```text
HTB{r3d15_1n574nc35
```

---

## 6 Redis RESP Protocol Analysis

### 6.1 Flag Fragment in Redis Packets

- Tiếp tục phân tích RESP packets
- Trong **packet 35**, phát hiện dữ liệu ASCII rõ ràng

=> **FLAG – Part 2**:

```text
_c0uld_0p3n_n3w
```

=> Điều này xác nhận attacker đã để lại dữ liệu trực tiếp trong Redis command stream.

---

## 7 Malware Binary Analysis

###  7.1 Suspicious Binary Detection

- Phát hiện payload có:
  - Kích thước bất thường
  - ELF header (`7f 45 4c 46`)
- Cho thấy mã độc Linux được tải thông qua Redis

---

### 7.2 Reverse Engineering (Ghidra)

- Import ELF binary vào Ghidra
- Phát hiện thông tin mã hóa hard-code:

```text
Key: h02B6aVgu09Kzu9QTvTOtgx9oER9WIoz
IV:  YDP7ECjzuV7sagMN
```

- Biến `x10SHp` chứa dữ liệu mã hóa

---

###  7.3 Decryption

- Sử dụng CyberChef để decrypt dữ liệu
- Giải mã thành công payload cuối

=> **FLAG – Part 3**:

```text
_un3xp3c73d_7r41l5!}
```

---

## 8 Full Flag Recovered

```text
HTB{r3d15_1n574nc35_c0uld_0p3n_n3w_un3xp3c73d_7r41l5!}
```

---

## 9 Attack Flow Reconstruction

```text
1. Attacker truy cập Redis trái phép
2. Thực thi payload obfuscated (Base64 + eval)
3. Redis trả về dữ liệu flag
4. ELF binary được tải xuống
5. Binary được decrypt bằng key/IV hard-code
6. Malware thực thi cryptominer
```

---

## 10 Timeline of Events

| Thời điểm | Sự kiện | Artifact |
|--------|--------|---------|
| T0 | Redis bị truy cập | Network traffic |
| T1 | Payload obfuscated được gửi | Stream 1 |
| T2 | Base64 decode | Script |
| T3 | RESP packet chứa flag | Packet 35 |
| T4 | ELF binary được tải | PCAP |
| T5 | Decrypt malware | Ghidra |

---

## 11 Root Cause Analysis

### Nguyên nhân
- Redis exposed trực tiếp ra Internet
- Cho phép lệnh nguy hiểm (`EVAL`, `CONFIG`)

### Kỹ thuật attacker
- Redis command abuse
- Base64 + reverse obfuscation
- Hard-coded crypto parameters

---

## 12 MITRE ATT&CK Mapping

| Technique | ID |
|--------|----|
| Exploit Public-Facing Application | T1190 |
| Command and Scripting Interpreter | T1059 |
| Obfuscated Files or Information | T1027 |
| Ingress Tool Transfer | T1105 |
| Resource Hijacking (Cryptomining) | T1496 |

---

## 13 Lessons Learned & Recommendations

###  Defensive Recommendations
- Không expose Redis ra Internet
- Bật authentication + bind localhost
- Disable các lệnh nguy hiểm:
  - `EVAL`
  - `CONFIG`
  - `MODULE LOAD`
- Giám sát RESP traffic bất thường
- IDS/IPS cho protocol Redis

###  DFIR Insight
> **Redis là mục tiêu phổ biến của cryptojacking do cấu hình sai và khả năng thực thi lệnh từ xa.**

---

## 14 Conclusion

Challenge RedTrails mô phỏng thành công một cuộc tấn công cryptojacking thông qua Redis. Bằng cách phân tích traffic mạng, RESP protocol và reverse binary ELF, quá trình DFIR đã tái dựng toàn bộ chuỗi tấn công, từ truy cập trái phép đến thực thi malware đào coin.
