# DFIR INCIDENT REPORT  
## Case: Reminiscent – Hack The Box

**Difficulty:** Easy  
**Category:** Forensics / Memory Analysis  
**Incident Type:** Phishing → Malware Execution  
**Primary Evidence:** Memory Dump, Phishing Email  

---

## 1 Executive Summary

Một máy tính ảo của nhân viên tuyển dụng đã bị nhiễm mã độc, nhiều khả năng thông qua **email lừa đảo (phishing)** được ngụy trang thành hồ sơ xin việc. Kẻ tấn công sử dụng một file ZIP được host trên máy chủ nội bộ để phát tán payload.

Do mã độc không để lại nhiều artifact trên ổ đĩa, quá trình điều tra chủ yếu dựa vào **memory forensics** để khôi phục file và chuỗi lệnh độc hại còn tồn tại trong RAM. Phân tích thành công đã cho phép trích xuất payload PowerShell và thu được flag.

---

## 2 Incident Overview

| Thuộc tính | Mô tả |
|---------|------|
| Initial Vector | Phishing Email |
| Payload Type | Shortcut (.lnk) → PowerShell |
| Artifact chính | Memory Dump |
| Kỹ thuật che giấu | Base64 + UTF-16LE |
| Persistence | Không xác định |
| Mức độ ảnh hưởng | Low – Medium |

---

## 3 Scope & Impact Assessment

###  Tài nguyên bị ảnh hưởng
- Máy ảo người dùng (Recruitment VM)
- Bộ nhớ RAM tại thời điểm nhiễm

###  Tác động
- Thực thi mã PowerShell độc hại
- Có khả năng tải payload từ mạng nội bộ
- Không ghi nhận lateral movement

---

## 4 Evidence Collection

| Artifact | Mô tả |
|--------|------|
| flounder-pc-memdump.elf | Memory dump toàn bộ RAM |
| Resume.eml | Email phishing |
| imageinfo.txt | Gợi ý profile Volatility |
| resume.pdf.lnk | Artifact độc hại trích xuất từ RAM |

---

## 5 Phishing Email Analysis

###  5.1 Nội dung Email

- File `Resume.eml` chứa email giả mạo hồ sơ xin việc
- Email dụ người dùng tải file từ link:

```text
http://10.10.99.55:8080/resume.zip
```

=> Đây là **điểm xâm nhập ban đầu (Initial Access)**

---

## 6 Memory Forensics Analysis

### 6.1 Tooling

- Volatility Framework 3
- Profile tham khảo từ `imageinfo.txt`

---

### 6.2 File Discovery in Memory

- Dùng plugin:

```text
windows.filescan.Filescan
```

- Phát hiện artifact còn tồn tại trong RAM:

```text
resume.pdf.lnk
```

=> Cho thấy payload được thực thi từ shortcut file

---

###  6.3 Dump File từ RAM

- Dùng plugin:

```text
windows.dumpfiles.DumpFiles
```

- Trích xuất thành công file `.lnk`

---

## 7 Payload Analysis

### 7.1 String Analysis

- Sử dụng `strings` để tìm dữ liệu đáng ngờ
- Phát hiện chuỗi **Base64 encoded**

---

### 7.2 Decode Obfuscated Data

#### Bước 1: CyberChef
- Decode:
  - Base64
  - UTF-16LE

=> Thu được PowerShell script bị obfuscate

---

#### Bước 2: PowerShell Decode
- Giải mã tiếp script PowerShell
- Thu được nội dung cuối cùng chứa flag

---

## 8 Attack Flow Reconstruction

```text
1. User nhận phishing email (Resume.eml)
2. User tải resume.zip từ server nội bộ
3. Shortcut resume.pdf.lnk được thực thi
4. PowerShell payload chạy trong bộ nhớ
5. Payload bị phát hiện qua memory dump
```

---

## 9 Timeline of Events

| Thời điểm | Sự kiện | Bằng chứng |
|--------|--------|-----------|
| T0 | Nhận email phishing | Resume.eml |
| T1 | Tải resume.zip | URL trong email |
| T2 | Thực thi resume.pdf.lnk | Memory dump |
| T3 | Payload PowerShell chạy | Base64 string |
| T4 | Artifact bị xóa khỏi disk | Không còn file trên FS |

---

## 10 Flag Recovered

```text
<FLAG_EXTRACTED_FROM_PAYLOAD>
```

*(Flag được thu trực tiếp sau khi decode PowerShell payload)*

---

## 11 Root Cause Analysis

###  Nguyên nhân gốc
- Người dùng mở email phishing
- Không có sandbox hoặc email filtering
- Payload thực thi hoàn toàn trong RAM

###  Kỹ thuật attacker sử dụng
- Shortcut file (.lnk)
- Fileless execution
- Obfuscation nhiều lớp

---

## 12 MITRE ATT&CK Mapping

| Technique | ID |
|--------|----|
| Phishing | T1566 |
| User Execution | T1204 |
| Shortcut Modification | T1547.009 |
| PowerShell | T1059.001 |
| Obfuscated Files or Information | T1027 |

---

## 13 Remediation & Recommendations

###  Phòng ngừa
- Email sandboxing
- Block `.lnk` trong email
- Disable PowerShell v2
- AMSI + Script Block Logging

###  Phát hiện
- Memory forensics playbook
- Phát hiện PowerShell encoded command
- Monitor shortcut execution

---

## 14 Conclusion

Challenge Reminiscent minh họa rõ ràng hiệu quả của **DFIR dựa trên memory forensics**, đặc biệt trong các tình huống mã độc không để lại dấu vết trên ổ đĩa. Việc kết hợp phân tích email, RAM dump và giải mã nhiều lớp cho phép tái dựng đầy đủ chuỗi tấn công dù attacker đã cố tình xóa artifact truyền thống.
