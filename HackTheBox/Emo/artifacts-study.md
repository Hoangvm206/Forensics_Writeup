#  DFIR REPORT  
## Incident: EMO – Hack The Box

**Difficulty:** Easy  
**Category:** Digital Forensics & Incident Response (DFIR)  
**Platform:** Hack The Box  

---

## 1 Executive Summary

Trong quá trình điều tra một file Microsoft Word khả nghi, nhóm phân tích phát hiện tài liệu này chứa **mã PowerShell bị obfuscate**, được thiết kế để thực thi payload độc hại khi mở file. Mã độc sử dụng kỹ thuật **XOR encoding** nhằm che giấu dữ liệu, đồng thời tận dụng PowerShell để thực thi mà không cần ghi thêm file xuống đĩa.

Sau khi giải mã payload, flag đã được trích xuất thành công. Không phát hiện dấu hiệu persistence hoặc kết nối Command & Control trong phạm vi bài lab.

---

## 2 Incident Overview

| Thuộc tính | Mô tả |
|----------|------|
| Loại file ban đầu | Microsoft Word Document |
| Dấu hiệu ban đầu | File Office khả nghi |
| Loại tấn công | Malicious Document |
| Kỹ thuật chính | PowerShell Obfuscation, XOR Encoding |
| Mức độ ảnh hưởng | Low |
| Dữ liệu điều tra | File DOC, hành vi PowerShell |

---

## 3 Scope & Impact Assessment

### Hệ thống bị ảnh hưởng
- Máy người dùng mở file Word độc hại

### Tác động
- Thực thi PowerShell script bị che giấu
- Giải mã và xử lý dữ liệu trong bộ nhớ
- Không phát hiện ghi file độc hại ra hệ thống

 Không phát hiện:
- Persistence
- Privilege escalation
- Lateral movement

---

## 4 Attack Analysis

### 4.1 Initial File Analysis

- File Word được phân tích ban đầu
- Phát hiện hành vi bất thường liên quan đến PowerShell
- File được upload lên môi trường phân tích động (any.run)

Kết quả cho thấy file thực thi một đoạn PowerShell script ngay khi mở.

---

### 4.2 PowerShell Payload Identification

- Trong quá trình phân tích hành vi, phát hiện đoạn mã PowerShell obfuscate
- Script chứa biến `FN5ggmsH` được sử dụng để lưu trữ dữ liệu dạng số

Ví dụ:

```powershell
$FN5ggmsH += (186,141,228,182,177,171,...)
```

- Ngoài ra, script sử dụng phép toán:

```text
byte ^ 0xdf
```

📌 Đây là dấu hiệu của **XOR encoding** với key `0xdf`

---

### 4.3 Deobfuscation & Decoding

- Trích xuất toàn bộ dãy số trong biến `FN5ggmsH`
- Sử dụng công cụ CyberChef để:
  - Áp dụng XOR với key `0xdf`
  - Chuyển kết quả sang ASCII

Kết quả giải mã cho thấy flag được che giấu trong payload.

---

## 5 Evidence & Artifacts

| Artifact | Mô tả |
|--------|------|
| File Word | Tài liệu Office độc hại |
| PowerShell script | Payload bị obfuscate |
| XOR key | `0xdf` |
| Decoded output | Flag |

---

## 6 Timeline of Events

| Thời điểm | Sự kiện | Bằng chứng |
|--------|-------|----------|
| T0 | File Word được mở | File DOC |
| T1 | PowerShell script được thực thi | any.run |
| T2 | Dữ liệu XOR được xử lý | Script analysis |
| T3 | Payload được decode | CyberChef |
| T4 | Flag được trích xuất | Decoded output |

---

## 7 Remediation & Recovery

###  Các bước xử lý

- Không mở file Word từ nguồn không tin cậy
- Vô hiệu hóa macro và PowerShell không cần thiết
- Áp dụng chính sách:
  - Constrained Language Mode cho PowerShell
  - AMSI & Script Block Logging
- Đào tạo người dùng về phishing document

---

## 8 Lessons Learned & Recommendations

###  Bài học rút ra
- File Office là vector tấn công phổ biến
- Obfuscation bằng XOR rất đơn giản nhưng hiệu quả
- PowerShell thường được dùng để thực thi mã độc không file (fileless)

### Khuyến nghị
- Giám sát PowerShell activity
- Block Office spawning PowerShell
- Dùng sandbox để phân tích file đáng ngờ
- Kết hợp static + dynamic analysis khi điều tra document malware

---

## 9 Mapping MITRE ATT&CK

| Technique | ID |
|---------|----|
| Obfuscated Files or Information | T1027 |
| PowerShell | T1059.001 |
| User Execution | T1204 |

---

## 10 Conclusion

Sự cố EMO cho thấy mức độ nguy hiểm của các tài liệu Office chứa mã độc obfuscate. Mặc dù kỹ thuật XOR đơn giản, việc kết hợp với PowerShell giúp attacker dễ dàng vượt qua kiểm tra thủ công. Phân tích DFIR tập trung vào hành vi runtime và giải mã payload là chìa khóa để phát hiện và xử lý loại mối đe dọa này.
