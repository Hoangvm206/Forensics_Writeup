#  DFIR REPORT  
## Incident: Fishy HTTP – Hack The Box

**Difficulty:** Easy  
**Category:** Digital Forensics & Incident Response (DFIR)  
**Platform:** Hack The Box  

---

## 1 Executive Summary

Trong quá trình điều tra một sự cố bảo mật, nhóm phân tích phát hiện một chương trình khả nghi trên máy người dùng đã thực hiện các yêu cầu HTTP bất thường đến một máy chủ từ xa. Qua phân tích lưu lượng mạng (PCAP) và file nhị phân Windows liên quan, xác định đây là một **malware sử dụng kỹ thuật steganography/obfuscation qua HTTP traffic** nhằm truyền dữ liệu bí mật.

Malware chia flag thành nhiều phần, được che giấu trong các HTTP stream và mã hóa bằng Base64 cũng như một cơ chế encode HTML tùy chỉnh được cài đặt trong binary .NET.

---

## 2 Incident Overview

| Thuộc tính | Mô tả |
|----------|------|
| Hệ điều hành | Windows |
| Dấu hiệu ban đầu | HTTP traffic bất thường |
| Loại tấn công | Malware giao tiếp qua HTTP |
| Kỹ thuật chính | Obfuscation, Base64, Custom HTML Encoding |
| Mức độ ảnh hưởng | Low – Medium |
| Dữ liệu điều tra | PCAP, Windows binary |

---

## 3 Scope & Impact Assessment

###  Hệ thống bị ảnh hưởng
- Máy người dùng chạy Windows
- Một tiến trình gửi HTTP request liên tục đến web server

###  Tác động
- Truyền dữ liệu bị che giấu qua HTTP
- Khả năng thực hiện reverse shell
- Không phát hiện hành vi phá hoại hệ thống hoặc ransomware

=> Không phát hiện:
- Lateral movement(di chuyển ngang)
- Privilege escalation(leo thang đặc quyền)

---

## 4 Attack Analysis

### 4.1 Network Traffic Analysis (PCAP)

- Phân tích file PCAP bằng Wireshark
- Phát hiện phần lớn traffic là HTTP
- Một số HTTP stream chứa payload bất thường

Các stream này bao gồm chuỗi phản hồi (feedback) với các ký tự được tô màu đỏ trong Wireshark, cho thấy dữ liệu có chủ đích được chèn vào response.

---

### 4.2 Obfuscated Payload Reconstruction

- Dữ liệu phản hồi HTTP được trích xuất và lưu vào file text
- Viết script Python để:
  - Tách từng từ
  - Lấy ký tự đầu của mỗi từ
  - Ghép lại thành một chuỗi hoàn chỉnh

Chuỗi thu được sau khi ghép được xác định là **Base64 encoded**.

Sau khi decode Base64, thu được **phần đầu của flag**:

```text
h77P_s73417hy_revSHELL}
```

---

### 4.3 Binary Analysis (Windows Executable)

- Phân tích file nhị phân bằng Detect It Easy
- Xác định:
  - Binary viết bằng .NET
  - Có liên kết với C++

- Dùng DotPeek để decompile
- Phát hiện thư viện và module bất thường trong project

Một hàm encode/decode HTML tùy chỉnh được tìm thấy, cho thấy malware sử dụng các thẻ HTML để biểu diễn dữ liệu hex.

---

### 4.4 Custom HTML Encoding Reversal

- Trích xuất HTTP stream chứa HTML payload
- Viết script Python để:
  - Map tên thẻ HTML sang ký tự hex
  - Ghép chuỗi hex
  - Convert sang ASCII

Kết quả giải mã cho thấy **phần còn lại của flag**:

```text
HTB{Th4ts_d07n37_
```

---

## 5 Evidence & Artifacts

| Artifact | Mô tả |
|--------|------|
| PCAP file | Lưu lượng HTTP chứa payload ẩn |
| Windows binary | Malware .NET |
| Python scripts | Dùng để decode payload |
| HTML payload | Dữ liệu mã hóa bằng thẻ HTML |

---

## 6 Timeline of Events

| Thời điểm | Sự kiện | Bằng chứng |
|--------|-------|----------|
| T0 | Malware gửi HTTP request | PCAP |
| T1 | Payload bị chèn vào HTTP response | Stream HTTP |
| T2 | Trích xuất Base64 payload | Script Python |
| T3 | Decode phần flag thứ nhất | Base64 decode |
| T4 | Reverse HTML encoding | Binary analysis |
| T5 | Thu thập flag hoàn chỉnh | Kết quả decode |

---

## 7 Remediation & Recovery

### Các bước xử lý

- Cô lập máy người dùng bị nhiễm
- Xóa file nhị phân độc hại
- Kiểm tra persistence (Startup, Registry, Scheduled Tasks)
- Giám sát outbound HTTP traffic bất thường
- Triển khai IDS/IPS cho HTTP anomaly detection

---

## 8 Lessons Learned & Recommendations

### Bài học rút ra
- HTTP traffic rất dễ bị lợi dụng để che giấu dữ liệu
- Malware có thể sử dụng encoding tùy chỉnh để né tránh phát hiện
- Phân tích PCAP kết hợp reverse binary là kỹ năng then chốt trong DFIR

### Khuyến nghị
- Giám sát nội dung HTTP response, không chỉ request
- Triển khai SSL inspection (nếu phù hợp)
- Huấn luyện SOC nhận diện traffic bất thường
- Kết hợp network forensics và malware analysis

---

## 9 Mapping MITRE ATT&CK

| Technique | ID |
|---------|----|
| Obfuscated Files or Information | T1027 |
| Application Layer Protocol (HTTP) | T1071.001 |
| Command and Control | TA0011 |

---

## 10 Conclusion

Sự cố Fishy HTTP cho thấy attacker có thể tận dụng giao thức HTTP phổ biến để che giấu hoạt động Command & Control. Việc kết hợp phân tích lưu lượng mạng và reverse engineering malware là chìa khóa để phát hiện và tái tạo toàn bộ hành vi tấn công.
