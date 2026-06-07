#  DFIR INCIDENT REPORT  
## Case: DIAGNOSTIC – Hack The Box

**Difficulty:** Easy  
**Category:** Forensics / Malicious Document  
**Incident Type:** Phishing → Malicious Office Document  
**Primary Evidence:** Microsoft Word (.doc)  
**Tools Used:** oleid, oleobj, Base64 Decoder, PowerShell  

---

## 1 Executive Summary

Cuộc điều tra xoay quanh một chiến dịch **phishing email** trong đó kẻ tấn công phát tán tài liệu Microsoft Word độc hại thông qua liên kết `diagnostic.htb/layoffs.doc`. Mặc dù DNS của domain đã ngừng hoạt động, máy chủ gốc vẫn lưu trữ tài liệu độc hại và cho phép tải trực tiếp bằng địa chỉ IP.

Phân tích cho thấy tài liệu Word chứa **OLE Object nhúng**, dẫn tới việc tải và thực thi nội dung HTML bên ngoài. Payload được che giấu bằng **Base64 và PowerShell string formatting**, cuối cùng để lộ flag sau khi giải mã.

---

## 2 Incident Overview

| Thuộc tính | Mô tả |
|----------|------|
| Initial Vector | Phishing Email |
| Payload Type | Malicious Office Document |
| Delivery Method | External URL (HTTP) |
| Obfuscation | Base64 + PowerShell |
| Impact Level | Low |
| User Interaction Required | Yes |

---

## 3 Scope & Impact Assessment

### Tài nguyên bị ảnh hưởng
- Máy người dùng mở file Word
- Trình xử lý OLE của Microsoft Office

### Tác động
- Thực thi nội dung từ nguồn bên ngoài
- Có khả năng dẫn đến tải payload bổ sung
- Không ghi nhận persistence

---

## 4 Evidence Collected

| Artifact | Mô tả |
|--------|------|
| layoffs.doc | File Word độc hại |
| OLE Object | Nội dung nhúng |
| HTML Payload | File HTML bên ngoài |
| Base64 String | Dữ liệu bị che giấu |
| PowerShell Code | Logic giải mã |

---

## 5 Malicious Document Analysis

###  5.1 File Acquisition

Tài liệu được tải trực tiếp từ IP máy chủ:

```text
http://94.237.122.36:44671/layoffs.doc
```

=> Bỏ qua DNS, cho thấy attacker vẫn duy trì hosting payload.

---

###  5.2 OLE Analysis

Sử dụng **oleid** để kiểm tra file Word:

```bash
oleid diagnostic.doc
```

Kết quả:
- Phát hiện **OLE Object**
- Mức độ rủi ro: **High**

=> Dấu hiệu tài liệu Office nhúng payload độc hại.

---

###  5.3 OLE Object Extraction

Trích xuất nội dung nhúng bằng:

```bash
oleobj diagnostic.doc
```

Kết quả:
- Thu được file HTML được tải từ máy chủ ngoài

---

## 6 Payload Analysis

###  6.1 HTML Inspection

Truy cập file HTML được trích xuất:

```text
http://94.237.122.36:44671/223_index_style_fancy.html
```

- Inspect source code
- Phát hiện đoạn **Base64 encoded string**

---

###  6.2 Base64 Decoding

- Giải mã Base64 bằng công cụ online
- Kết quả cho thấy dữ liệu PowerShell bị xáo trộn

---

###  6.3 PowerShell Deobfuscation

Chạy đoạn PowerShell:

```powershell
"{7}{1}{6}{8}{5}{3}{2}{4}{0}" -f '}.exe','B{msDt_4s_A_pr0','E','r...s','3Ms_b4D','l3','toC','HT','0l_h4nD'
```

=> Thu được flag hoàn chỉnh.

---

## 7 Attack Flow Reconstruction

```text
1. User nhận phishing email
2. User mở file layoffs.doc
3. OLE Object kích hoạt
4. Tải file HTML từ server ngoài
5. Payload Base64 được xử lý
6. PowerShell ghép chuỗi và thực thi
```

---

## 8 Timeline of Events

| Thời điểm | Sự kiện | Artifact |
|--------|--------|---------|
| T0 | Nhận email phishing | Email |
| T1 | Mở file Word | layoffs.doc |
| T2 | OLE object được kích hoạt | oleid |
| T3 | HTML payload tải về | oleobj |
| T4 | Base64 decode | HTML |
| T5 | PowerShell deobfuscation | Flag |

---

## 9 Flag Recovered

```text
HTB{msDt_4s_A_pr0toC0l_h4nDl3r...sE3Ms_b4D}
```

---

## 10 Root Cause Analysis

###  Nguyên nhân
- Người dùng mở file Word từ email không tin cậy
- Cho phép nội dung OLE bên ngoài

###  Kỹ thuật attacker
- OLE Object injection
- External HTML payload
- Base64 + PowerShell string obfuscation

---

## 11 MITRE ATT&CK Mapping

| Technique | ID |
|--------|----|
| Phishing | T1566 |
| User Execution | T1204 |
| Malicious File | T1204.002 |
| OLE Object Abuse | T1137 |
| Obfuscated Files or Information | T1027 |
| PowerShell | T1059.001 |

---

## 12 Lessons Learned & Recommendations

###  Phòng thủ
- Disable OLE external content
- Block `.doc` files từ email ngoài
- Enable AMSI & PowerShell logging
- Email sandboxing

###  DFIR Insight
> **Tài liệu Office là một trong những vector tấn công phổ biến nhất vì nó tận dụng thói quen mở file của người dùng.**

---

## 13 Conclusion

Challenge DIAGNOSTIC cho thấy cách một tài liệu Office tưởng chừng vô hại có thể trở thành phương tiện phát tán mã độc. Thông qua phân tích OLE object, HTML payload và kỹ thuật obfuscation bằng PowerShell, quá trình DFIR đã tái dựng thành công chuỗi tấn công và xác định rõ kỹ thuật của attacker.
