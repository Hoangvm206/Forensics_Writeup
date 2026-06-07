#  DFIR REPORT  
## Incident: Suspicious Threat – Hack The Box

**Difficulty:** Easy  
**Category:** Digital Forensics & Incident Response (DFIR)  

---

## 1 Executive Summary

Trong quá trình giám sát hệ thống, nhóm SOC phát hiện một máy chủ Linux có dấu hiệu bất thường liên quan đến **thư viện động bị can thiệp**. Điều tra cho thấy hệ thống đã bị nhiễm **userland rootkit** thông qua cơ chế **LD_PRELOAD**, cho phép kẻ tấn công che giấu file và tiến trình độc hại.

Rootkit được sử dụng để ẩn một thư mục trong `/var/`. Sau khi xác định và loại bỏ thư viện độc hại, hệ thống được xác nhận không còn dấu hiệu persistence.

---

## 2 Incident Overview

| Thuộc tính | Mô tả |
|----------|------|
| Hệ điều hành | Linux |
| Dấu hiệu ban đầu | Lệnh hệ thống hoạt động bất thường |
| Loại tấn công | Userland Rootkit |
| Kỹ thuật chính | Library Hooking (LD_PRELOAD) |
| Mức độ ảnh hưởng | Medium |
| Dữ liệu điều tra | Hệ thống live (SSH access) |

---

## 3 Scope & Impact Assessment

### Hệ thống bị ảnh hưởng
- Máy chủ Linux (môi trường mô phỏng)

### Tác động
- Che giấu file và thư mục
- Có khả năng ẩn tiến trình và hành vi độc hại
- Tạo điều kiện cho attacker duy trì truy cập

 Không phát hiện:
- Rò rỉ dữ liệu
- Kết nối Command & Control ra bên ngoài

---

## 4 Attack Analysis

### 4.1 Initial Detection

Trong quá trình kiểm tra hệ thống:
- Kết quả từ các lệnh như `ls` không phản ánh đầy đủ nội dung thư mục
- Xuất hiện nghi vấn các hàm hệ thống đã bị hook

---

### 4.2 Library Manipulation Discovery

Thực hiện kiểm tra thư viện động của binary hệ thống:

```bash
ldd /bin/ls
```

Phát hiện thư viện **bất thường**:

```text
libc.hook.so.6
```

 Thư viện này **không thuộc thư viện hệ thống chuẩn**, cho thấy:
- Cơ chế LD_PRELOAD đã bị lợi dụng
- Các hàm như `readdir()` và `fopen()` có khả năng đã bị hook

---

### 4.3 Rootkit Identification

- Thư viện `libc.hook.so.6` được xác định là **userland rootkit**
- Rootkit không cần kernel module
- Mục đích chính:
  - Che giấu file
  - Né tránh các phương pháp kiểm tra thông thường

---

### 4.4 Hidden Artifact Discovery

Sau khi vô hiệu hóa rootkit, tiến hành kiểm tra lại filesystem:

```bash
ls -ahl /var/
```

Phát hiện thư mục trước đó bị ẩn:

```text
/var/pr3l04d_
```

Bên trong chứa file:

```bash
/var/pr3l04d_/flag.txt
```

---

## 5 Evidence & Artifacts

| Artifact | Mô tả |
|--------|------|
| libc.hook.so.6 | Thư viện rootkit userland |
| /var/pr3l04d_ | Thư mục bị che giấu |
| flag.txt | Minh chứng hoạt động của rootkit |

---

## 6 Timeline of Events

| Thời điểm | Sự kiện | Bằng chứng |
|--------|-------|----------|
| T0 | Hệ thống có hành vi bất thường | Output `ls` |
| T1 | Phát hiện thư viện lạ | `ldd /bin/ls` |
| T2 | Xác định userland rootkit | libc.hook.so.6 |
| T3 | Vô hiệu hóa rootkit | Gỡ thư viện |
| T4 | Phát hiện artifact bị ẩn | /var/pr3l04d_ |

---

## 7 Remediation & Recovery

###  Các bước xử lý

- Gỡ bỏ thư viện độc hại:
```bash
rm -rf /lib/x86_64-linux-gnu/libc.hook.so.6
```

- Tái tạo linker cache:
```bash
ldconfig
```

- Kiểm tra lại biến môi trường:
```bash
env | grep LD_
```

---

## 8 Lessons Learned & Recommendations

### Bài học rút ra
- Userland rootkit có thể rất hiệu quả dù không cần quyền kernel
- LD_PRELOAD là một vector tấn công nguy hiểm nhưng thường bị bỏ sót

### Khuyến nghị
- Giám sát integrity thư viện hệ thống
- Audit biến môi trường (LD_PRELOAD, LD_LIBRARY_PATH)
- Hạn chế quyền ghi vào `/lib` và `/usr/lib`
- Sử dụng công cụ phát hiện rootkit định kỳ

---

## 9 Mapping MITRE ATT&CK

| Technique | ID |
|---------|----|
| Shared Library Hijacking | T1574.002 |
| Defense Evasion | TA0005 |
| Persistence | TA0003 |

---

## 10 Conclusion

Sự cố cho thấy **userland rootkit** có thể che giấu hiệu quả các dấu vết tấn công mà không cần can thiệp kernel. Phân tích thư viện động là bước then chốt trong điều tra DFIR và phản ứng sự cố trên hệ thống Linux.
