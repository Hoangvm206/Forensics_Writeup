#  TrueSecret – Hack The Box

**Độ khó:** Easy  
**Thể loại:** Forensics

---

## 1 Giới thiệu Challenge

- Bối cảnh: Lực lượng chức năng bắt giữ thủ lĩnh một nhóm APT
- Thu được bản chụp bộ nhớ (memory dump) từ máy tính đang chạy của hắn
- Nhóm APT sử dụng một **máy chủ Command & Control (C2) tùy chỉnh**

---

## 2 Mục tiêu

- Phân tích memory dump
- Trích xuất hoặc tái tạo:
  - Mã nguồn C2
  - Cấu hình
  - Giao thức giao tiếp của máy chủ C2

---

## 3 Phương pháp giải

### Bước 1: Phân tích file ZIP và memory dump

- Giải nén file được cấp, thu được:

![alt text](image.png)

- File `TrueSecrets.raw` được nhận diện là **file data**
- Sử dụng **Volatility 2** để phân tích

![alt text](image-1.png)

---

### Bước 2: Xác định profile hệ điều hành

- Thử profile:

```text
Win7SP1x86_23418
```

- Liệt kê các process đang chạy:

```bash
vol -f TrueSecrets.raw --profile=Win7SP1x86_23418 pslist
```

![alt text](image-2.png)

![alt text](image-3.png)

- Các process đáng chú ý:
  - `TrueCrypt.exe`
  - `DumpIt.exe` (tool dump RAM)
  - `7zFM.exe` (nén/giải nén)
  - `WiMPrvSE.exe` (process thường bị giả mạo)

---

### Bước 3: Phân tích command line

- Kiểm tra tham số dòng lệnh của các process:

```bash
vol -f TrueSecrets.raw --profile=Win7SP1x86_23418 cmdline
```

![alt text](image-4.png)

- Phát hiện `7zFM.exe` trỏ tới một file ZIP backup

---

### Bước 4: Trích xuất file ZIP từ RAM

- Dump file ZIP từ memory

![alt text](image-5.png)

- Sau khi trích xuất thu được:
  - 2 file dạng `.dat` và `.vacb`

![alt text](image-6.png)

- Giải nén tiếp thu được file có đuôi:

```text
.tc
```

![alt text](image-7.png)

---

### Bước 5: Bẻ khóa file TrueCrypt

- Sử dụng plugin Volatility:

```bash
vol -f TrueSecrets.raw --profile=Win7SP1x86_23418 truecryptpassphrase
```

![alt text](image-8.png)

- Mật khẩu thu được:

```text
X2Hk2XbEJqWYsh8VdbSYg6WpG9g7
```

---

### Bước 6: Mount container TrueCrypt

- Dùng **VeraCrypt 1.25** để mount file `.tc`

![alt text](image-9.png)

![alt text](image-10.png)

- Truy cập thư mục **agent server**
- Phát hiện đoạn code mã hóa bất thường

![alt text](image-11.png)

---

### Bước 7: Phân tích mã hóa C2

- Đoạn code sử dụng:
  - Thuật toán **DES**
  - Key và IV **cố định**
- Plaintext → Encrypt → Ciphertext dạng **Base64**

---

### Bước 8: Viết script giải mã

- Viết script decrypt để giải mã file session còn lại

![alt text](image-13.png)

- Chạy script và thu được dữ liệu giải mã

![alt text](image-12.png)

---


## 4 Kết luận & Bài học rút ra

- Nhóm APT sử dụng **hai lớp che giấu**:
  - Mã hóa volume bằng TrueCrypt
  - C2 tùy chỉnh với mã hóa DES cố định
- Sai lầm nghiêm trọng:
  - Không xóa sạch dữ liệu nhạy cảm khỏi RAM
- Volatility đã:
  - Trích xuất thành công mật khẩu TrueCrypt từ bộ nhớ
  - Cho phép truy cập mã nguồn C2
  - Tái tạo và đảo ngược thuật toán mã hóa DES
- Bài học:
  - **Memory forensics** là chìa khóa để phá vỡ các lớp mã hóa tĩnh
  - Thu thập RAM sớm có thể tiết lộ key, passphrase và protocol C2 bị bỏ sót
