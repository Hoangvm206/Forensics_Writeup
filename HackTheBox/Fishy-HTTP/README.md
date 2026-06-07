# Fishy HTTP – Hack The Box

**Độ khó:** Easy  
**Thể loại:** Forensics / Network

---

## 1 Giới thiệu Challenge

- Có một chương trình khả nghi trên máy người dùng
- Chương trình này gửi các yêu cầu HTTP tới một web server

---

## 2 Mục tiêu

- Phân tích các tệp được cung cấp
- Flag được chia thành **2 phần**

---

## 3 Phương pháp giải

---

## Phần 1: Phân tích PCAP

### Bước 1: Tải file challenge

- Tải file ZIP từ challenge
- Giải nén thu được:
  - 1 Windows binary
  - 1 file PCAP

![alt text](image-1.png)

---

### Bước 2: Phân tích file PCAP

- Mở file PCAP bằng **Wireshark**
- Quan sát thấy phần lớn traffic là HTTP

![alt text ](image-2.png)

- Kiểm tra các HTTP stream
- Phát hiện một stream chứa nội dung phản hồi bất thường
![alt text](image-6.png)

---

### Bước 3: Trích xuất chuỗi từ HTTP response

- Lưu nội dung phản hồi (màu đỏ) vào file `zup.txt`
- Viết script Python để ghép ký tự đầu của mỗi từ

Tạo script `extract_first_letters.py`:

```python
def extract_first_letters(file_path):
    result = ""
    try:
        with open(file_path, 'r') as file:
            content = file.read()
            words = content.split()
            for word in words:
                if word[0].isalpha():
                    result += word[0]
                else:
                    result += word[0]
        print("Extracted String:", result)
    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found.")
    except Exception as e:
        print(f"An error occurred: {e}")

file_path = "zup.txt"
extract_first_letters(file_path)
```

- Chạy script thu được một chuỗi mã hoá

![alt text](image-7.png)

---

### Bước 4: Giải mã Base64

- Sao chép chuỗi vừa thu được
- Dán vào **CyberChef**
- Sử dụng operation **Base64 Decode**

![alt text](image-8.png)

-> Thu được **phần 1 của flag**:

```text
h77P_s73417hy_revSHELL}
```

---

## Phần 2: Phân tích file nhị phân

### Bước 1: Phân tích binary

- Mở Windows binary bằng **Detect It Easy**

![alt text](image-9.png)

- Binary được viết bằng **.NET framework**
- Có dấu hiệu biên dịch C++

---

### Bước 2: Phân tích .NET bằng dotPeek

- Mở file bằng **dotPeek**
- Phát hiện project đáng ngờ: **My Project**

![alt text](image-10.png)

- Trong project có logic decode HTML
- Áp dụng logic này để giải mã HTML stream trong PCAP

---

### Bước 3: Trích xuất HTML stream

- Quay lại Wireshark
- Tìm HTTP stream chứa nội dung HTML

![alt text](image-11.png)

---

### Bước 4: Viết script decode HTML

Viết script Python dựa trên logic decode trong binary:

```python
import re

tag_hex = {
    "cite": "0", "h1": "1", "p": "2", "a": "3", "img": "4", "ul": "5", "ol": "6",
    "button": "7", "div": "8", "span": "9", "label": "a", "textarea": "b", "nav": "c",
    "b": "d", "i": "e", "blockquote": "f"
}

def decode_html(input_file):
    with open(input_file, 'r') as f:
        html_content = f.read()

    decoded_str = ""
    matches = re.findall(r'<(\w+)[\s>]', html_content)
    for match in matches:
        if match in tag_hex:
            decoded_str += tag_hex[match]

    print("Hex String:", decoded_str)

    decoded_bytes = bytes.fromhex(decoded_str)
    decoded_ascii = decoded_bytes.decode('ascii')

    print("\nDecoded ASCII:")
    print(decoded_ascii)

input_file = input("Enter path to HTML file: ")
decode_html(input_file)
```

- Lưu HTML stream ra file
- Chạy script trên file đó

- ![alt text](image-12.png)

-> Thu được **phần còn lại của flag**:

```text
HTB{Th4ts_d07n37_
```

---

## 4 Kết quả

Ghép 2 phần flag:

```text
HTB{Th4ts_d07n37_h77P_s73417hy_revSHELL}
```

![alt text](image-13.png)

---

## 5 Kết luận & Bài học rút ra

- Wireshark giúp nhanh chóng xác định traffic HTTP và các stream chứa payload
- Việc trích xuất dữ liệu rồi viết script tự động giúp giảm sai sót so với làm thủ công
- Detect It Easy hỗ trợ phân loại binary nhanh
- dotPeek rất hữu ích để phân tích logic ẩn trong file .NET

