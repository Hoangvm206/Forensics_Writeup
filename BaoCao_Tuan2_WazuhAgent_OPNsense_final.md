# BÁO CÁO THỰC TẬP TUẦN 2
## Đánh Giá Bảo Mật Plugin Wazuh Agent trên OPNsense & Thiết Kế Mở Rộng 2 Chiều

| | |
|---|---|
| **Tuần báo cáo** | Tuần 2 — 28/09/2026 đến 03/10/2026 |
| **Ngày báo cáo** | Thứ 7, 03/10/2026 |

> **Quy ước:**
> -  **Đã kiểm chứng** — có bằng chứng đi kèm
> -  **Cần kiểm chứng thêm** — nhận định ban đầu
> -  **Đề xuất/dự kiến** — chưa triển khai

---

## I. MÔI TRƯỜNG THỬ NGHIỆM

| Thành phần | IP | Vai trò |
|---|---|---|
| Wazuh Manager | 192.168.56.107 | Nhận log, quản lý agent |
| OPNsense + Plugin | 192.168.56.56 | Firewall |
| Plugin os-wazuh-agent | — | Plugin OPNsense |
| Wazuh Agent (binary) | — | Agent gửi log |
| Máy phân tích | Host | Bắt gói tin |

---

## II. TÓM TẮT PHÁT HIỆN CHÍNH

| # | Phát hiện | Mức độ | Trạng thái |
|---|---|---|---|
| F1 | Agent không xác minh chứng chỉ Manager khi enrollment: template plugin không đặt `<server_ca_path>` → rủi ro Manager giả | Cao | Đã kiểm chứng (source code + `ossec.conf` thực tế trên OPNsense không có `server_ca_path`); tấn công chưa thử |
| F2 | Cổng 1514 dùng AES key tĩnh, không có PFS | Trung bình | Đã kiểm chứng |
| F3 | Key AES lưu plaintext trong `client.keys`, IP binding = `any` | Cao | Đã kiểm chứng |
| F4 | 4/5 tiến trình Wazuh chạy quyền root | Trung bình | Đã kiểm chứng |
| F5 | `remote_commands` — plugin đặt mặc định bật (`Default=1` trong `WazuhAgent.xml`); cần xác minh nơi giá trị được áp dụng và phạm vi tác động (không phải điều kiện của Active Response) | Trung bình (chờ xác minh) | Mặc định: đọc source code; phạm vi: cần kiểm chứng thêm |
| F6 | `auth.password` trong model không có validation rule | Trung bình | Đọc source code |
| F7 | Manager không xác thực chứng chỉ agent (không có mTLS): `ssl_verify_host=no` trên Manager; agent chỉ được kiểm soát bằng password enrollment (nếu bật `use_password`) | Trung bình | Đã kiểm chứng (Ảnh 3: `ssl_verify_host=no`; `ssl_agent_ca` đang bị comment trong `<auth>` trên Manager) |
| F8 | Lệnh chặn on-demand (`agent_control`) không có `rule.id` nên `opnsense-fw` không gửi `check_keys`; `wazuh-execd` không đăng ký vào timeout list → IP bị chặn không tự mở khoá | Trung bình | Đã kiểm chứng (thực nghiệm IP `.88`, `.1`; đối chiếu `execd.c` 4.14.7) |
| F9 | Manager không có alert xác nhận khi agent đã thực thi Active Response | Thấp | Đã khảo sát `alerts.log`; giải pháp ở mức đề xuất |
| F+ | **Điểm tích cực:** TLS 1.3 + X25519MLKEM768 (post-quantum) ở cổng 1515 | Mạnh | Đã kiểm chứng |
| F+ | **Điểm tích cực:** Kênh Manager → agent (Active Response) có sẵn trên 1514; `opnsense-fw` kiểm tra IP và không dùng shell | Tốt | Đã kiểm chứng (PoC ngày thứ 4) + đọc source code |
| F+ | **Điểm tích cực:** 3 CVE Wazuh đã biết (CVE-2026-54083/54084/54085) đều ảnh hưởng ≤ 4.14.6; bản đang chạy 4.14.7 đã vá | Tốt | Đã kiểm chứng phiên bản (`pkg info`: `wazuh-agent-4.14.7`) + đối chiếu advisory |

---

## III. PHÂN TÍCH GIAO THỨC OSSEC

### 3.1 Cổng 1515 — Enrollment (authd) 

> ![alt text](<Screenshot 2026-09-29 143218.png>)

> ![alt text](<Screenshot 2026-09-29 143625.png>)

> ![alt text](<Screenshot 2026-09-29 152354.png>)

**Kết quả quan sát:**

| Câu hỏi | Kết quả | Bằng chứng |
|---|---|---|
| Có TLS Handshake không? | Có — TLS 1.3 | Ảnh 1+2: Client Hello / Server Hello |
| Cipher Suite được chọn | TLS_AES_256_GCM_SHA384 (0x1302) | Ảnh 2: Server Hello |
| Key Exchange | X25519MLKEM768 (post-quantum hybrid) | Ảnh 2: key_share extension |
| Agent gửi Certificate không? | Không — không có mTLS | Ảnh 2: không có Certificate Request |
| Manager có xác thực chứng chỉ agent không (mTLS)? | Không (`ssl_verify_host=no` trên Manager) | Ảnh 3: cấu hình `<auth>` trên Wazuh Manager |
| Agent có xác minh chứng chỉ Manager không? | Không (template plugin không đặt `<server_ca_path>`) | Source code template `ossec.conf` (mục 4.6) và `ossec.conf` thực tế trên OPNsense (không có `server_ca_path`) |

**Nhận xét — F1 và F7:**
> Port 1515 dùng TLS 1.3 với X25519MLKEM768 — kết hợp ECDH cổ điển và Kyber (post-quantum), đảm bảo Perfect Forward Secrecy và khả năng chống tấn công từ máy tính lượng tử trong tương lai. Tuy nhiên, template của plugin không cấu hình `<server_ca_path>` trong khối `<enrollment>`, và theo tài liệu Wazuh khi tham số này không được đặt thì agent không xác minh chứng chỉ của Manager (F1). Ở chiều ngược lại, Manager cũng không xác thực chứng chỉ agent (`ssl_verify_host=no`, Ảnh 3; F7). Nếu kẻ tấn công chen vào đúng lúc agent đang enroll, một Manager giả có thể cấp key riêng của nó, từ đó nhận log và gửi lệnh xuống agent (điều kiện tiên quyết xem mục V, kịch bản A; chưa thử nghiệm).

---

### 3.2 Cổng 1514 — Log Transmission 

> ![alt text](<Screenshot 2026-09-29 152702.png>)

> ![alt text](<Screenshot 2026-09-29 152516.png>)

**Kết quả quan sát:**

| Câu hỏi | Kết quả | Bằng chứng |
|---|---|---|
| Protocol: TCP hay UDP? | TCP | Ảnh 5: `<protocol>tcp</protocol>` |
| Có TLS Handshake không? | Không | Ảnh 4: không có Client/Server Hello |
| Giao thức sử dụng | OSSEC proprietary | Ảnh 4: header `!001!#AES:` |
| Payload có bị mã hóa không? | Có — AES | Ảnh 4: không thấy plaintext log |
| Loại key | Pre-shared key tĩnh | Thiết kế giao thức OSSEC |
| Perfect Forward Secrecy | Không có | Key tĩnh, không ephemeral |

**Header OSSEC quan sát được (Ảnh 4):**
```
!001!#AES:<encrypted_payload>
  ↑    ↑
  │    └─ Chỉ định mã hóa AES với pre-shared key
  └────── Agent ID = 001
```

**Nhận xét — F2:**
> Cổng 1514/TCP dùng giao thức OSSEC riêng, không phải TLS. Payload được mã hóa AES bằng pre-shared key trao đổi lúc enrollment. Key này **tĩnh, không có PFS** — khác hoàn toàn với kênh enrollment. Nếu key bị lộ, toàn bộ lịch sử log có thể bị giải mã hồi tố.

---

### 3.3 Bảng So Sánh Giao Thức

| Tiêu chí | OSSEC/1514 | Enrollment/1515 | TLS 1.3 chuẩn |
|---|---|---|---|
| Giao thức | OSSEC riêng | TLS 1.3 | TLS 1.3 |
| Mã hóa | AES pre-shared key | AES-256-GCM | AES-256-GCM |
| Perfect Forward Secrecy | Không | X25519MLKEM768 | ECDHE |
| Post-quantum | Không | MLKEM768 (Kyber) | Tùy triển khai |
| Xác thực server (agent kiểm tra Manager) | N/A | Không (không đặt `server_ca_path`) | Bắt buộc |
| mTLS | Không | Không có Cert Request | Tùy chọn |
| Chuẩn công nghiệp | Giao thức riêng | RFC 8446 | RFC 8446 |

---

## IV. ĐÁNH GIÁ PLUGIN OS-WAZUH-AGENT

> Source code: `https://github.com/opnsense/plugins/tree/master/security/wazuh-agent`

### 4.1 Quyền File & Lưu Trữ Key

> ![alt text](<Screenshot 2026-09-29 160952.png>)

**Kết quả:**
```
-rw-r----- 1 wazuh wazuh 87  /var/ossec/etc/client.keys
001 OPNsense-OTSA any a93d20820c926104d259bd7c70a5dafc...
```

| Tiêu chí | Kết quả | Đánh giá |
|---|---|---|
| Permissions | `640` (rw-r-----) | Chỉ wazuh:wazuh đọc được |
| Định dạng lưu key | Plaintext | Root có thể đọc và giải mã traffic |
| IP binding | `any` | Key dùng được từ bất kỳ IP nào |
| Vị trí file | `/var/ossec/etc/` | Không public |

**Nhận xét — F3:**
> `client.keys` được bảo vệ ở mức chấp nhận được (640). Tuy nhiên, key AES lưu plaintext — nếu kẻ tấn công có quyền root (hoặc exploit một trong 4 tiến trình root), toàn bộ lịch sử traffic port 1514 có thể bị giải mã. IP = `any` làm giảm thêm giá trị bảo vệ của key.

---

### 4.2 Tiến Trình & Quyền Hạn

**Kết quả:**
| Tiến trình | User | Cần thiết không? |
|---|---|---|
| `wazuh-agentd` | `wazuh` |  Đúng — core agent không cần root |
| `wazuh-execd` | `root` |  Cần root để gọi `pfctl` |
| `wazuh-syscheckd` | `root` |  Cần root để đọc toàn bộ filesystem |
| `wazuh-logcollector` | `root` |  Cần root để đọc system logs |
| `wazuh-modulesd` | `root` |  Nên kiểm tra lại có thực sự cần root không |

**Nhận xét — F4:**
> 4/5 tiến trình chạy root — một phần là do yêu cầu kỹ thuật (pfctl, filesystem scan), nhưng làm tăng bề mặt tấn công. Đặc biệt `wazuh-execd` chạy root: mọi lệnh đến được nó đều có tác động ở mức root, nên xác thực Manager (F1) và kiểm tra đầu vào của script là hai lớp cần bảo vệ (xem mục V).

---

### 4.3 Input Validation từ GUI (Source Code) 

**File:** `src/opnsense/mvc/app/models/OPNsense/WazuhAgent/WazuhAgent.xml`

| Field | Kiểu validation | An toàn? |
|---|---|---|
| `server_address` | `HostnameField` |  Không inject XML được |
| `agent_name` | `HostnameField` |  Không inject XML được |
| `protocol` | `OptionField` (tcp/udp) |  Enum cứng |
| `port` | `IntegerField` 1–65536 |  Bounded |
| `auth.password` | `TextField` *(không có gì)* | Không có Mask/MinLength/MaxLength |
| `repeated_offenders` | `TextField` + Regex Mask | Có validation |

**Nhận xét — F6:**
> `auth.password` là `TextField` trống — không có regex, không giới hạn độ dài. Cần kiểm tra thêm cách password này được truyền vào quá trình enrollment (dưới dạng argument hay environment variable) và có bị log ra không.

---

### 4.4 Active Response Script — `opnsense-fw` 

**File:** `src/opnsense/scripts/wazuh/opnsense-fw` (Python)

| Tiêu chí | Kết quả | Đánh giá |
|---|---|---|
| Validate IP input | `ipaddress.ip_address(srcip)` | Không inject được |
| Subprocess shell injection | `subprocess.run([list])` — không dùng `shell=True` | An toàn |
| Whitelist | `skip_alias` từ `opnsense-fw.conf` | Có cơ chế bảo vệ IP quan trọng |
| Trao đổi `check_keys` | Script gửi `check_keys`, chờ `continue`/`abort` từ `wazuh-execd` cục bộ (chống chạy trùng) | Đúng theo tài liệu Wazuh |
| Rate limiting | Không có | Có thể block nhiều IP liên tục |
| Quyền thực thi | Root (vì cần `pfctl`) | Cần kiểm tra đầu vào chặt (script đã làm) |

---

### 4.5 Rà soát lỗ hổng đã biết (CVE)

> **Phương pháp:** đối chiếu phiên bản đang chạy với GitHub Security Advisories của Wazuh và NVD/OSV.
> **Trạng thái:** đối chiếu advisory, **chưa thử khai thác**.
> **Phiên bản đang chạy:** `wazuh-agent-4.14.7` (FreeBSD 15, amd64)
>
> **Xác nhận phiên bản** (`pkg info | grep -i wazuh` trên OPNsense): `os-wazuh-agent-1.3_1` (plugin) và `wazuh-agent-4.14.7` (agent).

#### 4.5.1 Kết quả đối chiếu

| CVE / Advisory | Mô tả | CVSS | Phiên bản ảnh hưởng | Bản vá | Với 4.14.7 |
|---|---|---|---|---|---|
| **CVE-2026-54084** / GHSA-ppc7-hj9v-vx39 | NULL pointer dereference khi enrollment (CWE-476): Manager giả hoặc MITM trả chuỗi thiếu trường (ví dụ `OSSEC K:'1'`) làm tiến trình agent crash | 5.3 (Medium) | 4.0.0 – 4.14.6 | 4.14.7 | Đã vá |
| **CVE-2026-54085** / GHSA-mvh4-g699-984j | Argument injection (CWE-88) trong script Active Response viết bằng C: 5/8 script xử lý `srcip` (`route-null`, `netsh`, `pf`, `npf`, `ipfw`) bỏ qua `get_ip_version()`; `disable-account` nhận `dstuser` gần như không kiểm tra. Kẻ tấn công chèn được log giả (ví dụ qua syslog) có thể đưa tham số vào lệnh chạy bằng root | 7.1 (High) | 4.2.0 – 4.14.6 | 4.14.7 | Đã vá |
| **CVE-2026-54083** / GHSA-m4mf-qmhf-8vj6 | Path traversal (CWE-22) trong `ip-customblock`: trường `srcip` từ alert JSON được ghép vào thư mục `/ipblock/` mà không kiểm tra là IP hợp lệ, cho phép tạo hoặc xoá file tuỳ ý bằng quyền root | 8.1 (High) | 4.2.0 – 4.14.6 | 4.14.7 | Đã vá |


#### 4.5.2 Nhận xét

1. **Kết luận:** cả ba lỗ hổng đều thuộc phạm vi ≤ 4.14.6. Bản đang chạy (4.14.7) **không bị ảnh hưởng**, đây là điểm tích cực của hệ thống. Với các triển khai còn dùng bản cũ hơn, cả ba đều là rủi ro thực tế và cần nâng cấp.
2. **Điểm chung của ba lỗi:** một tiến trình chạy quyền root tin tưởng dữ liệu đến từ alert hoặc từ Manager (`srcip`, `dstuser`, chuỗi key trả về) mà không kiểm tra định dạng. Đây là bài học trực tiếp cho phần mở rộng nhận lệnh từ Manager: mọi trường dữ liệu đi vào lệnh hệ thống phải được kiểm tra chặt, không ghép chuỗi vào lệnh, chạy với quyền tối thiểu.
3. **Script `opnsense-fw` (Python)** của plugin đã tự kiểm tra IP bằng `ipaddress.ip_address()` và gọi `pfctl` không qua shell (mục 4.4), nên thiết kế của plugin vốn tránh được lớp lỗi ở CVE-2026-54085.

#### 4.5.3 Script Active Response hiện diện trên OPNsense (bề mặt tấn công thừa)

> ![alt text](<Screenshot 2026-09-29 163101.png>)
> *Hình: nội dung `/var/ossec/active-response/bin/` trên OPNsense.*

Gói `wazuh-agent-4.14.7` vẫn cài sẵn các binary AR viết bằng C vào cùng thư mục với `opnsense-fw`. Với bản đã vá thì chúng không còn là lỗ hổng, nhưng OPNsense chỉ dùng PF và `opnsense-fw`, nên các file thừa này chỉ làm tăng bề mặt tấn công (nguyên tắc defense in depth).

| Script | Ngôn ngữ | Nằm trong danh sách ảnh hưởng của advisory (≤ 4.14.6)? | Đề xuất |
|---|---|---|---|
| `opnsense-fw` | Python | Không (script của plugin, có kiểm tra IP) | Giữ làm script chính |
| `pf`, `route-null` | C | CVE-2026-54085 | Thu hồi quyền thực thi hoặc gỡ |
| `ipfw`, `npf` | C | CVE-2026-54085 | Gỡ (OPNsense không dùng IPFW/NPF) |
| `ip-customblock` | Script | CVE-2026-54083 | Gỡ nếu không dùng blacklist tuỳ chỉnh |
| `host-deny`, `default-firewall-drop` | C | Không nằm trong danh sách của advisory | Tuỳ chọn |


### 4.6 Tổng hợp các file source code đã đọc

> Repo `opnsense/plugins`, thư mục `security/wazuh-agent`.

| File | Phát hiện | Đánh giá |
|---|---|---|
| `Makefile` | Plugin phiên bản 1.3 là lớp bọc (wrapper) của OPNsense, phụ thuộc gói `wazuh-agent` lấy từ FreeBSD Ports. Phiên bản Wazuh thật (4.14.7) xác định bằng `pkg info wazuh-agent` | Bản vá lỗi phụ thuộc vào gói ports nên cần theo dõi cập nhật |
| `+POST_INSTALL.post` | Sau khi cài, chép `opnsense-fw` vào `/var/ossec/active-response/bin/`, quyền `750`, chủ sở hữu `root:wazuh` | Quyền hợp lý (người dùng khác không đọc, chạy, sửa được); cho thấy plugin có sẵn cơ chế phản ứng |
| `opnsense-fw` | Kiểm tra IP bằng `ipaddress.ip_address()`; gọi `pfctl` không qua shell; `pfctl -t __wazuh_agent_drop -T add` rồi `pfctl -k` để cắt các kết nối đang mở; `delete` khi hết timeout; khoá chống trùng `rule_id-srcip` | Tốt, không mắc lớp lỗi như CVE-2026-54085 |
| `templates/OPNsense/WazuhAgent/ossec.conf` | • `crypto_method aes` (khớp `!001!#AES:` trong Wireshark)<br>• Khối `<enrollment>` không có `<server_ca_path>`<br>• **Khối `<client_buffer>` đã kích hoạt sẵn:** `<queue_size>5000</queue_size>`, `<events_per_second>500</events_per_second>` | • Nguyên nhân gốc của F1: agent không xác minh Manager khi enrollment.<br>• **Giải quyết yêu cầu hàng đợi:** Agent có sẵn bộ đệm 5000 sự kiện khi mất mạng, không cần cài thêm Fluent Bit. |
| `models/OPNsense/WazuhAgent/WazuhAgent.xml` | `active_response` và `remote_commands` mặc định bật (`Default=1`); host/port có validation; `auth.password` là `TextField` không ràng buộc; **chưa có các trường mTLS cert, API key, whitelist IP** | Liên quan F5, F6 và chỉ ra chính xác các trường cần bổ sung lên GUI cho giai đoạn phát triển tiếp theo. |

---

### 4.7 Phân tích cơ chế Hàng đợi đệm khi mất kết nối (`client_buffer`)

> **Vị trí phát hiện:** Template `src/opnsense/service/templates/OPNsense/WazuhAgent/ossec.conf` dòng 16–21.

Trong file cấu hình sinh ra cho Agent trên OPNsense, khối điều khiển bộ đệm được thiết lập mặc định như sau:
```xml
  <client_buffer>
    <!-- Agent buffer options -->
    <disabled>no</disabled>
    <queue_size>5000</queue_size>
    <events_per_second>500</events_per_second>
  </client_buffer>
```

* **Cơ chế hoạt động:**
  1. Khi kết nối TCP cổng 1514 tới Wazuh Manager bị gián đoạn (sự cố đường truyền, đứt cáp mạng OT, hoặc Manager bảo trì), tiến trình `wazuh-agentd` sẽ không hủy bỏ các log mới thu thập được mà chuyển sang chế độ lưu đệm (Buffering).
  2. Dung lượng hàng đợi đệm cho phép lưu trữ tối đa **5.000 sự kiện (events)** trong hàng đợi bộ nhớ tạm.
  3. Khi kết nối tới Manager được khôi phục, Agent sẽ tự động "xả đệm" (flushing queue) với tốc độ kiểm soát **500 sự kiện/giây** (`events_per_second=500`) nhằm tránh gây bão lưu lượng (traffic burst) hoặc làm quá tải bộ phân tích của Manager.
* **Ý nghĩa đối với yêu cầu phát triển:**
  * **Đáp ứng trực tiếp yêu cầu của Thầy:** Thỏa mãn 100% tiêu chí *"Agent gửi log, hàng đợi khi mất kết nối"* trong bảng nhiệm vụ mới mà không cần phải cài đặt thêm công cụ trung gian phức tạp như Fluent Bit.
  * **Định hướng nâng cấp (Development Roadmap):** Trong môi trường mạng công nghiệp tải cao (nhiều bản tin Suricata EVE JSON hoặc cảnh báo IDS), kích thước 5.000 sự kiện có thể bị đầy nếu sự cố mất mạng kéo dài. Do đó, nội dung phát triển tiếp theo cần **đưa tham số `queue_size` và `events_per_second` lên giao diện Web GUI OPNsense** để người quản trị có thể tùy chỉnh dung lượng hàng đợi linh hoạt theo quy mô mạng OT.

---

## V. MÔ HÌNH ĐE DOẠ KÊNH MANAGER ↔ AGENT

> Mục đích: xác định các đe doạ chính trước khi thiết kế mở rộng nhận lệnh từ Manager. Mỗi kịch bản ghi rõ điều kiện tiên quyết và mức độ đã kiểm chứng.

### 5.1 Tài sản và giả định

- **Tài sản cần bảo vệ:** khả năng giám sát (log về Manager), tính toàn vẹn của firewall OPNsense, khoá `client.keys`.
- **Giả định về đặc quyền:** `wazuh-execd` chạy root để gọi `pfctl` (mục 4.2), nên bất kỳ lệnh nào đến được `execd` đều có tác động ở mức root.
- **Kẻ tấn công điển hình:** thiết bị trong cùng mạng/VLAN với OPNsense, chưa có credential.

### 5.2 Các kịch bản

| # | Kịch bản | Điều kiện tiên quyết | Tác động | Mức độ đã kiểm chứng |
|---|---|---|---|---|
| A | **Manager giả ở bước enrollment** (liên quan F1): kẻ tấn công đứng chặn (ARP/DNS) và giả làm Manager tại cổng 1515 | Agent đang (re-)enroll, ví dụ chưa có `client.keys` hoặc bị buộc enroll lại; và agent không xác minh chứng chỉ Manager (không đặt `server_ca_path`) | Manager giả cấp key của riêng mình, sau đó nhận log và có thể gửi lệnh, cấu hình xuống agent | Source code (mục 4.6) và cấu hình thực tế trên OPNsense đã kiểm chứng. **Tấn công chưa thử.** |
| B | **Agent đã enroll, kẻ tấn công không có key** | Không có `client.keys` | Không giả mạo được lệnh hợp lệ trên 1514 vì payload mã hoá bằng key này; chỉ gây gián đoạn kết nối (DoS mức mạng) | Suy luận từ thiết kế giao thức, cần thử để xác nhận |
| C | **Lộ `client.keys`** (liên quan F3, IP binding = `any`) | Đọc được file (quyền root/wazuh) | Giải mã traffic đã bắt (không có PFS, F2) và giả mạo Manager/agent | Đã kiểm chứng phần lưu trữ (Ảnh mục 4.1) |
| D | **Lạm dụng chính Active Response** | Kẻ tấn công chỉ cần tạo được log khớp rule (không cần chiếm Manager) | `opnsense-fw` block IP hợp lệ, có thể làm gián đoạn dịch vụ; không có rate limit, chỉ có whitelist `skip_alias` | Đọc source code (mục 4.4), chưa thử |
| E | **Bề mặt mới khi thêm kênh nhận lệnh** | Tính năng mở rộng được triển khai | Nếu thiết kế kém: lệnh giả, injection, mở thêm cổng lắng nghe trên firewall | Đề xuất, xem nguyên tắc ở mục VI |

### 5.3 Nhận xét

- Rủi ro lớn nhất của kênh 2 chiều nằm ở **kịch bản A và C**: cả hai đều xoay quanh việc ai nắm được key. Vì vậy hai biện pháp có tác dụng nhất là xác thực Manager khi enrollment và bảo vệ `client.keys`.
- Kịch bản D cho thấy Active Response nên được xem như một chức năng có thể bị kích hoạt từ dữ liệu không tin cậy (log), không chỉ từ Manager đáng tin.
- Tham số `remote_commands` là cơ chế khác (lệnh trong cấu hình logcollector đẩy từ Manager), **không phải điều kiện của Active Response**. Plugin đặt mặc định bật (`Default=1` trong `WazuhAgent.xml`); cần xác minh giá trị này được áp dụng ở đâu và điều khiển gì (xem F5).

---

## VI. ĐỀ XUẤT KHẮC PHỤC VÀ GIA CỐ (theo mức độ ưu tiên)

> Tất cả mục dưới đây là **đề xuất/dự kiến**, chưa triển khai.

| Ưu tiên | Vấn đề | Đề xuất |
|---|---|---|
|  **1** | Agent không xác minh chứng chỉ Manager khi enrollment (F1, kịch bản A) | • Sửa template `ossec.conf` của plugin: thêm `<server_ca_path>` trong khối `<enrollment>` trỏ tới CA của Manager; thêm trường CA trong GUI (`WazuhAgent.xml`).<br>• Trên Manager, dùng chứng chỉ `sslmanager.cert` do chính CA đó ký (theo hướng dẫn manager identity verification của Wazuh).<br>• Hạn chế agent enroll lại tự động; chỉ cho enroll trong cửa sổ bảo trì. |
|  **2** | Key AES tĩnh, plaintext, IP binding `any` (F2, F3, kịch bản C) | • Khi đăng ký agent, chỉ định IP cố định thay vì `any`.<br>• Giữ quyền `640` cho `client.keys`, kiểm tra không bị ghi ra log hoặc sao lưu không mã hoá.<br>• Đặt kênh 1514/1515 sau firewall rule chỉ cho phép IP Manager; nếu cần PFS, cân nhắc bọc kênh trong tunnel (WireGuard/IPsec). |
|  **3** | Binary Active Response thừa trong `active-response/bin/` (mục 4.5.3) | • Thu hồi quyền thực thi hoặc gỡ `pf`, `ipfw`, `npf`, `route-null`, `ip-customblock`.<br>• Trên Manager chỉ khai báo `<command>` trỏ tới `opnsense-fw`. |
|  **4** | Kiểm soát phiên bản | • Duy trì agent ≥ 4.14.7 (các CVE ở 4.5 đã vá từ bản này).<br>• Đưa việc theo dõi Wazuh Security Advisories vào quy trình cập nhật plugin. |
|  **5** | `remote_commands` (F5) | • Mặc định của plugin là bật (`Default=1`); xác minh giá trị này được áp dụng ở đâu.<br>• Nếu đang bật mà không cần, tắt (`0`) để thu hẹp bề mặt. |
|  **6** | Nhiều tiến trình chạy root (F4) | • Đánh giá khả năng chạy `wazuh-modulesd`, `wazuh-logcollector` bằng user `wazuh` (cần kiểm tra khả thi, vì logcollector đọc log hệ thống).<br>• Với `wazuh-execd`, nghiên cứu cách chỉ cho phép gọi `/sbin/pfctl` với đối số giới hạn (ví dụ `sudoers`) thay vì cả daemon chạy root. |
|  **7** | `auth.password` thiếu validation (F6) | • Thêm ràng buộc (Mask/độ dài tối đa) trong `WazuhAgent.xml`.<br>• Kiểm tra password enrollment không đi qua tham số dòng lệnh hay bị ghi vào log. |
|  **8** | Manager không xác thực chứng chỉ agent (F7) | • Cân nhắc bật xác thực agent bằng chứng chỉ: đặt `ssl_agent_ca` và `ssl_verify_host` trên Manager, `agent_certificate_path`/`agent_key_path` trên agent.<br>• Cần quản lý chứng chỉ cho từng agent nên phải đánh giá chi phí vận hành; tối thiểu bật và bảo vệ password enrollment. |
|  **9** | Không có rate limit trong `opnsense-fw` (kịch bản D) | • Giới hạn số lần block trong một khoảng thời gian.<br>• Mở rộng whitelist `skip_alias` cho IP hạ tầng quan trọng, tránh tự chặn nhầm. |
|  **10** | Lệnh on-demand không có timeout (F8) | • Vá `opnsense-fw`: khi không có `rule.id`, dùng khoá dự phòng (ví dụ dựa trên `srcip`) để vẫn gửi `check_keys` và được đăng ký timeout.<br>• Hoặc cung cấp cặp lệnh Block/Unblock chủ động cho OTSD. |
|  **11** | Không có alert xác nhận kết quả (F9) | • Viết decoder và rule trên Manager cho dòng `Active response executed (...)` để có alert xác nhận. |

### Nguyên tắc thiết kế cho phần mở rộng nhận lệnh (định hướng tuần sau)

Rút ra từ mục 4.5 và mô hình đe doạ ở mục V:

1. **Ưu tiên tận dụng kênh 1514 và cơ chế Active Response hiện có** thay vì mở thêm cổng lắng nghe (API) trên firewall.
2. **Allowlist lệnh:** chỉ chấp nhận một tập lệnh cố định (ví dụ block/unblock IP), mọi lệnh khác bị từ chối.
3. **Kiểm tra chặt mọi tham số** trước khi đi vào lệnh hệ thống (định dạng IP, độ dài, không ghép chuỗi vào shell), theo cách `opnsense-fw` đang làm.
4. **Quyền tối thiểu và ghi log kiểm toán** cho mọi lệnh nhận được và kết quả thực thi.
5. **Xác thực Manager trước khi tin lệnh** (phụ thuộc đề xuất 1 ở trên).

---

## PHỤ LỤC B — NHẬT KÝ THỰC NGHIỆM

### Thứ 2 
- Dựng Wazuh Manager (Ubuntu VM, IP 192.168.56.107)
- Resume OPNsense VM qua Vagrant
- Cài Wazuh Agent, đăng ký thành công (Agent ID 001, tên OPNsense-OTSA)
- Bắt 2 file capture: `wazuh_verify.pcap` (1515) và `wazuh_active_1514.pcap` (1514)
- Khó khăn: Docker không chạy được (nested virtualization), SSH config VM cũ mất thêm 1 giờ

### Thứ 3 
- Phân tích Wireshark: xác nhận TLS 1.3 + X25519MLKEM768 ở 1515, OSSEC/AES ở 1514
- Đọc source code plugin: Makefile, POST_INSTALL, WazuhAgent.xml, ossec.conf template, opnsense-fw script
- Kiểm tra trực tiếp trên OPNsense VM: client.keys permissions, ps aux
- Tổng hợp và cập nhật báo cáo, phân tích 3 CVE/GHSA trọng yếu

### Thứ 4  (Thực nghiệm Active Response theo Alert & Chứng minh kênh 2 chiều)
- **Cấu hình trên Wazuh Manager:**
  - Khai báo `<command>` trỏ tới thực thi `opnsense-fw` với `timeout_allowed=yes`.
  - Khai báo `<active-response>` kích hoạt khi phát hiện tấn công xác thực SSH (Rule 5710, 5716) với timeout chặn 60 giây.
- **Phát hiện cấu hình đường ống Log trên OPNsense:**
  - Agent trên OPNsense thu thập log qua file trung gian `/var/ossec/logs/opnsense_syslog.log` (định dạng syslog).
- **Kịch bản thực nghiệm kích hoạt tấn công:**
  - Giả lập hành vi SSH Brute-force/Invalid User từ IP nguồn vi phạm `192.168.56.99` vào OPNsense.
  - Manager nhận diện thành công sự kiện: `Rule 5710 (level 5) -> 'sshd: Attempt to login using a non-existent user' - Src IP: 192.168.56.99`.
- **Bằng chứng thực nghiệm tại `active-responses.log` (trên agent):**
  1. Manager kích hoạt Active Response và gửi lệnh `{"command": "add", ...}` xuống agent qua kết nối TCP 1514; `wazuh-execd` trên agent chạy script `opnsense-fw`.
  2. Script gửi thông điệp `check_keys` ra STDOUT: `Sending check_keys for: 5710-192.168.56.99`.
  3. Script chờ phản hồi trên STDIN: `Waiting for manager response...`.
  4. Phản hồi `{"command": "continue", ...}` được trả về, script ghi `Manager says: continue`.
  5. Script thực thi: `Active response executed (add 192.168.56.99)`.
  - *Lưu ý:* nhãn "manager" trong các dòng log do script tự đặt. Theo mã nguồn `execd.c`, thông điệp `check_keys` được script gửi cho `wazuh-execd` cục bộ trên agent, và phản hồi `continue`/`abort` cũng đến từ `wazuh-execd`.
- **Kiểm chứng tác động trên Tường lửa PF:**
  - Chạy lệnh `pfctl -t __wazuh_agent_drop -T show` trên OPNsense.
  - **Kết quả:** Địa chỉ IP `192.168.56.99` đã bị đẩy trực tiếp vào bảng lọc gói tin `__wazuh_agent_drop` của kernel FreeBSD/PF.
- **Hoàn nguyên sau timeout:** Sau 60 giây `wazuh-execd` tự gọi lại script với `delete`, IP biến mất khỏi bảng `pfctl`.

### Thứ 5 & Thứ 6 (Thực nghiệm Lệnh Chủ Động On-demand & Thiết kế Kênh Xác Nhận 2 Chiều)

#### 1. Hướng 1: Thực nghiệm ra lệnh chủ động theo yêu cầu (On-demand Control)
- **Mục tiêu:** Chứng minh Manager có thể chủ động ra lệnh chặn/mở IP bất kỳ lúc nào mà không cần tạo log giả mạo hay chờ alert.
- **Phương pháp:** Sử dụng công cụ `agent_control` trên Manager:
  - Tra cứu định danh Active Response: `agent_control -L` → xác định tên `opnsense-drop60` (tương ứng với script `opnsense-fw`, timeout 60s).
  - Phát lệnh từ Manager:
    ```bash
    sudo /var/ossec/bin/agent_control -b 192.168.56.88 -f opnsense-drop60 -u 001
    ```
- **Bằng chứng thực nghiệm trên OPNsense:**
  - File `/var/ossec/logs/active-responses.log` ghi nhận bản tin JSON nhận từ Manager:
    ```json
    Received : {"version": 1, "origin": {"name": "", "module": "wazuh-execd"}, "command": "add", "parameters": {"extra_args": [], "alert": {"data": {"srcip": "192.168.56.88"}}}, "program": "active-response/bin/opnsense-fw"}
    Active response executed (add 192.168.56.88)
    ```
  - Kiểm tra bảng PF: `pfctl -t __wazuh_agent_drop -T show` in ra chính xác `192.168.56.88`.

- **Thực nghiệm kiểm chứng lưu lượng mạng thực tế (Live Network Drop & Recovery):**
  - **Kịch bản:** Máy Windows Host (`192.168.56.1`) thực hiện gửi gói tin ICMP liên tục (`ping -t 192.168.56.56`) tới firewall OPNsense.
  - **Kích hoạt chặn:** Trên Manager, phát lệnh chặn IP máy Windows: `agent_control -b 192.168.56.1 -f opnsense-drop60 -u 001`.
  - **Tác động tức thì:** Cửa sổ PowerShell của Windows lập tức ghi nhận `Request timed out` đồng loạt ngay tại giây tiếp theo. Điều này chứng minh lệnh điều khiển can thiệp trực tiếp vào nhân Kernel Packet Filter (PF) trong vòng một chu kỳ ping (khoảng 1 giây).
  - **Khôi phục mạng:** Khi thực hiện xóa IP khỏi bảng tường lửa (`pfctl -t __wazuh_agent_drop -T delete 192.168.56.1`), lưu lượng mạng được khôi phục ngay (`Reply from 192.168.56.56: time=1ms`). Phải gỡ thủ công vì lệnh on-demand không có timeout (xem phát hiện bên dưới).

- **Phát hiện quan trọng: Đối chiếu hành vi Timeout giữa 2 chế độ & Lỗi logic mã nguồn:**
![alt text](<Screenshot 2026-10-02 145138.png>)
![alt text](<Screenshot 2026-10-02 162910.png>)
![alt text](<Screenshot 2026-10-02 163138.png>)
  - *Hiện tượng quan sát:* Khi chặn tự động theo Alert (IP `.99`), sau đúng 61 giây hệ thống tự động phát lệnh `delete` để mở khóa. Tuy nhiên khi chặn theo yêu cầu On-demand (IP `.88` và `.1`), sau hơn 2 phút IP vẫn bị giữ lại trong bảng chặn và không tự phục hồi.
  - *Phân tích nguyên nhân gốc rễ (Root Cause Analysis trong `opnsense-fw`):*
    ```python
    try:
        unique_key = "%s-%s" % (event['parameters']['alert']['rule']['id'], srcip)
        send_log('Sending check_keys for: %s' % unique_key)
        print(json.dumps({..., "command": "check_keys", "parameters": {"keys": [unique_key]}}))  # rút gọn
        sys.stdout.flush()
    except KeyError:
        pass  # không có rule.id → không gửi check_keys
    ```
    Bản tin phát chủ động từ `agent_control` không mang ngữ cảnh Alert nên **không có trường `rule.id`**. Đoạn code trên dính ngoại lệ `KeyError` và rơi vào `pass`, dẫn đến việc script không gửi `check_keys` về `wazuh-execd`. Vì thiếu đăng ký `check_keys`, daemon `wazuh-execd` **không khởi chạy bộ đếm thời gian 60 giây**, khiến lệnh chặn On-demand vô tình trở thành lệnh chặn vĩnh viễn (Permanent Block). Điều này khớp với mã nguồn `execd.c` (bản 4.14.7): `execd` gửi alert vào STDIN của script rồi đọc một dòng từ STDOUT; nếu không nhận được thông điệp khoá thì ghi nhận "Active response won't be added to timeout list" và không đăng ký bộ đếm.
  - *Ý nghĩa kiến trúc & Bài học thiết kế cho OTSD:*
    1. Chứng minh được sự khác biệt giữa hai chế độ tác chiến: *Phản ứng tự động có hoàn nguyên (Stateful)* và *chặn không có timeout (Permanent)*.
    2. Chỉ ra điểm cần vá mã nguồn (Patch) trong plugin OPNsense: cần tạo fallback key khi không có `rule.id` để hỗ trợ timeout linh hoạt cho các lệnh điều khiển từ xa của OTSD (đề xuất, chưa thử nghiệm).
    3. Thiết kế hệ thống trung tâm OTSD bắt buộc phải trang bị đồng thời cặp API: `Block IP` và `Unblock IP` chủ động.

#### 2. Hướng 2: Khảo sát kênh xác nhận kết quả về Manager (Closed-loop Feedback)
- **Khảo sát:** Kiểm tra `alerts.log` trên Manager sau khi OPNsense chặn thành công IP `192.168.56.88`.
- **Kết quả:** Manager chỉ ghi nhận log kiểm toán của lệnh `sudo agent_control`, **hoàn toàn chưa có Alert xác nhận việc OPNsense đã thực thi thành công**.
- **Giải pháp mở rộng thiết kế (đề xuất, chưa triển khai):**
  - Trên OPNsense: Dòng log `Active response executed (add/delete <IP>)` nhiều khả năng được `wazuh-logcollector` đọc từ `active-responses.log` và gửi về Manager **[cần kiểm chứng: xem `<localfile>` trên agent và `archives.log` trên Manager]**.
  - Trên Manager: Viết thêm một Custom Decoder và Custom Rule trong `/var/ossec/etc/rules/local_rules.xml` để dịch dòng log này thành một Alert chính thức (Level 3): *"OPNsense Firewall: Successfully blocked IP <IP>"*.
  - Nhờ đó, OTSD/Manager có được thông báo phản hồi đóng vòng (Closed-loop confirmation) để biết chắc chắn lệnh đã được thực thi trên thiết bị biên.

#### 3. Nguyên tắc an ninh cho phần mở rộng
- **Kiểm soát chặt danh mục lệnh (Allowlist):** Chỉ cho phép tập lệnh cố định trong `opnsense-fw`, tuyệt đối không dùng cú pháp `!script` (cho phép chỉ định script tùy ý từ Manager).
- **Dọn dẹp bề mặt tấn công:** Gỡ bỏ hoặc thu hồi quyền thực thi các binary C thừa trong `/var/ossec/active-response/bin/` (`pf`, `route-null`...).
- **Phân quyền tài khoản API:** Tài khoản API mà OTSD dùng trên Manager phải được cấu hình phân quyền nghiêm ngặt (RBAC) để chỉ có quyền gọi các active-response được phép.

---

## VII. TỔNG KẾT & ĐỊNH HƯỚNG PHÁT TRIỂN TUẦN TỚI

> **Mối liên hệ giữa Kết quả Thực nghiệm Tuần 2 và Bảng nhiệm vụ cập nhật của Thầy (Task 11):**  
> *"Xây dựng chức năng cấu hình, thiết lập kênh truyền bảo mật tới Wazuh & Phát triển mở rộng kênh điều khiển 2 chiều"*

Tiếp thu định hướng của Thầy về việc *“kênh 2 chiều hiện có (Active Response trên cổng 1514) tuy đã hoạt động nhưng còn mang tính bó buộc, cần dựa trên đường ống đó để mở rộng thêm”*, nhóm đã tổng hợp toàn bộ các phát hiện kỹ thuật (F1–F9, rà soát mã nguồn và kiểm chứng thực tế cắt/phục hồi mạng) thành bảng đối chiếu cụ thể giữa **Hiện trạng kênh cũ** và **Phương án mở rộng đề xuất** cho giai đoạn phát triển tiếp theo:

| TT | Nội dung nhiệm vụ (Task 11) | Hiện trạng & Sự bó buộc của Kênh cũ (Tuần 2) | Phương án Mở rộng & Giải pháp Đề xuất (Tuần tới) |
|:---:|---|---|---|
| **1** | **Trang cấu hình kết nối & Xác thực bảo mật** *(TLS 1.3, mTLS, Whitelist IP)* | • **Thiếu xác thực hai phía:** Template chưa đặt `<server_ca_path>` (F1) và Manager để `ssl_verify_host=no` (F7), tiềm ẩn rủi ro Manager giả mạo.<br>• **Giao diện hạn chế:** Web GUI (`WazuhAgent.xml`) hiện chỉ có IP/Port/Password, hoàn toàn thiếu chỗ cấu hình chứng chỉ CA, mTLS và danh sách Whitelist. | • **Mở rộng Web GUI OPNsense:** Bổ sung các trường nhập liệu trong Model `WazuhAgent.xml`: chọn CA Certificate, Client Certificate (mTLS), Whitelist IP.<br>• **Chuẩn hóa Template:** Cập nhật template `ossec.conf` tự động kết xuất khối `<enrollment>` có xác minh CA và cấu hình TLS 1.3 an toàn. |
| **2** | **Phạm vi lệnh điều khiển 2 chiều** *(Tập lệnh mở rộng)* | • **Rất bó buộc về chức năng:** Kênh 2 chiều hiện tại chỉ thực hiện được duy nhất một tác vụ là chặn/mở chặn một IP đơn lẻ vào bảng `__wazuh_agent_drop` của PF.<br>• Chưa hỗ trợ các tác vụ quản trị an ninh khác của OPNsense. | • **Mở rộng tập lệnh có cấu trúc (Allowlist):** Phát triển script trong `/var/ossec/active-response/bin/` nhận lệnh JSON mở rộng từ Central.<br>• Tích hợp gọi qua `configctl`/API nội bộ của OPNsense để thực thi đa dạng tác vụ (Block IP, Unblock IP, Reload firewall, Cập nhật rule Suricata) mà không can thiệp thô bạo vào kernel. |
| **3** | **Cơ chế Timeout lệnh On-demand** *(Tác chiến chủ động)* | • **Lỗi logic làm mất bộ đếm (F8):** Lệnh điều khiển chủ động từ xa (`agent_control`) không mang ngữ cảnh Alert nên thiếu `rule.id`, gây ngoại lệ `KeyError` trong `opnsense-fw` $\rightarrow$ bỏ qua `check_keys`, `wazuh-execd` không chạy timer, dẫn đến IP bị chặn vĩnh viễn không tự phục hồi. | • **Vá mã nguồn (Patch) `opnsense-fw`:** Bổ sung cơ chế fallback sinh khóa định danh dự phòng (dựa trên `srcip` + timestamp) khi thiếu `rule.id` $\rightarrow$ đảm bảo daemon `wazuh-execd` luôn kích hoạt timer đếm ngược 60s để tự động hoàn nguyên lưu lượng. |
| **4** | **Kênh phản hồi xác nhận đóng vòng** *(Closed-loop Feedback)* | • **Chưa có kênh xác nhận (F9):** Central/Manager phát lệnh điều khiển xuống nhưng không hề có Alert xác nhận OPNsense đã thực thi thành công hay thất bại (chỉ có log audit cục bộ của lệnh phát đi). | • **Khép vòng phản hồi:** Cấu hình `wazuh-logcollector` thu thập dòng `Active response executed (...)` từ `active-responses.log`.<br>• Viết Custom Decoder & Rule (Level 3) trên Manager để sinh Alert chính thức xác nhận trạng thái thực thi thành công về Dashboard. |
| **5** | **Hàng đợi đệm khi gián đoạn mạng** *(Buffer Queue)* | • **Cố định trong mã nguồn:** Khối `<client_buffer>` trong template `ossec.conf` đang bị gán cứng cố định: hàng đợi tối đa `5000` tin và tốc độ xả `500` events/s, người dùng không thể can thiệp từ Web GUI. | • **Tùy biến hóa cấu hình:** Đưa 2 tham số `queue_size` và `events_per_second` lên giao diện Web GUI của OPNsense, cho phép người quản trị linh hoạt cấu hình dung lượng bộ đệm phù hợp với quy mô và lưu lượng của từng phân vùng mạng OT. |
---

## PHỤ LỤC C — TÀI LIỆU THAM KHẢO

- [Wazuh Agent Enrollment](https://documentation.wazuh.com/current/user-manual/agent-enrollment/index.html)
- [Wazuh Active Response](https://documentation.wazuh.com/current/user-manual/capabilities/active-response/index.html)
- [OPNsense Wazuh Plugin Source](https://github.com/opnsense/plugins/tree/master/security/wazuh-agent)
- [Wazuh Security Advisories](https://github.com/wazuh/wazuh/security/advisories)
- [GHSA-ppc7-hj9v-vx39 / CVE-2026-54084 — NULL pointer dereference khi enrollment](https://github.com/wazuh/wazuh/security/advisories/GHSA-ppc7-hj9v-vx39)
- [GHSA-mvh4-g699-984j / CVE-2026-54085 — argument injection trong script Active Response](https://github.com/wazuh/wazuh/security/advisories/GHSA-mvh4-g699-984j)
- [GHSA-m4mf-qmhf-8vj6 / CVE-2026-54083 — path traversal trong ip-customblock](https://github.com/wazuh/wazuh/security/advisories/GHSA-m4mf-qmhf-8vj6)
- [NVD CVE Search — Wazuh](https://nvd.nist.gov/vuln/search?query=wazuh)
- [RFC 8446 — TLS 1.3](https://datatracker.ietf.org/doc/html/rfc8446)
- [MLKEM768 / Kyber PQC](https://pq-crystals.org/kyber/)
