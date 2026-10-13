# 3. Kịch bản thử nghiệm và phương pháp đánh giá

Một đồ án tốt cần **số liệu đo được**, không chỉ "demo chạy được". Phần này đề xuất bộ kịch bản,
chỉ số và cách so sánh với một baseline.

## 3.1. Bộ kịch bản (ánh xạ MITRE ATT&CK)

| # | Kịch bản | Cách tạo (an toàn) | Kỹ thuật | Kết quả mong đợi |
|---|---|---|---|---|
| S1 | Mã độc **đã được báo cáo** được tải về | File kiểm thử EICAR vào `~/Downloads` (`simulate_linux_lab.sh`) hoặc alert mẫu `01` | T1204.002, T1105 | VT định danh `virus.eicar/test`, mức ≥ high, Claude nhận ra đây là file kiểm thử |
| S2 | Ransomware đã biết được cài persistence | Alert mẫu `02` (hash WannaCry — chỉ dùng hash, không dùng mẫu thật) | T1547.001, T1059.001 | critical, leo thang, có nút cách ly |
| S3 | Web shell **chưa từng được báo cáo** | File PHP vô hại, nội dung ngẫu nhiên trong `/var/www/html/uploads` | T1505.003 | VT `not_found` nhưng vẫn high nhờ ngữ cảnh |
| S4 | Thêm khoá SSH lạ | Ghi khoá giả vào `/root/.ssh/authorized_keys` | T1098.004 | medium; AI nhỏ có thể leo thang |
| S5 | Cron persistence | `/etc/cron.d/sentinel-fim-lab` | T1053.003 | medium/high (rule 100143) |
| S6 | Giả dạng tài liệu | `hoa-don-thang-10.pdf.sh`, `*.pdf.exe` | T1036.007 | medium, có yếu tố "hai phần mở rộng" |
| S7 | Prompt injection qua tên file | Alert mẫu `06` | (tấn công vào chính hệ thống AI) | AI nhỏ bị lừa nói "benign" nhưng mức độ **không bị hạ** |
| S8 | Mã hoá hàng loạt | Script đổi tên/ghi đè 30 file rác trong thư mục giám sát trong < 60s | T1486 | rule 100161 (level 14) → high |
| N1–Nn | **Hoạt động bình thường** (đo dương tính giả) | Cài phần mềm (`apt install`, bộ cài .exe/.msi hợp lệ), tải tài liệu PDF/DOCX, `git clone`, cập nhật hệ điều hành | — | low, không gửi email |

Với Windows, có thể dùng [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) (các test
T1547.001, T1036.007, T1105) trên VM lab đã snapshot — chỉ chọn các test không phá huỷ.

## 3.2. Chỉ số

| Nhóm | Chỉ số | Cách đo |
|---|---|---|
| Hiệu quả phát hiện | Detection rate (Recall) = số kịch bản tấn công được cảnh báo đúng mức / tổng số kịch bản | Đếm trên S1–S8 |
| | False positive rate = số hoạt động bình thường bị gửi email / tổng số hoạt động bình thường | Đếm trên N1–Nn (nên ≥ 30 hoạt động) |
| | Precision, F1 | Từ hai số trên |
| Tốc độ | MTTD: thời điểm file xuất hiện → email tới hộp thư | `timestamp` alert Wazuh so với giờ nhận email (header `Date`) |
| | Thời gian từng tầng: VT, AI nhỏ, Claude | Execution trong n8n (thời gian từng node) |
| | MTTR (lab): email → file được cách ly | log `active-responses.log` |
| Chi phí | Số request VirusTotal / alert (tỉ lệ trúng cache) | Log engine, bảng `vt_cache` |
| | Số token và chi phí Claude / sự cố leo thang | Trang Usage của Claude Console, hoặc ghi `response.usage` |
| | Tỉ lệ alert được leo thang lên Claude | `escalate` trong `/v1/incidents` |
| Chất lượng AI | Độ chính xác của mô hình nhỏ (benign/suspicious/malicious) so với nhãn thật | Gán nhãn tay cho tập alert |
| | Chất lượng báo cáo Claude | Rubric 1–5: đúng sự thật, ATT&CK hợp lý, hành động khả thi, nhận diện đúng dương tính giả, không bịa IOC |
| Độ bền | Hành vi khi VT hết hạn mức, Ollama tắt, Claude lỗi | Tắt từng dịch vụ và chạy lại `replay_alerts.py` |

## 3.3. Baseline để so sánh

| Cấu hình | Mô tả |
|---|---|
| **B0** – Wazuh mặc định | Chỉ rule FIM gốc (550/554), không integration |
| **B1** – Wazuh + VirusTotal có sẵn | Bật khối `<integration><name>virustotal</name>` trong `ossec.conf.snippet.xml` (giải pháp Wazuh khuyến nghị) |
| **P1** – Sentinel-FIM chỉ L1 | `ANTHROPIC_API_KEY` để trống, `OLLAMA_URL` để trống: VT + luật + ATT&CK |
| **P2** – P1 + mô hình nhỏ | Bật Ollama |
| **P3** – Đầy đủ | Bật Claude |

Câu hỏi nghiên cứu gợi ý:
1. Ngữ cảnh (vị trí, tiến trình, rule) giúp phát hiện được bao nhiêu kịch bản **chưa được báo cáo** mà B1 bỏ sót (S3, S4, S5, S8)?
2. Mô hình nhỏ cục bộ có giảm được số alert phải gửi lên Claude mà không bỏ sót không? (so sánh P2 và P3)
3. Báo cáo của Claude giúp analyst ra quyết định nhanh hơn bao nhiêu so với alert thô của B0/B1? (có thể nhờ
   2–3 bạn cùng lớp đóng vai analyst, bấm giờ)
4. So sánh các mô hình (đặt `CLAUDE_MODEL`, `OLLAMA_MODEL`): chất lượng báo cáo/chi phí/độ trễ.

## 3.4. Quy trình chạy thí nghiệm

1. Snapshot các VM agent trước mỗi lượt.
2. Đặt `DEDUP_WINDOW_SECONDS=0` cho engine để mỗi lượt được tính riêng.
3. Với mỗi cấu hình B0…P3: chạy toàn bộ kịch bản, ghi kết quả vào bảng dưới, khôi phục snapshot.
4. Lặp ít nhất 3 lần, báo cáo trung bình và độ lệch chuẩn cho các chỉ số thời gian.
5. Xuất dữ liệu: `GET /v1/incidents?limit=500` (JSON) để vẽ biểu đồ trong báo cáo.

Mẫu bảng kết quả:

| Kịch bản | B0 | B1 | P1 | P2 | P3 | MTTD (s) | Ghi chú |
|---|---|---|---|---|---|---|---|
| S1 EICAR | | | | | | | |
| S3 web shell mới | | | | | | | |
| … | | | | | | | |

## 3.5. Giới hạn cần nêu trung thực trong báo cáo

- **Phụ thuộc hash:** mã độc đa hình/được đóng gói lại có hash mới → VirusTotal `not_found`. Hệ thống bù bằng
  ngữ cảnh nhưng không thay được phân tích hành vi (EDR, sandbox).
- **Hạn mức VirusTotal free (4 request/phút):** khi nhiều file xuất hiện cùng lúc (cài phần mềm, ransomware),
  phần lớn alert sẽ ở trạng thái `rate_limited`. Đây là giới hạn thực tế; hướng mở rộng: hàng đợi tra cứu lại sau,
  hoặc dùng nguồn TI khác (MalwareBazaar, CIRCL hashlookup cho file sạch đã biết).
- **FIM chỉ thấy file:** tấn công fileless (chạy trong bộ nhớ, PowerShell không ghi file) cần nguồn log khác
  (Sysmon, auditd execve) — có thể mở rộng vì Wazuh đã thu thập được.
- **AI có thể sai:** mô hình nhỏ dễ bị prompt injection (S7 chứng minh), Claude có thể suy luận quá mức; vì vậy
  AI chỉ được nâng mức và con người duyệt hành động.
- **Lab ≠ production:** số lượng agent nhỏ, dữ liệu bình thường ít đa dạng hơn môi trường doanh nghiệp.
