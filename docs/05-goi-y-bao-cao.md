# 5. Gợi ý cấu trúc báo cáo, kế hoạch và chuẩn bị bảo vệ

## 5.1. Tên đề tài gợi ý

- *Xây dựng hệ thống tự động đánh giá mối đe doạ từ cảnh báo toàn vẹn tệp tin dựa trên Wazuh, VirusTotal và mô hình ngôn ngữ lớn*
- *Ứng dụng SOAR mã nguồn mở và AI phân tầng trong phát hiện, phân loại và ứng phó mã độc trên máy trạm*

## 5.2. Cấu trúc báo cáo

1. **Mở đầu** — bối cảnh (thiếu nhân lực SOC, "bão cảnh báo"), mục tiêu, phạm vi (FIM trên Linux/Windows, mã độc
   đã biết + dấu hiệu persistence), đóng góp.
2. **Cơ sở lý thuyết**
   - SIEM/XDR, File Integrity Monitoring (realtime vs whodata vs định kỳ)
   - SOAR và playbook; mô hình SOC L1/L2/L3
   - Threat Intelligence, phát hiện dựa trên hash và giới hạn của nó
   - MITRE ATT&CK; NIST SP 800-61
   - Mô hình ngôn ngữ: mô hình nhỏ chạy cục bộ vs mô hình lớn qua API; structured output; prompt injection
3. **Phân tích và thiết kế** — yêu cầu, kiến trúc (docs/01), thiết kế chấm điểm, quy tắc leo thang, thiết kế an
   toàn (bảng mối đe doạ → biện pháp), thiết kế dữ liệu.
4. **Triển khai** — môi trường lab, cấu hình Wazuh, engine, workflow n8n, prompt (đưa nguyên văn system prompt
   vào phụ lục), active response.
5. **Thử nghiệm và đánh giá** — kịch bản (docs/03), kết quả so sánh B0/B1/P1–P3, chi phí, phân tích lỗi
   (trường hợp sai và vì sao).
6. **Kết luận và hướng phát triển** — xem 5.4.
- **Phụ lục**: cấu hình, rule, prompt, ảnh chụp email/execution n8n, bảng số liệu thô.

## 5.3. Kế hoạch 12 tuần (tham khảo)

| Tuần | Công việc | Sản phẩm |
|---|---|---|
| 1–2 | Đọc tài liệu Wazuh FIM, n8n, VirusTotal API, ATT&CK; dựng lab | Lab chạy, agent active |
| 3–4 | Rule tùy biến, cấu hình FIM, integration → n8n | Alert về tới n8n |
| 5–6 | Engine: VirusTotal, chấm điểm, ATT&CK; unit test | Triage hoạt động |
| 7 | Mô hình nhỏ (Ollama), so sánh 2–3 mô hình | Bảng so sánh mô hình nhỏ |
| 8 | Claude, email Gmail | Email báo cáo hoàn chỉnh |
| 9 | Human-in-the-loop + active response | Demo cách ly |
| 10–11 | Chạy thí nghiệm, thu số liệu | Bảng/biểu đồ kết quả |
| 12 | Viết báo cáo, slide, video demo dự phòng | Báo cáo + slide |

## 5.4. Hướng phát triển (để ghi vào phần kết luận)

- Thêm nguồn dữ liệu ngoài FIM: Sysmon (Windows), auditd `execve` (Linux) để bắt tấn công fileless.
- Hàng đợi tra cứu lại khi VirusTotal hết hạn mức; thêm nguồn TI (MalwareBazaar, CIRCL hashlookup cho file sạch).
- Quét YARA tại chỗ cho file chưa có trên VirusTotal (Wazuh có hướng dẫn tích hợp YARA qua active response).
- Tinh chỉnh (fine-tune) mô hình nhỏ trên tập alert đã được analyst gán nhãn từ nút phản hồi.
- Tích hợp TheHive/Jira để quản lý ticket, dashboard thống kê sự cố.
- Cho Claude gọi công cụ (tool use) để tự truy vấn thêm log Wazuh trước khi kết luận.

## 5.5. Câu hỏi hội đồng có thể hỏi

| Câu hỏi | Ý trả lời |
|---|---|
| Tại sao không để AI quyết định luôn? | Dữ liệu đầu vào do kẻ tấn công kiểm soát (tên file) → prompt injection; kịch bản S7 chứng minh mô hình nhỏ bị lừa. Vì vậy luật quyết định mức tối thiểu, AI chỉ nâng; hành động ngăn chặn cần người duyệt. |
| Đã có integration VirusTotal của Wazuh, đóng góp của em là gì? | Baseline B1 chỉ trả lời "VT có phát hiện không". Hệ thống bổ sung ngữ cảnh (bắt được mẫu chưa được báo cáo — S3/S4/S5/S8), ATT&CK, phân loại, báo cáo có hướng dẫn xử lý, phản hồi dương tính giả, và quy trình duyệt cách ly. Có số liệu so sánh ở chương 5. |
| Gửi dữ liệu ra Claude/VirusTotal có vi phạm quyền riêng tư không? | VT chỉ nhận hash, không upload file. Claude chỉ nhận sự cố đã leo thang, đã ẩn tên người dùng/IP/tên máy; tầng L1 chạy cục bộ. Có thể tắt hẳn L2. |
| Mã độc đa hình thì sao? | Hash mới → `not_found`; điểm ngữ cảnh vẫn hoạt động (S3). Thừa nhận giới hạn, đề xuất YARA/sandbox/EDR. |
| Chi phí khi triển khai thật? | Bảng 4.7 + số liệu đo được: chi phí/sự cố × số sự cố leo thang/tháng. |
| Nếu kẻ tấn công tắt Wazuh agent? | Ngoài phạm vi FIM; Wazuh có rule cảnh báo agent ngắt kết nối; nêu trong hướng phát triển. |
| Link trong email bị lộ thì sao? | Token HMAC gắn sự cố + hành động + hạn dùng, dùng một lần, GET không thực thi; production nên thêm SSO. |

## 5.6. Mẹo demo

- Quay sẵn video demo đầy đủ (phòng khi mạng hội trường không ra Internet được).
- Dùng `scripts/replay_alerts.py --engine ... --analyze` để có bảng kết quả trên terminal trong 1 lệnh.
- Mở song song: Wazuh dashboard, n8n Executions, hộp thư Gmail, terminal agent (`tail -f active-responses.log`).
- Demo kịch bản S7 (prompt injection) — đây là điểm khác biệt dễ gây ấn tượng nhất.
