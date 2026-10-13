# 4. Ánh xạ ra thực tiễn

Phần này trả lời câu hỏi hội đồng hay hỏi: *"Hệ thống này dùng được ở đâu ngoài phòng lab, và nó tương ứng
với cái gì mà doanh nghiệp đang dùng?"*

## 4.1. Tương ứng với mô hình vận hành SOC

| Hoạt động của SOC thật | Ở Sentinel-FIM |
|---|---|
| Thu thập telemetry từ endpoint (EDR/XDR agent) | Wazuh agent, FIM realtime/whodata |
| Use case / detection rule | `wazuh/rules/sentinel_fim_rules.xml` — mỗi rule gắn ATT&CK |
| Làm giàu cảnh báo bằng Threat Intelligence | VirusTotal theo hash (+ sandbox ATT&CK) |
| Phân loại L1 (triage), lọc nhiễu | Luật chấm điểm + mô hình nhỏ cục bộ |
| Phân tích L2, viết báo cáo sự cố | Claude, đầu ra có cấu trúc (JSON schema) |
| Playbook SOAR | 2 workflow n8n |
| Phê duyệt hành động ngăn chặn | Email có nút xác nhận, token HMAC |
| Ngăn chặn trên endpoint | Wazuh Active Response `sentinel-quarantine` |
| Tuning / phản hồi dương tính giả | Nút *Đánh dấu dương tính giả* → allowlist hash |
| Hồ sơ sự cố, báo cáo định kỳ | Bảng `incidents` (SQLite), API `/v1/incidents` |

## 4.2. Theo vòng đời ứng phó sự cố NIST SP 800-61

| Giai đoạn (Rev. 2) | Thành phần | Nhóm chức năng NIST CSF 2.0 (Rev. 3 dùng khung này) |
|---|---|---|
| Chuẩn bị (Preparation) | Chọn thư mục giám sát, rule, cấu hình agent, playbook n8n | GV, PR |
| Phát hiện & phân tích (Detection & Analysis) | FIM → VirusTotal → chấm điểm → ATT&CK → AI nhỏ → Claude | DE.CM (giám sát liên tục), DE.AE (phân tích sự kiện bất thường), RS.AN (phân tích sự cố) |
| Ngăn chặn, loại bỏ, khôi phục | Cách ly file sau khi analyst duyệt; metadata để khôi phục | RS.MI (giảm thiểu sự cố) |
| Hoạt động sau sự cố | Lưu sự cố, allowlist từ phản hồi, số liệu MTTD/MTTR | RS.MA, RS.CO, ID.IM (cải tiến) |

## 4.3. Độ phủ MITRE ATT&CK

| Chiến thuật | Kỹ thuật được phát hiện/ánh xạ |
|---|---|
| Execution | T1204.002, T1059.001, T1059.005 |
| Persistence | T1547.001, T1053.003, T1543.002, T1098.004, T1136.001, T1505.003, T1546.004, T1574.006, T1554 |
| Privilege Escalation | T1548.003 (và các kỹ thuật persistence dùng chung chiến thuật) |
| Defense Evasion | T1036.007, T1218.005, T1218.011, T1197, T1070.004 (rule gốc 553) |
| Command and Control | T1105 |
| Impact | T1486; T1565.001, T1485 (rule FIM gốc 550/553) |

Có thể dùng [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) tô màu các kỹ thuật trên để đưa
vào báo cáo như "bản đồ độ phủ" — đây là cách các đội SOC thật trình bày năng lực phát hiện.

## 4.4. Tương ứng với yêu cầu tuân thủ

| Chuẩn / quy định | Yêu cầu liên quan | Sentinel-FIM đáp ứng một phần bằng |
|---|---|---|
| PCI DSS v4.0 | 11.5.2 — cơ chế phát hiện thay đổi (FIM) với file quan trọng, cảnh báo nhân sự | FIM + email cảnh báo |
| ISO/IEC 27001:2022 | A.8.7 Phòng chống mã độc; A.8.16 Hoạt động giám sát | VirusTotal + FIM + quy trình xử lý |
| Việt Nam: Nghị định 85/2016/NĐ-CP, TCVN 11930:2017 | Yêu cầu giám sát, phòng chống mã độc theo cấp độ an toàn hệ thống thông tin | Giám sát toàn vẹn, phát hiện mã độc đã biết |
| Việt Nam: quy định bảo vệ dữ liệu cá nhân (Nghị định 13/2023/NĐ-CP và Luật Bảo vệ dữ liệu cá nhân 2025) | Hạn chế chuyển dữ liệu cá nhân ra bên thứ ba | Chỉ gửi hash cho VirusTotal; ẩn tên người dùng/IP trước khi gửi Claude; mô hình nhỏ chạy cục bộ |

> Khi viết báo cáo, hãy trích dẫn số hiệu và điều khoản từ văn bản hiện hành (các văn bản trên có thể đã được
> sửa đổi/thay thế) — bảng này chỉ định hướng nơi cần tra cứu.

## 4.5. Kịch bản triển khai thực tế

| Đối tượng | Vấn đề | Cách dùng Sentinel-FIM |
|---|---|---|
| Doanh nghiệp vừa và nhỏ (không có SOC 24/7) | 1–2 người IT, không đọc nổi hàng nghìn alert | Chỉ nhận email khi có sự cố thật, kèm hướng dẫn xử lý bằng tiếng Việt |
| Đơn vị hosting / máy chủ web của trường, khoa | Web shell sau khi bị khai thác lỗ hổng upload | Rule web root + phát hiện file script mới chưa được báo cáo |
| Phòng máy, máy trạm văn phòng | Người dùng tải file `.pdf.exe` từ email | Downloads + hai phần mở rộng + VirusTotal |
| MSSP (dịch vụ an ninh được quản lý) | Nhiều khách hàng, ít analyst | Nhóm agent theo khách hàng, n8n gửi email theo nhóm, Claude giảm thời gian viết báo cáo |

## 4.6. Khoảng cách từ lab tới production

| Hạng mục | Lab (đồ án) | Production |
|---|---|---|
| Kết nối | HTTP trong mạng nội bộ | HTTPS/mTLS ở mọi chặng (Wazuh→n8n, n8n→engine), reverse proxy |
| Bí mật | `.env`, credential n8n | Secret manager (Vault, Docker/K8s secrets), xoay vòng khoá |
| Xác thực link hành động | Token HMAC trong email | SSO/MFA cho trang xác nhận, ghi audit trail người duyệt |
| Threat Intelligence | VirusTotal public API (phi thương mại, 4 req/phút) | VirusTotal Premium/Enterprise hoặc nguồn TI có giấy phép, hàng đợi tra cứu lại |
| AI | Claude API theo lượt dùng, Ollama trên CPU | Thoả thuận xử lý dữ liệu, chính sách lưu giữ dữ liệu, GPU cho mô hình cục bộ, đánh giá định kỳ |
| Tính sẵn sàng | 1 container mỗi dịch vụ | n8n queue mode, nhiều worker, cơ sở dữ liệu PostgreSQL thay SQLite |
| Quy trình | Email | Ticket (TheHive, Jira), on-call (PagerDuty, Zalo/Teams/Slack), SLA |
| Nhiễu do thay đổi có kế hoạch | Allowlist thủ công | Gắn với quy trình change management, cửa sổ bảo trì |

## 4.7. Ước tính chi phí vận hành (quy mô nhỏ)

| Thành phần | Chi phí |
|---|---|
| Wazuh, n8n (tự host), Ollama | 0đ bản quyền (Wazuh GPLv2; n8n Sustainable Use License cho mục đích nội bộ); chỉ tốn máy chủ |
| VirusTotal public API | 0đ, giới hạn 500 request/ngày, chỉ phi thương mại |
| Claude | Trả theo token. Với `claude-opus-5-5` ($4 / 1M token vào, $20 / 1M token ra), một báo cáo cỡ vài nghìn token vào và vài nghìn token ra (gồm cả suy luận) rơi vào khoảng vài cent USD. **Hãy đo thực tế** trong phần đánh giá và nhân với số sự cố leo thang mỗi tháng |

Nhờ phân tầng, nếu chỉ ~5% alert được leo thang thì 1.000 alert/tháng chỉ tạo ra ~50 lần gọi Claude.

## 4.8. So sánh với xu hướng công nghiệp

Các nền tảng thương mại đều đang đi theo hướng "AI hỗ trợ analyst": trợ lý AI tích hợp trong XDR/SIEM tóm tắt
sự cố, giải thích cảnh báo, gợi ý bước xử lý. Sentinel-FIM là một phiên bản thu nhỏ, mã nguồn mở của ý tưởng đó,
với hai điểm nhấn có thể đưa vào phần đóng góp của đồ án:

1. **Phân tầng mô hình** (luật → mô hình nhỏ cục bộ → mô hình lớn) để cân bằng chi phí, độ trễ và quyền riêng tư.
2. **An toàn của chính hệ thống AI**: chống prompt injection bằng thiết kế (AI chỉ nâng mức), chống HTML injection,
   human-in-the-loop có ký số cho mọi hành động ngăn chặn.
