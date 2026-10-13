# 2. Hướng dẫn triển khai lab

## 2.1. Mô hình lab đề xuất

| Máy (VM) | Vai trò | Cấu hình tối thiểu | IP ví dụ |
|---|---|---|---|
| `wazuh` | Wazuh server all-in-one (manager + indexer + dashboard) | 4 vCPU, 8 GB RAM, 50 GB | 192.168.56.20 |
| `soar` | Docker: n8n + sentinel-engine + Ollama | 4 vCPU, 8 GB RAM (Ollama chạy CPU) | 192.168.56.10 |
| `ubuntu-lab-01` | Agent Linux (Ubuntu 22.04/24.04) + Apache/Nginx để thử web shell | 2 vCPU, 2 GB | 192.168.56.101 |
| `win10-lab-02` | Agent Windows 10/11 | 2 vCPU, 4 GB | 192.168.56.102 |

Dùng mạng **host-only/NAT riêng** cho lab. Máy `soar` cần ra Internet để gọi VirusTotal và Claude API.

## 2.2. Cài Wazuh

Làm theo tài liệu chính thức (Quickstart, bản 4.x): trên máy `wazuh`

```bash
curl -sO https://packages.wazuh.com/4.x/wazuh-install.sh && sudo bash ./wazuh-install.sh -a
```

Lưu lại mật khẩu `admin` và tài khoản API (`wazuh-wui`) mà script in ra. Cài agent cho 2 máy lab từ
dashboard (*Agents → Deploy new agent*) và kiểm tra cả hai ở trạng thái *active*.

### Cấu hình FIM, rule và integration (trên manager)

```bash
# Rule tùy biến (gắn MITRE ATT&CK)
sudo cp wazuh/rules/sentinel_fim_rules.xml /var/ossec/etc/rules/
sudo chown wazuh:wazuh /var/ossec/etc/rules/sentinel_fim_rules.xml

# Cấu hình FIM tập trung, manager tự đẩy xuống mọi agent trong nhóm default
sudo cp wazuh/manager/agent.conf /var/ossec/etc/shared/default/agent.conf
sudo /var/ossec/bin/verify-agent-conf

# Integration đẩy alert sang n8n
sudo cp wazuh/integrations/custom-n8n /var/ossec/integrations/custom-n8n
sudo chown root:wazuh /var/ossec/integrations/custom-n8n
sudo chmod 750 /var/ossec/integrations/custom-n8n
```

Thêm khối `<integration>` trong `wazuh/manager/ossec.conf.snippet.xml` vào `/var/ossec/etc/ossec.conf`:
- `hook_url` = `http://192.168.56.10:5678/webhook/sentinel-fim`
- `api_key` = một chuỗi ngẫu nhiên (`openssl rand -hex 24`) — dùng lại ở bước tạo credential n8n.

```bash
sudo systemctl restart wazuh-manager
sudo tail -f /var/ossec/logs/integrations.log   # xem alert được đẩy đi
```

### Trên agent Linux

```bash
# whodata (biết tiến trình nào ghi file) cần auditd
sudo apt install -y auditd && sudo systemctl enable --now auditd

# Script cách ly (chạy khi analyst duyệt)
sudo cp wazuh/active-response/sentinel-quarantine /var/ossec/active-response/bin/
sudo chown root:wazuh /var/ossec/active-response/bin/sentinel-quarantine
sudo chmod 750 /var/ossec/active-response/bin/sentinel-quarantine
sudo systemctl restart wazuh-agent
```

Nếu giám sát thư mục lớn với `realtime`, tăng giới hạn inotify: `sudo sysctl fs.inotify.max_user_watches=524288`.

### Trên agent Windows

FIM whodata tự cấu hình audit policy. Để dùng nút *Cách ly*, đóng gói script thành `.exe` (cần Python trên máy build):

```powershell
pip install pyinstaller
pyinstaller --onefile --name sentinel-quarantine wazuh\active-response\sentinel-quarantine
copy dist\sentinel-quarantine.exe "C:\Program Files (x86)\ossec-agent\active-response\bin\"
Restart-Service WazuhSvc
```

## 2.3. Dựng n8n + engine + Ollama (máy `soar`)

```bash
git clone <repo> sentinel-fim && cd sentinel-fim
cp .env.example .env
# Điền: SENTINEL_API_TOKEN, ACTION_SECRET (openssl rand -hex 32), VT_API_KEY, ANTHROPIC_API_KEY,
#       ALERT_EMAIL_TO, N8N_PUBLIC_URL, ACTION_BASE_URL, WAZUH_API_URL
docker compose up -d --build
docker compose --profile setup run --rm ollama-pull     # tải qwen2.5:3b (~2 GB)
curl -s http://127.0.0.1:8000/healthz                   # {"virustotal":true,"small_llm":true,"claude":true}
```

Kiểm tra engine trước khi nối n8n:

```bash
set -a; source .env; set +a
python3 scripts/replay_alerts.py --engine http://127.0.0.1:8000 --token "$SENTINEL_API_TOKEN" --analyze
```

## 2.4. Cấu hình n8n

Mở `http://192.168.56.10:5678`, tạo tài khoản owner, rồi:

1. **Import workflow**: *Workflows → Import from file* lần lượt
   `n8n/workflows/sentinel-fim-triage.json` và `n8n/workflows/sentinel-fim-analyst-action.json`
   (hoặc `docker compose exec n8n n8n import:workflow --separate --input=/workflows`).
2. **Tạo 3 credential** và chọn vào các node đang báo thiếu credential:

   | Credential | Loại | Giá trị | Dùng ở node |
   |---|---|---|---|
   | `Sentinel - Wazuh webhook token` | Header Auth | Name `X-Sentinel-Token`, Value = `api_key` trong ossec.conf | *Wazuh alert (webhook)* |
   | `Gmail account` | Gmail OAuth2 | Đăng nhập Google (cần OAuth client trong Google Cloud Console, bật Gmail API) | *Gửi email cảnh báo (Gmail)* |
   | `Wazuh API` | Basic Auth | user/mật khẩu API Wazuh (`wazuh-wui`) | *Wazuh API: lấy JWT* |

3. **Bật (Activate)** cả hai workflow. URL production của webhook là `/webhook/sentinel-fim` và `/webhook/sentinel-action`.

> Nếu không muốn cấu hình OAuth, có thể thay node Gmail bằng node *Send Email* (SMTP `smtp.gmail.com:465`
> với App Password của tài khoản Google bật 2FA).

## 2.5. Kiểm thử đầu-cuối

```bash
# Gửi alert mẫu qua n8n giống hệt Wazuh
python3 scripts/replay_alerts.py --n8n http://127.0.0.1:5678/webhook/sentinel-fim --token <api_key webhook>

# Hoặc tạo dấu vết thật trên agent Linux (vô hại, có cleanup)
sudo DELAY=30 ./scripts/simulate_linux_lab.sh run
sudo ./scripts/simulate_linux_lab.sh cleanup
```

Theo dõi: Wazuh dashboard (*Threat Hunting*, lọc `rule.groups:sentinel_fim`) → n8n *Executions* →
hộp thư `ALERT_EMAIL_TO` → bấm *Cách ly file* → *Xác nhận* → trên agent:
`sudo tail /var/ossec/logs/active-responses.log` và `ls /var/ossec/quarantine`.

## 2.6. Xử lý sự cố thường gặp

| Hiện tượng | Kiểm tra |
|---|---|
| n8n không nhận alert | `/var/ossec/logs/integrations.log`; tường lửa cổng 5678; workflow đã *Active* chưa; token header khớp chưa |
| Webhook trả 403 | Credential Header Auth sai tên header/giá trị |
| `virustotal.status = rate_limited` | Đang vượt 4 req/phút; giảm thư mục giám sát hoặc chờ, kết quả cache sẽ dùng lại |
| `small_llm = null` | `docker compose logs ollama`; đã pull mô hình chưa; tăng `OLLAMA_TIMEOUT` nếu CPU chậm |
| `claude_status = error: HTTP 401` | Sai `ANTHROPIC_API_KEY` |
| Node HTTP báo lỗi `$env` | Thiếu `N8N_BLOCK_ENV_ACCESS_IN_NODE=false` trong môi trường n8n |
| Cách ly báo "SHA256 không khớp" | File đã thay đổi sau alert — hành vi đúng; điều tra lại file hiện tại |
| Alert FIM không có tiến trình | Thư mục đang ở chế độ `realtime`, cần `whodata` (+ auditd trên Linux) |
