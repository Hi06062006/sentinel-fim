#!/usr/bin/env bash
# Sentinel-FIM: tái hiện các kỹ thuật tấn công phổ biến trên MÁY LAB Linux có Wazuh agent,
# bằng thao tác VÔ HẠI và hoàn tác được — để kiểm tra rule, VirusTotal, AI và email.
#
#   sudo ./simulate_linux_lab.sh run      # tạo các "dấu vết"
#   sudo ./simulate_linux_lab.sh cleanup  # gỡ toàn bộ
#
# CHỈ CHẠY TRÊN MÁY ẢO LAB. Không dùng mẫu mã độc thật: phát hiện "virus đã được báo cáo"
# được kiểm chứng bằng file kiểm thử EICAR (mọi antivirus coi như mã độc, nhưng vô hại).

set -euo pipefail

LAB_USER="${SUDO_USER:-$(id -un)}"
LAB_HOME="$(getent passwd "$LAB_USER" | cut -d: -f6)"
MARK="sentinel-fim-lab"
EICAR='X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'

step() { printf '\n[%s] %s\n' "$(date +%H:%M:%S)" "$*"; sleep "${DELAY:-20}"; }

run() {
  [[ $EUID -eq 0 ]] || { echo "Cần chạy với sudo"; exit 1; }

  step "T1204.002/T1105 — mã độc ĐÃ ĐƯỢC BÁO CÁO (EICAR) xuất hiện trong Downloads"
  install -d -o "$LAB_USER" "$LAB_HOME/Downloads"
  printf '%s' "$EICAR" > "$LAB_HOME/Downloads/eicar.com"
  chown "$LAB_USER" "$LAB_HOME/Downloads/eicar.com"

  step "T1036.007 — file thực thi giả dạng tài liệu (hai phần mở rộng)"
  printf '#!/bin/sh\necho %s\n' "$MARK" > "$LAB_HOME/Downloads/hoa-don-thang-10.pdf.sh"
  chown "$LAB_USER" "$LAB_HOME/Downloads/hoa-don-thang-10.pdf.sh"

  step "T1505.003 — web shell CHƯA TỪNG được báo cáo (nội dung vô hại, hash mới)"
  install -d /var/www/html/uploads
  printf '<?php /* %s %s */ echo "ok"; ?>\n' "$MARK" "$(date +%s%N)" > /var/www/html/uploads/thumb.php

  step "T1098.004 — thêm khoá SSH lạ vào authorized_keys của root"
  install -d -m 700 /root/.ssh
  echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeKeyForSentinelFimLabOnlyDoNotUse000000 $MARK" >> /root/.ssh/authorized_keys

  step "T1053.003 — tạo cron job duy trì truy cập (lệnh vô hại)"
  echo "*/30 * * * * root /bin/true # $MARK" > /etc/cron.d/$MARK

  step "T1105 — thả file thực thi không phần mở rộng vào /tmp (nội dung ngẫu nhiên => hash chưa có trên VirusTotal)"
  head -c 4096 /dev/urandom > /tmp/.$MARK-agent && chmod +x /tmp/.$MARK-agent

  echo -e "\nXong. Theo dõi alert trong Wazuh dashboard, execution trong n8n và hộp thư SOC."
}

cleanup() {
  [[ $EUID -eq 0 ]] || { echo "Cần chạy với sudo"; exit 1; }
  rm -f "$LAB_HOME/Downloads/eicar.com" "$LAB_HOME/Downloads/hoa-don-thang-10.pdf.sh" \
        /var/www/html/uploads/thumb.php /etc/cron.d/$MARK /tmp/.$MARK-agent
  [[ -f /root/.ssh/authorized_keys ]] && sed -i "/$MARK/d" /root/.ssh/authorized_keys
  echo "Đã gỡ các dấu vết của $MARK."
}

case "${1:-}" in
  run) run ;;
  cleanup) DELAY=0 cleanup ;;
  *) echo "Cách dùng: sudo $0 run|cleanup   (DELAY=<giây> giữa các bước, mặc định 20)"; exit 1 ;;
esac
