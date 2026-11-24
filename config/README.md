# Cấu hình release

- `devices.json`: cấu hình mặc định của MCP (không chứa credential).
- `credentials.json`: **bạn tạo** từ `credentials.example.json`; không chia sẻ.
- `device.csv`: inventory MCP; copy từ hệ thống của bạn hoặc tạo từ
  `device.example.csv`. Cột bắt buộc: `name`, `ip`; cột tùy chọn:
  `netmiko_device_type`, `profile`, `manufacturer`, `function`, `pop`,
  `serviceZoneName`, `room`, `rack`, `description`.
- `devices.json` không tham chiếu `credentials_file`; MCP tự nạp
  `credentials.json` cùng thư mục nếu có. Có thể dùng
  `NETMIKO_WEB_MCP_CREDENTIALS` để chỉ định đường dẫn khác.

Không commit/zip các file `credentials.json`, `known_hosts`, `device.csv` thật
lên repository công khai.
