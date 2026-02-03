# CLI IDS: Phát hiện bất thường mạng (ML + Sigma)

Công cụ CLI bằng Python để phát hiện bất thường trong mạng bằng hai cách:
- Mô hình học máy LSTM `.h5` (Keras/TensorFlow)
- Luật Sigma (YAML) áp cho log JSONL

Bạn có thể chạy riêng lẻ hoặc kết hợp cả hai. Công cụ không phụ thuộc vào SIEM cụ thể; nó đọc file JSON Lines (một event JSON mỗi dòng) hoặc CSV cho phần ML.

## Tính năng
- Nạp model LSTM `.h5` và chạy dự đoán theo cửa sổ trượt (sequence length cấu hình).
- Chuẩn hóa đặc trưng tùy chọn (z-score hoặc min-max) từ file cấu hình.
- Trình khớp Sigma tối giản: hỗ trợ so khớp bằng `==`, wildcard `*`, và các toán tử `|contains`, `|startswith`, `|endswith`.
- Điều kiện Sigma hỗ trợ: `selection` cơ bản và `1 of selection*`/`all of selection*`.
- Xuất cảnh báo dạng JSONL để tích hợp dễ dàng.

## Cài đặt
Tạo môi trường Python (khuyến nghị Python 3.10+). Cài dependencies:

```powershell
pip install -r requirements.txt
# Tùy chọn cho ML nếu bạn chạy phần LSTM:
# pip install tensorflow-cpu
```

Lưu ý: TensorFlow khá nặng; nếu bạn chỉ chạy Sigma, không cần cài.

### Yêu cầu hệ thống khi capture
- Linux: cần quyền root hoặc capabilities để sniff gói tin.
  - Chạy bằng sudo: `sudo -E python3 -m cli_ids ...`
  - Hoặc cấp quyền cho Python (không bắt buộc):
    ```bash
    sudo setcap 'cap_net_raw,cap_net_admin+eip' $(readlink -f $(which python3))
    ```
- Windows: cần Npcap và PowerShell chạy Run as Administrator.

## Cấu trúc
- `cli_ids/`: mã nguồn chính
- `rules/`: ví dụ luật Sigma
- `config/`: ví dụ cấu hình đặc trưng cho ML
- `data/`: dữ liệu mẫu

## Sử dụng nhanh

- Quét Sigma trên file JSONL:
```powershell
python -m cli_ids sigma --rules .\rules --input .\data\sample_events.jsonl --output .\alerts_sigma.jsonl
```

- Chạy ML trên CSV (có sẵn các cột đặc trưng):
```powershell
python -m cli_ids ml --model-path .\model\lstm.h5 --features-config .\config\features.example.yaml --input .\data\sample_features.csv --input-format csv --output .\alerts_ml.jsonl
```
### Dùng artifacts model (feature.pkl, scaler.pkl, model.h5)
- Nếu thư mục model chứa `model.h5`, `feature.pkl` (danh sách tên đặc trưng), `scaler.pkl` (đối tượng sklearn có `transform`), bạn có thể chỉ cần cung cấp `--model-dir`:
```powershell
python -m cli_ids ml --model-dir .\model --input .\data\captured_events.jsonl --input-format jsonl --output .\alerts_ml.jsonl
```
 - Hoặc chỉ rõ từng file:
```powershell
python -m cli_ids ml --model-path .\model\model.h5 --feature-pkl .\model\feature.pkl --scaler-pkl .\model\scaler.pkl --input .\data\captured_events.jsonl --input-format jsonl --output .\alerts_ml.jsonl
```
 - Lệnh `combined` và `realtime` cũng hỗ trợ `--model-dir`, `--feature-pkl`, `--scaler-pkl` tương tự (YAML chỉ dùng như fallback để lấy `sequence_length`/`threshold` nếu thiếu).
Lưu ý: bạn PHẢI cung cấp danh sách đặc trưng qua `feature.pkl` hoặc `features_config.feature_names`. Nếu không có danh sách feature, phần ML sẽ lỗi do đầu vào rỗng.

- Kết hợp cả hai trên JSONL (ML dùng các trường số trong sự kiện):
### Thu thập dữ liệu bằng Scapy rồi detect
Trên Linux nên chạy với sudo; trên Windows cần Npcap và quyền admin.

1) Thu thập lưu lượng và trích xuất feature `bytes_in/bytes_out` theo session mỗi 1 giây:
Linux (ví dụ iface `eth0`):
```bash
sudo -E python3 -m cli_ids capture --iface eth0 --duration 30 --bpf "tcp or udp" --bin-seconds 1 --output ./data/captured_events.jsonl
```
Windows:
```powershell
python -m cli_ids capture --iface "<Tên_interface>" --duration 30 --bpf "tcp or udp" --bin-seconds 1 --output .\data\captured_events.jsonl
```

2) Dùng model LSTM `.h5` để detect từ file JSONL vừa thu thập:
Linux:
```bash
python3 -m cli_ids ml --model-path ./model/lstm.h5 --features-config ./config/features.example.yaml --input ./data/captured_events.jsonl --input-format jsonl --output ./alerts_ml.jsonl
```
Windows:
```powershell
python -m cli_ids ml --model-path .\model\lstm.h5 --features-config .\config\features.example.yaml --input .\data\captured_events.jsonl --input-format jsonl --output .\alerts_ml.jsonl
```

### Realtime capture + detect (Sigma trước, rồi ML)
Linux:
```bash
sudo -E python3 -m cli_ids realtime --rules ./rules --model-path ./model/lstm.h5 --features-config ./config/features.example.yaml --iface eth0 --bpf "tcp or udp" --bin-seconds 1 --duration 60 --alerts-output ./alerts_realtime.jsonl
```
Windows:
```powershell
python -m cli_ids realtime --rules .\rules --model-path .\model\lstm.h5 --features-config .\config\features.example.yaml --iface "<Tên_interface>" --bpf "tcp or udp" --bin-seconds 1 --duration 60 --alerts-output .\alerts_realtime.jsonl
```

Quy trình:
- Mỗi 1 giây tổng hợp bytes_in/bytes_out theo phiên (5-tuple).
- Áp Sigma lên event; nếu match thì ghi alert Sigma ngay.
- Nếu không match, đẩy vào buffer theo phiên và đánh giá ML LSTM; nếu vượt ngưỡng thì ghi alert ML.

## Chạy dạng service (tương tự Suricata)
- Sử dụng file cấu hình YAML: `config/server.example.yaml`
- Chạy dịch vụ nền từ config:
  - Linux:
    ```bash
    sudo -E python3 -m cli_ids serve --config ./config/server.example.yaml
    ```
  - Windows (PowerShell Admin):
    ```powershell
    python -m cli_ids serve --config .\config\server.example.yaml
    ```
- Triển khai hệ thống:
  - Linux systemd (ví dụ `cli-ids.service`):
    ```ini
    [Unit]
    Description=CLI IDS Service (Sigma + LSTM)
    After=network.target

    [Service]
    Type=simple
    ExecStart=/usr/bin/python3 -m cli_ids serve --config /opt/cli-ids/config/server.yaml
    WorkingDirectory=/opt/cli-ids
    Restart=on-failure
    AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN

    [Install]
    WantedBy=multi-user.target
    ```
    Sau đó:
    ```bash
    sudo systemctl daemon-reload
    sudo systemctl enable cli-ids
    sudo systemctl start cli-ids
    sudo systemctl status cli-ids
    ```
  - Windows: có thể dùng NSSM để wrap lệnh `python -m cli_ids serve ...` thành Windows Service.

```powershell
python -m cli_ids combined --model-path .\model\lstm.h5 --features-config .\config\features.example.yaml --rules .\rules --input .\data\sample_events.jsonl --output .\alerts_combined.jsonl --group-field session_id --time-field timestamp
```

## Cấu hình đặc trưng ML
`config/features.example.yaml`
```yaml
feature_names:
  - bytes_in
  - bytes_out
sequence_length: 10
threshold: 0.7
scaler:
  type: zscore  # zscore|minmax
  mean:
    bytes_in: 1000
    bytes_out: 1200
  std:
    bytes_in: 300
    bytes_out: 400
# Hoặc minmax:
# scaler:
#   type: minmax
#   min:
#     bytes_in: 0
#     bytes_out: 0
#   max:
#     bytes_in: 100000
#     bytes_out: 100000
```

## Định dạng input
- JSONL: mỗi dòng một JSON event, ví dụ:
```json
{"timestamp": "2025-11-27T10:00:00Z", "session_id": "A", "src_ip": "10.0.0.1", "dst_port": 443, "bytes_in": 1200, "bytes_out": 800, "message": "TLS handshake"}
```
- CSV (cho ML): có các cột trùng `feature_names`.

## Lưu ý về mô hình LSTM
- Công cụ giả định mô hình đầu ra xác suất bất thường hoặc nhị phân (1 chiều sigmoid). Bạn có thể đặt `--threshold` để điều chỉnh.
- Nếu mô hình là autoencoder, bạn cần tự điều chỉnh logic điểm bất thường (not hiện hỗ trợ sẵn). Có thể mở rộng trong `cli_ids/ml.py`.

## Giấy phép & trách nhiệm
- Đây là mã mẫu mang tính tham khảo, cần hiệu chỉnh cho môi trường thực tế.
- Luật Sigma được hỗ trợ ở tập con thông dụng; các tính năng nâng cao (aggregation/timeframe phức tạp) không nằm trong phạm vi bản tối giản này.

## Lệnh hỗ trợ
Xem trợ giúp:
```powershell
python -m cli_ids --help
python -m cli_ids sigma --help
python -m cli_ids ml --help
python -m cli_ids combined --help
python -m cli_ids serve --help
```

## Ghi log: hành động, kết quả, lỗi
- Mặc định ghi ra 3 file: `./logs/actions.log`, `./logs/results.log`, `./logs/errors.log`.
- Có thể đổi đường dẫn log bằng options toàn cục khi gọi lệnh:
```powershell
python -m cli_ids --action-log .\logs\act.log --result-log .\logs\res.log --error-log .\logs\err.log sigma --rules .\rules --input .\data\sample_events.jsonl
```
- `actions.log`: các bước, bắt đầu/kết thúc.
- `results.log`: từng alert (dạng JSONL) để dễ ingest.
- `errors.log`: lỗi và ngoại lệ.

### Log sự kiện capture (JSONL)
- Mỗi event sau khi capture/gộp bin sẽ được ghi thêm vào `./logs/captured_events.jsonl` (mặc định).
- Đổi đường dẫn bằng option toàn cục `--capture-event-log` hoặc trong YAML `logs.capture_events`.