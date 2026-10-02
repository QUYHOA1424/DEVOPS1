# devsecops_automation.py
import os
import sys
import subprocess
import json

# Định nghĩa các biến cấu hình hệ thống
TARGET_DIR = os.getenv("TARGET_DIR", ".")
REPORT_DIR = os.getenv("REPORT_DIR", "security_reports")

def check_dependencies():
    """Kiểm tra xem các công cụ quét bảo mật đã được cài đặt chưa."""
    tools = ["bandit", "trivy"]
    missing_tools = []
    for tool in tools:
        if subprocess.run(["which", tool], capture_output=True).returncode != 0:
            missing_tools.append(tool)
    
    if missing_tools:
        print(f"[-] Lỗi: Thiếu các công cụ sau trong hệ thống: {', '.join(missing_tools)}")
        print("[*] Hãy cài đặt chúng trước khi chạy script (e.g., pip install bandit)")
        sys.exit(1)

def run_sast():
    """Thực hiện quét SAST (Mã nguồn Python) bằng Bandit."""
    print("[+] 1. Bắt đầu quét SAST mã nguồn với Bandit...")
    os.makedirs(REPORT_DIR, exist_ok=True)
    report_path = os.path.join(REPORT_DIR, "sast_report.json")
    
    # Chạy bandit và xuất kết quả dạng JSON
    cmd = ["bandit", "-r", TARGET_DIR, "-f", "json", "-o", report_path]
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    # Kiểm tra tệp báo cáo
    if os.path.exists(report_path):
        with open(report_path, "r") as f:
            try:
                data = json.load(f)
                issues = data.get("results", [])
                print(f"[!] Quét SAST hoàn tất. Phát hiện {len(issues)} lỗ hổng.")
                return len(issues)
            except json.JSONDecodeError:
                print("[-] Không thể đọc tệp báo cáo JSON từ Bandit.")
    return 0

def run_dependency_scan():
    """Thực hiện quét lỗ hổng thư viện / Docker Image bằng Trivy."""
    print("[+] 2. Bắt đầu quét thành phần phụ thuộc (SCA) với Trivy...")
    report_path = os.path.join(REPORT_DIR, "sca_report.json")
    
    # Quét thư mục hiện tại để tìm lỗ hổng trong tệp requirements.txt hoặc Dockerfile
    cmd = ["trivy", "fs", "--format", "json", "--output", report_path, TARGET_DIR]
    subprocess.run(cmd, capture_output=True)
    
    if os.path.exists(report_path):
        print(f"[!] Quét SCA hoàn tất. Báo cáo đã được lưu tại {report_path}")
    else:
        print("[-] Không thể tạo báo cáo SCA từ Trivy.")

def enforce_security_gate(issue_count):
    """Cấu hình cổng kiểm soát (Security Gate) tự động dừng CI/CD nếu phát hiện lỗi nặng."""
    MAX_ALLOWED_ISSUES = 0
    print(f"[+] 3. Kiểm tra cổng bảo mật hệ thống (Giới hạn: {MAX_ALLOWED_ISSUES} lỗi)...")
    if issue_count > MAX_ALLOWED_ISSUES:
        print(f"[-] THẤT BẠI: Số lượng lỗi ({issue_count}) vượt quá giới hạn cấu hình!")
        print("[-] Hệ thống sẽ tự động chặn tiến trình CI/CD này.")
        sys.exit(1)
    print("[+] THÀNH CÔNG: Hệ thống an toàn để tiếp tục deploy.")

if __name__ == "__main__":
    print("=== PIPELINE TỰ ĐỘNG HÓA CẤU HÌNH BẢO MẬT DEVSECOPS ===")
    check_dependencies()
    sast_errors = run_sast()
    run_dependency_scan()
    enforce_security_gate(sast_errors)
