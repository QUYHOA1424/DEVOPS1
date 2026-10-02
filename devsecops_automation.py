import json
import os
import shutil
import subprocess
import sys
from pathlib import Path


TARGET_DIR = os.getenv("TARGET_DIR", ".")
REPORT_DIR = os.getenv("REPORT_DIR", "security_reports")


def check_dependencies() -> None:
    """Kiểm tra các công cụ quét bảo mật bắt buộc."""
    tools = ["bandit", "trivy"]
    missing_tools = [tool for tool in tools if shutil.which(tool) is None]

    if missing_tools:
        print(f"[-] Lỗi: Thiếu các công cụ sau trong hệ thống: {', '.join(missing_tools)}")
        print("[*] Hãy cài đặt chúng trước khi chạy script (ví dụ: pip install bandit)")
        sys.exit(1)


def run_sast() -> int:
    """Thực hiện quét SAST mã nguồn Python bằng Bandit và trả về số lỗi."""
    print("[+] 1. Bắt đầu quét SAST mã nguồn với Bandit...")
    os.makedirs(REPORT_DIR, exist_ok=True)
    report_path = Path(REPORT_DIR) / "sast_report.json"

    cmd = ["bandit", "-r", TARGET_DIR, "-f", "json", "-o", str(report_path)]
    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode != 0 and result.returncode != 1:
        print("[-] Bandit chạy thất bại.")
        if result.stderr:
            print(result.stderr.strip())
        sys.exit(1)

    if not report_path.exists():
        print("[-] Không thể tạo báo cáo JSON từ Bandit.")
        return 0

    try:
        with report_path.open("r", encoding="utf-8") as file:
            data = json.load(file)
    except json.JSONDecodeError:
        print("[-] Không thể đọc tệp báo cáo JSON từ Bandit.")
        return 0

    issues = data.get("results", [])
    print(f"[!] Quét SAST hoàn tất. Phát hiện {len(issues)} lỗ hổng.")
    return len(issues)


def run_dependency_scan() -> None:
    """Thực hiện quét SCA (dependency/image) bằng Trivy."""
    print("[+] 2. Bắt đầu quét thành phần phụ thuộc (SCA) với Trivy...")
    os.makedirs(REPORT_DIR, exist_ok=True)
    report_path = Path(REPORT_DIR) / "sca_report.json"

    cmd = ["trivy", "fs", "--format", "json", "--output", str(report_path), TARGET_DIR]
    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode not in (0, 1):
        print("[-] Trivy chạy thất bại.")
        if result.stderr:
            print(result.stderr.strip())
        sys.exit(1)

    if report_path.exists():
        print(f"[!] Quét SCA hoàn tất. Báo cáo đã được lưu tại {report_path}")
    else:
        print("[-] Không thể tạo báo cáo SCA từ Trivy.")


def enforce_security_gate(issue_count: int) -> None:
    """Dừng pipeline nếu số lỗi vượt quá ngưỡng cho phép."""
    max_allowed_issues = 0
    print(f"[+] 3. Kiểm tra cổng bảo mật hệ thống (Giới hạn: {max_allowed_issues} lỗi)...")
    if issue_count > max_allowed_issues:
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
