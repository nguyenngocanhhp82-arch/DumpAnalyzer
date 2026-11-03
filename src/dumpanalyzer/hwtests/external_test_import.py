"""
Plugin nhập kết quả kiểm tra phần cứng từ công cụ chuyên dụng ngoài (Phần 4.2c).
Hỗ trợ MemTest86, Memtest86+, OCCT, Prime95, CrystalDiskInfo v.v.
Kèm tính năng xuất phiếu hướng dẫn kiểm tra RAM bằng USB boot.
"""

import datetime
from typing import Optional, Dict, Any, Tuple

from dumpanalyzer.hwtests.base import HardwareTest, TestResult
from dumpanalyzer.core.logging_setup import get_logger

logger = get_logger("hwtests.external")


class ExternalTestImport(HardwareTest):
    """
    Plugin tiếp nhận kết quả kiểm tra phần cứng từ các công cụ chuyên dụng chạy ngoài.
    Áp dụng quy tắc:
    - errors > 0 -> 'failed' (bằng chứng mạnh, khẳng định lỗi)
    - errors == 0 và passes >= min_passes (mặc định 4) -> 'passed' (bằng chứng phản bác)
    - còn lại (ví dụ 0 lỗi nhưng chỉ chạy 1-2 passes) -> 'inconclusive'
    """

    id: str = "external_test_import"
    name: str = "Nhập kết quả công cụ ngoài (MemTest86, OCCT, Prime95...)"
    description: str = "Nhập và quy đổi kết quả từ các công cụ kiểm tra phần cứng chuyên dụng chạy ngoài môi trường Windows."
    group: str = "ram"
    requires_reboot: bool = False
    requires_admin: bool = False
    estimated_minutes: int = 0

    def check_prerequisites(self) -> Tuple[bool, str]:
        """Luôn sẵn sàng tiếp nhận dữ liệu nhập tay hoặc file log."""
        return True, "Sẵn sàng nhập dữ liệu kết quả kiểm tra ngoài."

    def start(self, machine_id: Optional[int] = None) -> TestResult:
        """Khởi tạo trạng thái chờ nhập dữ liệu."""
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        return TestResult(
            status="pending",
            details="Đang chờ người dùng cung cấp kết quả từ công cụ kiểm tra ngoài.",
            started_at=now_iso,
            finished_at="",
            raw="",
        )

    def collect_result(
        self,
        machine_id: Optional[int] = None,
        run_id: Optional[int] = None,
    ) -> TestResult:
        """Nếu không có dữ liệu nhập cụ thể, trả về trạng thái not_run."""
        return TestResult(
            status="not_run",
            details="Chưa có dữ liệu kết quả từ công cụ ngoài.",
        )

    def evaluate_external_result(
        self,
        tool_name: str,
        group: str,
        passes: int,
        errors: int,
        duration_minutes: int = 0,
        notes: str = "",
        report_path: str = "",
        test_rules: Optional[Dict[str, Any]] = None,
    ) -> TestResult:
        """
        Đánh giá và quy đổi số liệu kiểm tra ngoài thành TestResult chuẩn mực.
        """
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        tr = (test_rules or {}).get("test_rules", {})
        min_passes = tr.get("external_test_rules", {}).get("min_passes", 4)

        raw_info = (
            f"Tool: {tool_name} | Group: {group} | Passes: {passes} | Errors: {errors} | "
            f"Duration: {duration_minutes}m | Report: {report_path} | Notes: {notes}"
        )

        if errors > 0:
            status = "failed"
            details = (
                f"Công cụ {tool_name} phát hiện {errors} LỖI phần cứng ({group}) "
                f"sau {passes} lượt chạy ({duration_minutes} phút). Ghi chú: {notes or 'Không'}"
            )
        elif errors == 0 and passes >= min_passes:
            status = "passed"
            details = (
                f"Công cụ {tool_name} hoàn thành {passes} lượt chạy (>= ngưỡng chuẩn {min_passes} passes) "
                f"và KHÔNG phát hiện lỗi nào ({group}). Thời lượng: {duration_minutes} phút."
            )
        else:
            status = "inconclusive"
            details = (
                f"Kết quả {tool_name} CHƯA ĐỦ ĐỂ KẾT LUẬN (inconclusive): ghi nhận 0 lỗi nhưng chỉ chạy {passes} lượt "
                f"(khuyến nghị tối thiểu {min_passes} lượt để loại trừ lỗi chập chờn). "
                f"Thời lượng: {duration_minutes} phút."
            )

        return TestResult(
            status=status,
            details=details,
            started_at=now_iso,
            finished_at=now_iso,
            raw=raw_info,
        )


def generate_ram_test_guide() -> str:
    """
    Sinh tài liệu hướng dẫn kỹ thuật kiểm tra bộ nhớ RAM chuẩn mực bằng USB Boot (MemTest86).
    Dành cho kỹ thuật viên IT thực hiện kiểm tra ngoài hệ điều hành.
    """
    return (
        "================================================================================\n"
        "PHIẾU HƯỚNG DẪN KIỂM TRA BỘ NHỚ RAM CHUYÊN DỤNG BẰNG USB BOOT (MEMTEST86)\n"
        "Áp dụng cho: Kỹ thuật viên IT & Người quản trị hệ thống\n"
        "Hệ thống: DumpAnalyzer Hardware Diagnostic Framework\n"
        "================================================================================\n\n"
        "1. NGUYÊN TẮC QUAN TRỌNG:\n"
        "   - Hệ điều hành Windows đang chạy KHÔNG THỂ kiểm tra toàn diện 100% dung lượng RAM\n"
        "     do một phần lớn bộ nhớ bị khóa bởi Kernel, Driver và các tiến trình hệ thống.\n"
        "   - Các lỗi RAM do chập chờn điện áp, lỗi vi mạch hoặc quá nhiệt thường chỉ lộ diện\n"
        "     khi chạy nhiều chu kỳ đọc/ghi dữ liệu lặp lại liên tục.\n\n"
        "2. CÁC BƯỚC THỰC HIỆN KIỂM TRA BẰNG MEMTEST86:\n"
        "   Bước 1: Chuẩn bị USB Test\n"
        "     - Sử dụng một USB trống (dung lượng từ 512MB trở lên).\n"
        "     - Truy cập trang chủ chính thức: https://www.memtest86.com\n"
        "     - Tải về gói 'MemTest86 Free Edition' (hỗ trợ UEFI boot).\n"
        "     - Giải nén và chạy công cụ 'imageUSB.exe' đi kèm để ghi bộ nạp vào USB.\n\n"
        "   Bước 2: Khởi động máy từ USB\n"
        "     - Cắm USB vào máy tính cần kiểm tra phần cứng.\n"
        "     - Bật nguồn máy tính và nhấn phím gọi Boot Menu (F12, F11, F8 hoặc F2/Del tùy bo mạch).\n"
        "     - Chọn khởi động ở chế độ UEFI từ ổ đĩa USB MemTest86.\n\n"
        "   Bước 3: Tiến hành chạy bài kiểm tra (Test Run)\n"
        "     - MemTest86 sẽ tự động chạy quy trình kiểm tra gồm 13 bài test thuật toán.\n"
        "     - KHUYẾN NGHỊ BẮT BUỘC: Hãy để công cụ chạy TỐI THIỂU 4 PASSES (4 chu kỳ hoàn chỉnh).\n"
        "       Thời gian kiểm tra thông thường từ 1 đến 4 giờ tùy dung lượng và tốc độ RAM.\n"
        "     - Nếu có bất kỳ lỗi nào xuất hiện (Error > 0 màu đỏ): Bộ nhớ RAM hoặc khe cắm RAM\n"
        "       chắc chắn có sự cố phần cứng. Bạn có thể bấm phím 'c' hoặc ESC để dừng sớm.\n\n"
        "   Bước 4: Ghi nhận kết quả\n"
        "     - Chụp ảnh màn hình kết quả hoặc lưu file log HTML vào USB (nếu có tùy chọn).\n"
        "     - Ghi nhận lại:\n"
        "       + Số lượt hoàn thành (Passes completed)\n"
        "       + Số lượng lỗi ghi nhận (Errors count)\n"
        "       + Tổng thời lượng chạy kiểm tra (Elapsed time)\n\n"
        "3. NHẬP KẾT QUẢ VÀO PHẦN MỀM DUMPANALYZER:\n"
        "   - Khởi động lại vào Windows và mở phần mềm DumpAnalyzer.\n"
        "   - Chuyển sang Tab 'Kiểm tra phần cứng'.\n"
        "   - Tại mục 'Nhập kết quả công cụ ngoài', điền:\n"
        "     * Công cụ: MemTest86 (hoặc OCCT / Prime95)\n"
        "     * Nhóm kiểm tra: RAM\n"
        "     * Số lượt pass: (ví dụ: 4)\n"
        "     * Số lỗi: (ví dụ: 0 hoặc số lỗi thật)\n"
        "     * Đường dẫn file báo cáo / ảnh chụp kết quả.\n"
        "   - Nhấn 'Lưu kết quả kiểm tra'. Hệ thống sẽ tự động cập nhật độ tin cậy và gợi ý xử lý tiếp theo.\n\n"
        "================================================================================\n"
    )
