"""
Khung plugin kiểm tra phần cứng (Hardware Testing Plugins Framework) cho DumpAnalyzer.
Cung cấp các công cụ kiểm tra RAM, Ổ đĩa an toàn, không phá hủy.
"""

from dumpanalyzer.hwtests.base import HardwareTest, TestResult, test_result_to_evidence
from dumpanalyzer.hwtests.storage_health import StorageHealthTest
from dumpanalyzer.hwtests.windows_memory_diagnostic import WindowsMemoryDiagnosticTest
from dumpanalyzer.hwtests.external_test_import import ExternalTestImport, generate_ram_test_guide

__all__ = [
    "HardwareTest",
    "TestResult",
    "test_result_to_evidence",
    "StorageHealthTest",
    "WindowsMemoryDiagnosticTest",
    "ExternalTestImport",
    "generate_ram_test_guide",
]
