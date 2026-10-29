<#
.SYNOPSIS
    Windows Event Log Analyzer - ứng dụng giao diện phân tích Dump (BSOD), Reset, Restart bất thường.

.DESCRIPTION
    - Chọn máy tính + khoảng thời gian, quét Event Log (System) và phân tích.
    - Gom các sự kiện thành "sự cố" (BSOD / mất nguồn / treo cứng / tắt máy không đúng cách).
    - Tra mã Bug Check theo bảng ~380 mã của Microsoft, phân nhóm nguyên nhân.
    - Phỏng đoán thiết bị nghi ngờ (RAM, ổ đĩa, GPU, CPU/mainboard, nguồn, driver...)
      kèm mức tin cậy và bằng chứng cụ thể.
    - Xuất báo cáo CSV / HTML.

    Chạy bằng file Chay-EventLogAnalyzer.bat (tự xin quyền Admin).
    Tham số -NoGui chỉ dùng để kiểm thử phần xử lý (không mở cửa sổ).
#>
param([switch]$NoGui)

$ErrorActionPreference = 'Continue'
$script:AppName = 'Windows Event Log Analyzer'
$script:AppVer  = '1.0'
$script:RefLink = 'https://learn.microsoft.com/windows-hardware/drivers/debugger/bug-check-code-reference2'
$script:LocalName = if ($env:COMPUTERNAME) { $env:COMPUTERNAME } else { [System.Net.Dns]::GetHostName() }

# ============================================================
#  HẰNG SỐ
# ============================================================
$script:LV = @{ High = 'Cao'; Mid = 'Trung bình'; Low = 'Thấp'; Info = 'Thông tin' }

$script:DEV = @{
    Power   = 'Nguồn điện / treo cứng'
    RAM     = 'RAM (bộ nhớ)'
    Disk    = 'Ổ đĩa (SSD/HDD/NVMe)'
    GPU     = 'Card màn hình (GPU / driver)'
    CPU     = 'CPU / Mainboard / Nhiệt độ'
    Driver  = 'Driver phần mềm'
    Periph  = 'Card mạng / USB / Bluetooth'
    Bios    = 'BIOS / Firmware'
    Windows = 'Hệ điều hành Windows'
    Unknown = 'Phần cứng (chưa xác định)'
    None    = '(không phải lỗi thiết bị)'
}

# Khuyến nghị kiểm tra theo từng thiết bị
$script:REC = @{}
$script:REC[$script:DEV.Power]   = 'Kiểm tra ổ cắm/UPS và nguồn máy (PSU); theo dõi nhiệt độ CPU/GPU khi tải nặng (máy có thể tự tắt khi quá nhiệt); nếu máy treo cứng phải giữ nút nguồn thì kiểm tra thêm driver, RAM và ổ đĩa.'
$script:REC[$script:DEV.RAM]     = 'Chạy Windows Memory Diagnostic (mdsched.exe) hoặc MemTest86 vài vòng; thử tháo từng thanh RAM, vệ sinh chân RAM và khe cắm.'
$script:REC[$script:DEV.Disk]    = 'Kiểm tra SMART bằng CrystalDiskInfo; sao lưu dữ liệu ngay nếu có cảnh báo; chạy chkdsk /scan; kiểm tra cáp SATA/khe M.2; cập nhật firmware SSD.'
$script:REC[$script:DEV.GPU]     = 'Cài sạch driver card màn hình (dùng DDU), kiểm tra nhiệt độ và quạt GPU, tắt ép xung; thử card khác để loại trừ.'
$script:REC[$script:DEV.CPU]     = 'Kiểm tra nhiệt độ bằng HWMonitor/Core Temp, vệ sinh quạt và tra lại keo tản nhiệt, tắt ép xung, cập nhật BIOS; lỗi WHEA nghiêm trọng thường là lỗi phần cứng CPU/RAM/PCIe.'
$script:REC[$script:DEV.Driver]  = 'Mở file minidump bằng BlueScreenView (NirSoft) hoặc WinDbg để biết driver gây lỗi; cập nhật hoặc gỡ driver mới cài; chạy Windows Update.'
$script:REC[$script:DEV.Periph]  = 'Cập nhật driver card mạng/USB/Bluetooth; rút bớt thiết bị USB ngoại vi; thử tắt Fast Startup.'
$script:REC[$script:DEV.Bios]    = 'Cập nhật BIOS/UEFI lên bản mới nhất của hãng; đặt lại BIOS về mặc định.'
$script:REC[$script:DEV.Windows] = 'Chạy sfc /scannow và DISM /Online /Cleanup-Image /RestoreHealth; quét virus; cập nhật Windows; kiểm tra cấu hình pagefile và dump.'
$script:REC[$script:DEV.Unknown] = 'Xem chi tiết các sự kiện WHEA-Logger trong tab Toàn bộ sự kiện để biết thành phần phần cứng nào báo lỗi.'

# ============================================================
#  BẢNG CHUẨN HÓA THỦ CÔNG cho các mã BSOD hay gặp nhất
#  (các mã khác được phân nhóm theo từ khóa trong tên lỗi)
# ============================================================
$script:BugCurated = @{}
function Add-Curated {
    param([string]$Hex, [string]$Nhom, [string]$Dev, [string]$Note, [bool]$Skip = $false)
    $script:BugCurated[$Hex.ToUpper().PadLeft(8, '0')] = @{ Nhom = $Nhom; ThietBi = $Dev; GhiChu = $Note; BoQua = $Skip }
}
$D = $script:DEV
Add-Curated '0A'  'Driver/phần mềm truy cập bộ nhớ sai mức ưu tiên (IRQL)' $D.Driver 'Thường do driver mới cài/cập nhật; ít gặp hơn là RAM lỗi. Gỡ hoặc cập nhật driver gần thời điểm lỗi.'
Add-Curated '19'  'Vùng nhớ hệ thống (pool) bị hỏng' $D.RAM 'RAM lỗi hoặc driver ghi sai bộ nhớ. Test RAM và cập nhật driver.'
Add-Curated '1A'  'Lỗi quản lý bộ nhớ' $D.RAM 'Nghi RAM lỗi hoặc driver. Chạy MemTest86 / Windows Memory Diagnostic.'
Add-Curated '1E'  'Ngoại lệ kernel không xử lý được' $D.Driver 'Driver hoặc thành phần kernel gây lỗi. Xem driver được nêu trong file dump.'
Add-Curated '24'  'Lỗi hệ thống tệp NTFS' $D.Disk 'Ổ đĩa có bad sector, cáp lỏng hoặc controller lỗi. Chạy chkdsk và kiểm tra SMART.'
Add-Curated '2E'  'Lỗi bus dữ liệu / bộ nhớ hệ thống' $D.RAM 'Thường là RAM hoặc mainboard. Test RAM, thử thay từng thanh.'
Add-Curated '3B'  'Ngoại lệ trong dịch vụ hệ thống' $D.Driver 'Thường do driver card màn hình, phần mềm diệt virus hoặc driver bên thứ ba.'
Add-Curated '50'  'Truy cập vùng nhớ không hợp lệ' $D.RAM 'RAM lỗi hoặc driver/dịch vụ hỏng; hay xuất hiện sau khi cài phần cứng hoặc phần mềm mới.'
Add-Curated '7A'  'Lỗi đọc dữ liệu từ ổ đĩa vào RAM (inpage)' $D.Disk 'Bad sector, cáp SATA/NVMe lỏng, controller lỗi; ít gặp hơn là RAM.'
Add-Curated '7B'  'Không truy cập được ổ khởi động' $D.Disk 'Driver lưu trữ, chế độ AHCI/RAID trong BIOS hoặc ổ hỏng.'
Add-Curated '7E'  'Luồng hệ thống gây ngoại lệ' $D.Driver 'Thường do driver (card màn hình, mạng, âm thanh). Xem driver trong file dump.'
Add-Curated '7F'  'Bẫy CPU không mong đợi' $D.CPU 'CPU/RAM lỗi, ép xung, quá nhiệt hoặc lỗi phần mềm kernel.'
Add-Curated '80'  'NMI phần cứng' $D.CPU 'Lỗi phần cứng nghiêm trọng (mainboard, RAM, thiết bị PCI).'
Add-Curated '9C'  'Lỗi phần cứng nghiêm trọng do CPU phát hiện (Machine Check)' $D.CPU 'CPU, RAM, mainboard hoặc nguồn điện không ổn định. Tắt ép xung, kiểm tra nhiệt độ.'
Add-Curated '9F'  'Driver không xử lý đúng trạng thái nguồn' $D.Driver 'Driver không xử lý đúng Sleep/Hibernate/tắt máy. Cập nhật driver mạng/USB/chipset, tắt Fast Startup.'
Add-Curated 'A5'  'BIOS không tương thích ACPI' $D.Bios 'Cập nhật BIOS/UEFI.'
Add-Curated 'C2'  'Driver dùng bộ nhớ sai cách (bad pool caller)' $D.Driver 'Tìm driver mới cài rồi gỡ hoặc cập nhật.'
Add-Curated 'C4'  'Driver Verifier phát hiện driver vi phạm' $D.Driver 'Nếu không chủ ý bật Driver Verifier, chạy lệnh verifier /reset.'
Add-Curated 'D1'  'Driver truy cập bộ nhớ sai mức IRQL' $D.Driver 'Lỗi rất phổ biến do driver (mạng, card màn hình...).'
Add-Curated 'EF'  'Tiến trình hệ thống quan trọng bị dừng' $D.Windows 'File hệ thống hỏng, ổ đĩa lỗi, driver hoặc phần mềm độc hại.'
Add-Curated 'F4'  'Tiến trình/luồng quan trọng bị kết thúc' $D.Disk 'Thường do ổ đĩa, cáp hoặc controller lỗi.'
Add-Curated '101' 'Một nhân CPU không phản hồi' $D.CPU 'CPU, ép xung, BIOS hoặc quá nhiệt.'
Add-Curated '109' 'Cấu trúc kernel bị ghi đè/hỏng' $D.RAM 'RAM lỗi hoặc driver lỗi.'
Add-Curated '116' 'Driver card màn hình không phản hồi (TDR)' $D.GPU 'Cập nhật hoặc cài sạch driver GPU; kiểm tra nhiệt độ card.'
Add-Curated '117' 'Card màn hình quá thời gian phản hồi (TDR)' $D.GPU 'Cập nhật hoặc cài sạch driver GPU; kiểm tra nhiệt độ card.'
Add-Curated '124' 'Lỗi phần cứng không sửa được (WHEA)' $D.CPU 'CPU, RAM, PCIe, ổ đĩa hoặc nguồn. Xem thêm sự kiện WHEA-Logger.'
Add-Curated '12B' 'Phần cứng làm hỏng trang bộ nhớ' $D.RAM 'Thường là RAM. Test RAM.'
Add-Curated '133' 'Một thành phần chạy quá lâu không phản hồi (DPC watchdog)' $D.Disk 'Thường do firmware SSD hoặc driver lưu trữ (iaStor/stornvme); cũng có thể do driver khác.'
Add-Curated '139' 'Phát hiện dữ liệu kernel bị hỏng' $D.Driver 'Driver lỗi, RAM lỗi hoặc file hệ thống hỏng.'
Add-Curated '154' 'Lỗi trong bộ quản lý Store (bộ nhớ nén)' $D.Disk 'Thường do ổ đĩa/SSD lỗi hoặc driver lưu trữ.'
Add-Curated '1C8' 'Người dùng giữ nút nguồn để tắt máy' $D.Power 'Windows ghi nhận việc giữ nút nguồn (thường vì máy đã treo).'
Add-Curated 'E2'  'Crash do người dùng chủ động kích hoạt' $D.None 'Không phải lỗi thiết bị.' $true
Add-Curated 'DEADDEAD' 'Crash do người dùng chủ động kích hoạt' $D.None 'Không phải lỗi thiết bị.' $true

# ============================================================
#  LUẬT THU THẬP SỰ KIỆN (mỗi luật = 1 truy vấn Get-WinEvent)
# ============================================================
$script:EventRules = @(
    @{ Key = 'KP41';         Name = 'Khởi động lại bất thường (Kernel-Power 41)'; Log = 'System'; Ids = @(41);                Providers = @('Microsoft-Windows-Kernel-Power'); Rx = '^Microsoft-Windows-Kernel-Power$' }
    @{ Key = 'BUGCHECK1001'; Name = 'Báo cáo BSOD (Event 1001)';                  Log = 'System'; Ids = @(1001);              Providers = $null; Rx = 'BugCheck|WER-SystemErrorReporting' }
    @{ Key = 'EVTLOG';       Name = 'Sự kiện khởi động / tắt máy';                Log = 'System'; Ids = @(6005, 6006, 6008);  Providers = @('EventLog'); Rx = '^EventLog$' }
    @{ Key = 'USER32';       Name = 'Restart / Shutdown có kế hoạch';             Log = 'System'; Ids = @(1074, 1076);        Providers = @('User32'); Rx = '^User32$' }
    @{ Key = 'DISK';         Name = 'Lỗi ổ đĩa (disk)';                           Log = 'System'; Ids = @(7, 11, 15, 51, 52, 153); Providers = @('disk'); Rx = '^disk$' }
    @{ Key = 'NTFS';         Name = 'Lỗi hệ thống tệp NTFS';                      Log = 'System'; Ids = @(55, 137, 140);      Providers = $null; Rx = '^(Ntfs|Microsoft-Windows-Ntfs)$' }
    @{ Key = 'STORRESET';    Name = 'Reset bộ điều khiển lưu trữ';                Log = 'System'; Ids = @(129);               Providers = $null; Rx = '(?i)stor|nvme|ahci|iastor|sas|scsi|raid' }
    @{ Key = 'DUMPFAIL';     Name = 'Lỗi tạo file dump';                          Log = 'System'; Ids = @(46, 161);           Providers = @('volmgr'); Rx = '^volmgr$' }
    @{ Key = 'WHEA';         Name = 'Lỗi phần cứng (WHEA-Logger)';                Log = 'System'; Ids = @(1, 17, 18, 19, 20, 47); Providers = @('Microsoft-Windows-WHEA-Logger'); Rx = 'WHEA' }
    @{ Key = 'TDR';          Name = 'Driver card màn hình ngừng phản hồi (TDR)';  Log = 'System'; Ids = @(4101);              Providers = @('Display'); Rx = '^Display$' }
    @{ Key = 'GPUDRV';       Name = 'Lỗi driver GPU (NVIDIA/AMD)';                Log = 'System'; Ids = $null;                Providers = @('nvlddmkm', 'amdkmdag'); Rx = '^(nvlddmkm|amdkmdag)$'; MaxLevel = 3 }
    @{ Key = 'CPUTHROTTLE';  Name = 'CPU bị giới hạn tốc độ (nhiệt/nguồn)';       Log = 'System'; Ids = @(37);                Providers = @('Microsoft-Windows-Kernel-Processor-Power'); Rx = 'Processor-Power' }
)

$bugCheckRaw = @"
0x00000001	APC_INDEX_MISMATCH
0x00000002	DEVICE_QUEUE_NOT_BUSY
0x00000003	INVALID_AFFINITY_SET
0x00000004	INVALID_DATA_ACCESS_TRAP
0x00000005	INVALID_PROCESS_ATTACH_ATTEMPT
0x00000006	INVALID_PROCESS_DETACH_ATTEMPT
0x00000007	INVALID_SOFTWARE_INTERRUPT
0x00000008	IRQL_NOT_DISPATCH_LEVEL
0x00000009	IRQL_NOT_GREATER_OR_EQUAL
0x0000000A	IRQL_NOT_LESS_OR_EQUAL
0x0000000B	NO_EXCEPTION_HANDLING_SUPPORT
0x0000000C	MAXIMUM_WAIT_OBJECTS_EXCEEDED
0x0000000D	MUTEX_LEVEL_NUMBER_VIOLATION
0x0000000E	NO_USER_MODE_CONTEXT
0x0000000F	SPIN_LOCK_ALREADY_OWNED
0x00000010	SPIN_LOCK_NOT_OWNED
0x00000011	THREAD_NOT_MUTEX_OWNER
0x00000012	TRAP_CAUSE_UNKNOWN
0x00000013	EMPTY_THREAD_REAPER_LIST
0x00000014	CREATE_DELETE_LOCK_NOT_LOCKED
0x00000015	LAST_CHANCE_CALLED_FROM_KMODE
0x00000016	CID_HANDLE_CREATION
0x00000017	CID_HANDLE_DELETION
0x00000018	REFERENCE_BY_POINTER
0x00000019	BAD_POOL_HEADER
0x0000001A	MEMORY_MANAGEMENT
0x0000001B	PFN_SHARE_COUNT
0x0000001C	PFN_REFERENCE_COUNT
0x0000001D	NO_SPIN_LOCK_AVAILABLE
0x0000001E	KMODE_EXCEPTION_NOT_HANDLED
0x0000001F	SHARED_RESOURCE_CONV_ERROR
0x00000020	KERNEL_APC_PENDING_DURING_EXIT
0x00000021	QUOTA_UNDERFLOW
0x00000022	FILE_SYSTEM
0x00000023	FAT_FILE_SYSTEM
0x00000024	NTFS_FILE_SYSTEM
0x00000025	NPFS_FILE_SYSTEM
0x00000026	CDFS_FILE_SYSTEM
0x00000027	RDR_FILE_SYSTEM
0x00000028	CORRUPT_ACCESS_TOKEN
0x00000029	SECURITY_SYSTEM
0x0000002A	INCONSISTENT_IRP
0x0000002B	PANIC_STACK_SWITCH
0x0000002C	PORT_DRIVER_INTERNAL
0x0000002D	SCSI_DISK_DRIVER_INTERNAL
0x0000002E	DATA_BUS_ERROR
0x0000002F	INSTRUCTION_BUS_ERROR
0x00000030	SET_OF_INVALID_CONTEXT
0x00000031	PHASE0_INITIALIZATION_FAILED
0x00000032	PHASE1_INITIALIZATION_FAILED
0x00000033	UNEXPECTED_INITIALIZATION_CALL
0x00000034	CACHE_MANAGER
0x00000035	NO_MORE_IRP_STACK_LOCATIONS
0x00000036	DEVICE_REFERENCE_COUNT_NOT_ZERO
0x00000037	FLOPPY_INTERNAL_ERROR
0x00000038	SERIAL_DRIVER_INTERNAL
0x00000039	SYSTEM_EXIT_OWNED_MUTEX
0x0000003A	SYSTEM_UNWIND_PREVIOUS_USER
0x0000003B	SYSTEM_SERVICE_EXCEPTION
0x0000003C	INTERRUPT_UNWIND_ATTEMPTED
0x0000003D	INTERRUPT_EXCEPTION_NOT_HANDLED
0x0000003E	MULTIPROCESSOR_CONFIGURATION_NOT_SUPPORTED
0x0000003F	NO_MORE_SYSTEM_PTES
0x00000040	TARGET_MDL_TOO_SMALL
0x00000041	MUST_SUCCEED_POOL_EMPTY
0x00000042	ATDISK_DRIVER_INTERNAL
0x00000043	NO_SUCH_PARTITION
0x00000044	MULTIPLE_IRP_COMPLETE_REQUESTS
0x00000045	INSUFFICIENT_SYSTEM_MAP_REGS
0x00000046	DEREF_UNKNOWN_LOGON_SESSION
0x00000047	REF_UNKNOWN_LOGON_SESSION
0x00000048	CANCEL_STATE_IN_COMPLETED_IRP
0x00000049	PAGE_FAULT_WITH_INTERRUPTS_OFF
0x0000004A	IRQL_GT_ZERO_AT_SYSTEM_SERVICE
0x0000004B	STREAMS_INTERNAL_ERROR
0x0000004C	FATAL_UNHANDLED_HARD_ERROR
0x0000004D	NO_PAGES_AVAILABLE
0x0000004E	PFN_LIST_CORRUPT
0x0000004F	NDIS_INTERNAL_ERROR
0x00000050	PAGE_FAULT_IN_NONPAGED_AREA
0x00000051	REGISTRY_ERROR
0x00000052	MAILSLOT_FILE_SYSTEM
0x00000053	NO_BOOT_DEVICE
0x00000054	LM_SERVER_INTERNAL_ERROR
0x00000055	DATA_COHERENCY_EXCEPTION
0x00000056	INSTRUCTION_COHERENCY_EXCEPTION
0x00000057	XNS_INTERNAL_ERROR
0x00000058	FTDISK_INTERNAL_ERROR
0x00000059	PINBALL_FILE_SYSTEM
0x0000005A	CRITICAL_SERVICE_FAILED
0x0000005B	SET_ENV_VAR_FAILED
0x0000005C	HAL_INITIALIZATION_FAILED
0x0000005D	UNSUPPORTED_PROCESSOR
0x0000005E	OBJECT_INITIALIZATION_FAILED
0x0000005F	SECURITY_INITIALIZATION_FAILED
0x00000060	PROCESS_INITIALIZATION_FAILED
0x00000061	HAL1_INITIALIZATION_FAILED
0x00000062	OBJECT1_INITIALIZATION_FAILED
0x00000063	SECURITY1_INITIALIZATION_FAILED
0x00000064	SYMBOLIC_INITIALIZATION_FAILED
0x00000065	MEMORY1_INITIALIZATION_FAILED
0x00000066	CACHE_INITIALIZATION_FAILED
0x00000067	CONFIG_INITIALIZATION_FAILED
0x00000068	FILE_INITIALIZATION_FAILED
0x00000069	IO1_INITIALIZATION_FAILED
0x0000006A	LPC_INITIALIZATION_FAILED
0x0000006B	PROCESS1_INITIALIZATION_FAILED
0x0000006C	REFMON_INITIALIZATION_FAILED
0x0000006D	SESSION1_INITIALIZATION_FAILED
0x0000006E	SESSION2_INITIALIZATION_FAILED
0x0000006F	SESSION3_INITIALIZATION_FAILED
0x00000070	SESSION4_INITIALIZATION_FAILED
0x00000071	SESSION5_INITIALIZATION_FAILED
0x00000072	ASSIGN_DRIVE_LETTERS_FAILED
0x00000073	CONFIG_LIST_FAILED
0x00000074	BAD_SYSTEM_CONFIG_INFO
0x00000075	CANNOT_WRITE_CONFIGURATION
0x00000076	PROCESS_HAS_LOCKED_PAGES
0x00000077	KERNEL_STACK_INPAGE_ERROR
0x00000078	PHASE0_EXCEPTION
0x00000079	MISMATCHED_HAL
0x0000007A	KERNEL_DATA_INPAGE_ERROR
0x0000007B	INACCESSIBLE_BOOT_DEVICE
0x0000007C	BUGCODE_NDIS_DRIVER
0x0000007D	INSTALL_MORE_MEMORY
0x0000007E	SYSTEM_THREAD_EXCEPTION_NOT_HANDLED
0x0000007F	UNEXPECTED_KERNEL_MODE_TRAP
0x00000080	NMI_HARDWARE_FAILURE
0x00000081	SPIN_LOCK_INIT_FAILURE
0x00000082	DFS_FILE_SYSTEM
0x00000085	SETUP_FAILURE
0x0000008B	MBR_CHECKSUM_MISMATCH
0x0000008E	KERNEL_MODE_EXCEPTION_NOT_HANDLED
0x0000008F	PP0_INITIALIZATION_FAILED
0x00000090	PP1_INITIALIZATION_FAILED
0x00000092	UP_DRIVER_ON_MP_SYSTEM
0x00000093	INVALID_KERNEL_HANDLE
0x00000094	KERNEL_STACK_LOCKED_AT_EXIT
0x00000096	INVALID_WORK_QUEUE_ITEM
0x00000097	BOUND_IMAGE_UNSUPPORTED
0x00000098	END_OF_NT_EVALUATION_PERIOD
0x00000099	INVALID_REGION_OR_SEGMENT
0x0000009A	SYSTEM_LICENSE_VIOLATION
0x0000009B	UDFS_FILE_SYSTEM
0x0000009C	MACHINE_CHECK_EXCEPTION
0x0000009E	USER_MODE_HEALTH_MONITOR
0x0000009F	DRIVER_POWER_STATE_FAILURE
0x000000A0	INTERNAL_POWER_ERROR
0x000000A1	PCI_BUS_DRIVER_INTERNAL
0x000000A2	MEMORY_IMAGE_CORRUPT
0x000000A3	ACPI_DRIVER_INTERNAL
0x000000A4	CNSS_FILE_SYSTEM_FILTER
0x000000A5	ACPI_BIOS_ERROR
0x000000A7	BAD_EXHANDLE
0x000000AC	HAL_MEMORY_ALLOCATION
0x000000AD	VIDEO_DRIVER_DEBUG_REPORT_REQUEST
0x000000B1	BGI_DETECTED_VIOLATION
0x000000B4	VIDEO_DRIVER_INIT_FAILURE
0x000000B8	ATTEMPTED_SWITCH_FROM_DPC
0x000000B9	CHIPSET_DETECTED_ERROR
0x000000BA	SESSION_HAS_VALID_VIEWS_ON_EXIT
0x000000BB	NETWORK_BOOT_INITIALIZATION_FAILED
0x000000BC	NETWORK_BOOT_DUPLICATE_ADDRESS
0x000000BD	INVALID_HIBERNATED_STATE
0x000000BE	ATTEMPTED_WRITE_TO_READONLY_MEMORY
0x000000BF	MUTEX_ALREADY_OWNED
0x000000C1	SPECIAL_POOL_DETECTED_MEMORY_CORRUPTION
0x000000C2	BAD_POOL_CALLER
0x000000C4	DRIVER_VERIFIER_DETECTED_VIOLATION
0x000000C5	DRIVER_CORRUPTED_EXPOOL
0x000000C6	DRIVER_CAUGHT_MODIFYING_FREED_POOL
0x000000C7	TIMER_OR_DPC_INVALID
0x000000C8	IRQL_UNEXPECTED_VALUE
0x000000C9	DRIVER_VERIFIER_IOMANAGER_VIOLATION
0x000000CA	PNP_DETECTED_FATAL_ERROR
0x000000CB	DRIVER_LEFT_LOCKED_PAGES_IN_PROCESS
0x000000CC	PAGE_FAULT_IN_FREED_SPECIAL_POOL
0x000000CD	PAGE_FAULT_BEYOND_END_OF_ALLOCATION
0x000000CE	DRIVER_UNLOADED_WITHOUT_CANCELLING_PENDING_OPERATIONS
0x000000CF	TERMINAL_SERVER_DRIVER_MADE_INCORRECT_MEMORY_REFERENCE
0x000000D0	DRIVER_CORRUPTED_MMPOOL
0x000000D1	DRIVER_IRQL_NOT_LESS_OR_EQUAL
0x000000D2	BUGCODE_ID_DRIVER
0x000000D3	DRIVER_PORTION_MUST_BE_NONPAGED
0x000000D4	SYSTEM_SCAN_AT_RAISED_IRQL_CAUGHT_IMPROPER_DRIVER_UNLOAD
0x000000D5	DRIVER_PAGE_FAULT_IN_FREED_SPECIAL_POOL
0x000000D6	DRIVER_PAGE_FAULT_BEYOND_END_OF_ALLOCATION
0x000000D7	DRIVER_UNMAPPING_INVALID_VIEW
0x000000D8	DRIVER_USED_EXCESSIVE_PTES
0x000000D9	LOCKED_PAGES_TRACKER_CORRUPTION
0x000000DA	SYSTEM_PTE_MISUSE
0x000000DB	DRIVER_CORRUPTED_SYSPTES
0x000000DC	DRIVER_INVALID_STACK_ACCESS
0x000000DE	POOL_CORRUPTION_IN_FILE_AREA
0x000000DF	IMPERSONATING_WORKER_THREAD
0x000000E0	ACPI_BIOS_FATAL_ERROR
0x000000E1	WORKER_THREAD_RETURNED_AT_BAD_IRQL
0x000000E2	MANUALLY_INITIATED_CRASH
0x000000E3	RESOURCE_NOT_OWNED
0x000000E4	WORKER_INVALID
0x000000E6	DRIVER_VERIFIER_DMA_VIOLATION
0x000000E7	INVALID_FLOATING_POINT_STATE
0x000000E8	INVALID_CANCEL_OF_FILE_OPEN
0x000000E9	ACTIVE_EX_WORKER_THREAD_TERMINATION
0x000000EA	THREAD_STUCK_IN_DEVICE_DRIVER
0x000000EB	DIRTY_MAPPED_PAGES_CONGESTION
0x000000EC	SESSION_HAS_VALID_SPECIAL_POOL_ON_EXIT
0x000000ED	UNMOUNTABLE_BOOT_VOLUME
0x000000EF	CRITICAL_PROCESS_DIED
0x000000F0	STORAGE_MINIPORT_ERROR
0x000000F1	SCSI_VERIFIER_DETECTED_VIOLATION
0x000000F2	HARDWARE_INTERRUPT_STORM
0x000000F3	DISORDERLY_SHUTDOWN
0x000000F4	CRITICAL_OBJECT_TERMINATION
0x000000F5	FLTMGR_FILE_SYSTEM
0x000000F6	PCI_VERIFIER_DETECTED_VIOLATION
0x000000F7	DRIVER_OVERRAN_STACK_BUFFER
0x000000F8	RAMDISK_BOOT_INITIALIZATION_FAILED
0x000000F9	DRIVER_RETURNED_STATUS_REPARSE_FOR_VOLUME_OPEN
0x000000FA	HTTP_DRIVER_CORRUPTED
0x000000FC	ATTEMPTED_EXECUTE_OF_NOEXECUTE_MEMORY
0x000000FD	DIRTY_NOWRITE_PAGES_CONGESTION
0x000000FE	BUGCODE_USB_DRIVER
0x000000FF	RESERVE_QUEUE_OVERFLOW
0x00000100	LOADER_BLOCK_MISMATCH
0x00000101	CLOCK_WATCHDOG_TIMEOUT
0x00000102	DPC_WATCHDOG_TIMEOUT
0x00000103	MUP_FILE_SYSTEM
0x00000104	AGP_INVALID_ACCESS
0x00000105	AGP_GART_CORRUPTION
0x00000106	AGP_ILLEGALLY_REPROGRAMMED
0x00000108	THIRD_PARTY_FILE_SYSTEM_FAILURE
0x00000109	CRITICAL_STRUCTURE_CORRUPTION
0x0000010A	APP_TAGGING_INITIALIZATION_FAILED
0x0000010C	FSRTL_EXTRA_CREATE_PARAMETER_VIOLATION
0x0000010D	WDF_VIOLATION
0x0000010E	VIDEO_MEMORY_MANAGEMENT_INTERNAL
0x0000010F	RESOURCE_MANAGER_EXCEPTION_NOT_HANDLED
0x00000111	RECURSIVE_NMI
0x00000112	MSRPC_STATE_VIOLATION
0x00000113	VIDEO_DXGKRNL_FATAL_ERROR
0x00000114	VIDEO_SHADOW_DRIVER_FATAL_ERROR
0x00000115	AGP_INTERNAL
0x00000116	VIDEO_TDR_FAILURE
0x00000117	VIDEO_TDR_TIMEOUT_DETECTED
0x00000119	VIDEO_SCHEDULER_INTERNAL_ERROR
0x0000011A	EM_INITIALIZATION_FAILURE
0x0000011B	DRIVER_RETURNED_HOLDING_CANCEL_LOCK
0x0000011C	ATTEMPTED_WRITE_TO_CM_PROTECTED_STORAGE
0x0000011D	EVENT_TRACING_FATAL_ERROR
0x0000011E	TOO_MANY_RECURSIVE_FAULTS
0x0000011F	INVALID_DRIVER_HANDLE
0x00000120	BITLOCKER_FATAL_ERROR
0x00000121	DRIVER_VIOLATION
0x00000122	WHEA_INTERNAL_ERROR
0x00000123	CRYPTO_SELF_TEST_FAILURE
0x00000124	WHEA_UNCORRECTABLE_ERROR
0x00000125	NMR_INVALID_STATE
0x00000126	NETIO_INVALID_POOL_CALLER
0x00000127	PAGE_NOT_ZERO
0x00000128	WORKER_THREAD_RETURNED_WITH_BAD_IO_PRIORITY
0x00000129	WORKER_THREAD_RETURNED_WITH_BAD_PAGING_IO_PRIORITY
0x0000012A	MUI_NO_VALID_SYSTEM_LANGUAGE
0x0000012B	FAULTY_HARDWARE_CORRUPTED_PAGE
0x0000012C	EXFAT_FILE_SYSTEM
0x0000012D	VOLSNAP_OVERLAPPED_TABLE_ACCESS
0x0000012E	INVALID_MDL_RANGE
0x0000012F	VHD_BOOT_INITIALIZATION_FAILED
0x00000130	DYNAMIC_ADD_PROCESSOR_MISMATCH
0x00000131	INVALID_EXTENDED_PROCESSOR_STATE
0x00000132	RESOURCE_OWNER_POINTER_INVALID
0x00000133	DPC_WATCHDOG_VIOLATION
0x00000134	DRIVE_EXTENDER
0x00000135	REGISTRY_FILTER_DRIVER_EXCEPTION
0x00000136	VHD_BOOT_HOST_VOLUME_NOT_ENOUGH_SPACE
0x00000137	WIN32K_HANDLE_MANAGER
0x00000138	GPIO_CONTROLLER_DRIVER_ERROR
0x00000139	KERNEL_SECURITY_CHECK_FAILURE
0x0000013A	KERNEL_MODE_HEAP_CORRUPTION
0x0000013B	PASSIVE_INTERRUPT_ERROR
0x0000013C	INVALID_IO_BOOST_STATE
0x0000013D	CRITICAL_INITIALIZATION_FAILURE
0x00000140	STORAGE_DEVICE_ABNORMALITY_DETECTED
0x00000143	PROCESSOR_DRIVER_INTERNAL
0x00000144	BUGCODE_USB3_DRIVER
0x00000145	SECURE_BOOT_VIOLATION
0x00000147	ABNORMAL_RESET_DETECTED
0x00000149	REFS_FILE_SYSTEM
0x0000014A	KERNEL_WMI_INTERNAL
0x0000014B	SOC_SUBSYSTEM_FAILURE
0x0000014C	FATAL_ABNORMAL_RESET_ERROR
0x0000014D	EXCEPTION_SCOPE_INVALID
0x0000014E	SOC_CRITICAL_DEVICE_REMOVED
0x0000014F	PDC_WATCHDOG_TIMEOUT
0x00000150	TCPIP_AOAC_NIC_ACTIVE_REFERENCE_LEAK
0x00000151	UNSUPPORTED_INSTRUCTION_MODE
0x00000152	INVALID_PUSH_LOCK_FLAGS
0x00000153	KERNEL_LOCK_ENTRY_LEAKED_ON_THREAD_TERMINATION
0x00000154	UNEXPECTED_STORE_EXCEPTION
0x00000155	OS_DATA_TAMPERING
0x00000157	KERNEL_THREAD_PRIORITY_FLOOR_VIOLATION
0x00000158	ILLEGAL_IOMMU_PAGE_FAULT
0x00000159	HAL_ILLEGAL_IOMMU_PAGE_FAULT
0x0000015A	SDBUS_INTERNAL_ERROR
0x0000015B	WORKER_THREAD_RETURNED_WITH_SYSTEM_PAGE_PRIORITY_ACTIVE
0x00000160	WIN32K_ATOMIC_CHECK_FAILURE
0x00000162	KERNEL_AUTO_BOOST_INVALID_LOCK_RELEASE
0x00000163	WORKER_THREAD_TEST_CONDITION
0x00000164	WIN32K_CRITICAL_FAILURE
0x0000016C	INVALID_RUNDOWN_PROTECTION_FLAGS
0x0000016D	INVALID_SLOT_ALLOCATOR_FLAGS
0x0000016E	ERESOURCE_INVALID_RELEASE
0x00000170	CLUSTER_CSV_CLUSSVC_DISCONNECT_WATCHDOG
0x00000171	CRYPTO_LIBRARY_INTERNAL_ERROR
0x00000173	COREMSGCALL_INTERNAL_ERROR
0x00000174	COREMSG_INTERNAL_ERROR
0x00000178	ELAM_DRIVER_DETECTED_FATAL_ERROR
0x0000017B	PROFILER_CONFIGURATION_ILLEGAL
0x0000017E	MICROCODE_REVISION_MISMATCH
0x00000187	VIDEO_DWMINIT_TIMEOUT_FALLBACK_BDD
0x00000189	BAD_OBJECT_HEADER
0x0000018B	SECURE_KERNEL_ERROR
0x0000018C	HYPERGUARD_VIOLATION
0x0000018D	SECURE_FAULT_UNHANDLED
0x0000018E	KERNEL_PARTITION_REFERENCE_VIOLATION
0x00000191	PF_DETECTED_CORRUPTION
0x00000192	KERNEL_AUTO_BOOST_LOCK_ACQUISITION_WITH_RAISED_IRQL
0x00000196	LOADER_ROLLBACK_DETECTED
0x00000197	WIN32K_SECURITY_FAILURE
0x00000199	KERNEL_STORAGE_SLOT_IN_USE
0x0000019A	WORKER_THREAD_RETURNED_WHILE_ATTACHED_TO_SILO
0x0000019B	TTM_FATAL_ERROR
0x0000019C	WIN32K_POWER_WATCHDOG_TIMEOUT
0x000001A0	TTM_WATCHDOG_TIMEOUT
0x000001A2	WIN32K_CALLOUT_WATCHDOG_BUGCHECK
0x000001AA	EXCEPTION_ON_INVALID_STACK
0x000001AB	UNWIND_ON_INVALID_STACK
0x000001C6	FAST_ERESOURCE_PRECONDITION_VIOLATION
0x000001C7	STORE_DATA_STRUCTURE_CORRUPTION
0x000001C8	MANUALLY_INITIATED_POWER_BUTTON_HOLD
0x000001CA	SYNTHETIC_WATCHDOG_TIMEOUT
0x000001CB	INVALID_SILO_DETACH
0x000001CD	INVALID_CALLBACK_STACK_ADDRESS
0x000001CE	INVALID_KERNEL_STACK_ADDRESS
0x000001CF	HARDWARE_WATCHDOG_TIMEOUT
0x000001D0	CPI_FIRMWARE_WATCHDOG_TIMEOUT
0x000001D2	WORKER_THREAD_INVALID_STATE
0x000001D3	WFP_INVALID_OPERATION
0x000001D5	DRIVER_PNP_WATCHDOG
0x000001D6	WORKER_THREAD_RETURNED_WITH_NON_DEFAULT_WORKLOAD_CLASS
0x000001D7	EFS_FATAL_ERROR
0x000001D8	UCMUCSI_FAILURE
0x000001D9	HAL_IOMMU_INTERNAL_ERROR
0x000001DA	HAL_BLOCKED_PROCESSOR_INTERNAL_ERROR
0x000001DB	IPI_WATCHDOG_TIMEOUT
0x000001DC	DMA_COMMON_BUFFER_VECTOR_ERROR
0x000001DD	BUGCODE_MBBADAPTER_DRIVER
0x000001DE	BUGCODE_WIFIADAPTER_DRIVER
0x000001DF	PROCESSOR_START_TIMEOUT
0x000001E4	VIDEO_DXGKRNL_SYSMM_FATAL_ERROR
0x000001E9	ILLEGAL_ATS_INITIALIZATION
0x000001EA	SECURE_PCI_CONFIG_SPACE_ACCESS_VIOLATION
0x000001EB	DAM_WATCHDOG_TIMEOUT
0x000001ED	HANDLE_ERROR_ON_CRITICAL_THREAD
0x000001F1	KASAN_ENLIGHTENMENT_VIOLATION
0x000001F2	KASAN_ILLEGAL_ACCESS
0x00000356	XBOX_ERACTRL_CS_TIMEOUT
0x00000BFE	BC_BLUETOOTH_VERIFIER_FAULT
0x00000BFF	BC_BTHMINI_VERIFIER_FAULT
0x00020001	HYPERVISOR_ERROR
0x1000007E	SYSTEM_THREAD_EXCEPTION_NOT_HANDLED_M
0x1000007F	UNEXPECTED_KERNEL_MODE_TRAP_M
0x1000008E	KERNEL_MODE_EXCEPTION_NOT_HANDLED_M
0x100000EA	THREAD_STUCK_IN_DEVICE_DRIVER_M
0x4000008A	THREAD_TERMINATE_HELD_MUTEX
0xC0000218	STATUS_CANNOT_LOAD_REGISTRY_FILE
0xC000021A	WINLOGON_FATAL_ERROR
0xC0000221	STATUS_IMAGE_CHECKSUM_MISMATCH
0xDEADDEAD	MANUALLY_INITIATED_CRASH1
"@

$script:BugNames = @{}
foreach ($line in ($bugCheckRaw -split "`r?`n")) {
    $p = $line.Trim() -split '\s+', 2
    if ($p.Count -eq 2 -and $p[0] -match '^0x[0-9A-Fa-f]{1,8}$') {
        $script:BugNames[('{0:X8}' -f [Convert]::ToUInt32($p[0].Substring(2), 16))] = $p[1].Trim()
    }
}

# ============================================================
#  TIỆN ÍCH
# ============================================================
function Test-IsLocalComputer {
    param([string]$Name)
    if ([string]::IsNullOrWhiteSpace($Name)) { return $true }
    $n = $Name.Trim().ToLower()
    return ($n -eq '.' -or $n -eq 'localhost' -or $n -eq '127.0.0.1' -or $n -eq $script:LocalName.ToLower())
}

function Get-EventProp {
    param($e, [int]$i)
    try { if ($e.Properties -and $e.Properties.Count -gt $i) { return [string]$e.Properties[$i].Value } } catch {}
    return $null
}

function Get-EventDataByName {
    param($e, [string]$Name)
    try {
        $xml = [xml]$e.ToXml()
        foreach ($n in $xml.Event.EventData.Data) {
            if ($n.GetAttribute('Name') -eq $Name) { return [string]$n.InnerText }
        }
    } catch {}
    return $null
}

function ConvertTo-UInt32OrNull {
    param($s)
    if ($null -eq $s) { return $null }
    $t = ([string]$s).Trim()
    if ($t -eq '') { return $null }
    try {
        if ($t -match '^0x[0-9a-fA-F]{1,8}$') { return [Convert]::ToUInt32($t.Substring(2), 16) }
        if ($t -match '^\d{1,10}$') { $v = [uint64]$t; if ($v -le [uint32]::MaxValue) { return [uint32]$v } }
    } catch {}
    return $null
}

# ============================================================
#  TRA MÃ BUG CHECK
# ============================================================
function Get-BugCheckGroupFromName {
    param([string]$Name)
    $D = $script:DEV
    $n = $Name.ToUpper()
    $t = $n -split '_'
    $has = { param($rx) return (@($t | Where-Object { $_ -match $rx }).Count -gt 0) }

    if (& $has '^(MACHINE|WHEA|HARDWARE|CHIPSET|NMI|IOMMU|MICROCODE|PROCESSOR|CLOCK|IPI|SOC)$') {
        return @{ Nhom = 'Lỗi phần cứng (CPU / mainboard / chipset)'; ThietBi = $D.CPU }
    }
    if (& $has '^(VIDEO|DXGKRNL|AGP|DWMINIT)$') {
        return @{ Nhom = 'Driver / phần cứng card màn hình'; ThietBi = $D.GPU }
    }
    if (& $has '^(USB|USB3|NDIS|NETWORK|NETIO|TCPIP|NIC|WIFIADAPTER|MBBADAPTER|BLUETOOTH|BTHMINI|SDBUS|UCMUCSI)$') {
        return @{ Nhom = 'Driver mạng / USB / Bluetooth'; ThietBi = $D.Periph }
    }
    $diskTok = (& $has '^(STORAGE|DISK|ATDISK|FTDISK|VOLUME|VOLSNAP|NTFS|FAT|CDFS|NPFS|EXFAT|REFS|UDFS|DFS|PINBALL|PARTITION|MBR|SCSI|RAMDISK|VHD|INPAGE|STORE)$') -or ($n -match 'FILE_SYSTEM|BOOT_DEVICE|BOOT_VOLUME|DRIVE_LETTERS|DRIVE_EXTENDER')
    if ($diskTok -and $n -notmatch '^KERNEL_STORAGE|PROTECTED_STORAGE') {
        return @{ Nhom = 'Ổ đĩa / hệ thống tệp / lưu trữ'; ThietBi = $D.Disk }
    }
    if (& $has '^(ACPI|BIOS|HAL|HAL1)$') {
        return @{ Nhom = 'BIOS / ACPI / HAL'; ThietBi = $D.Bios }
    }
    if (& $has '^POWER$') {
        return @{ Nhom = 'Quản lý nguồn (driver / kernel)'; ThietBi = $D.Driver }
    }
    if (& $has '^(DRIVER|WDF|PNP|IRQL|BUGCODE|ELAM|GPIO|FLTMGR)$') {
        return @{ Nhom = 'Driver'; ThietBi = $D.Driver }
    }
    if (& $has '^(MEMORY|MEMORY1|POOL|EXPOOL|MMPOOL|PFN|PTE|PTES|SYSPTES|MDL|PAGE|PAGES|NONPAGED|NOEXECUTE|READONLY)$') {
        return @{ Nhom = 'RAM / bộ nhớ (hoặc driver ghi sai bộ nhớ)'; ThietBi = $D.RAM }
    }
    if (& $has '^(WATCHDOG|TIMEOUT)$') {
        return @{ Nhom = 'Thành phần bị treo quá lâu (watchdog/timeout)'; ThietBi = $D.Driver }
    }
    if (& $has '^(SECURITY|CRYPTO|BITLOCKER|SECURE|EFS|HYPERGUARD|TAMPERING)$') {
        return @{ Nhom = 'Bảo mật / mã hóa / toàn vẹn hệ thống'; ThietBi = $D.Windows }
    }
    return @{ Nhom = 'Lỗi nhân / hệ thống Windows'; ThietBi = $D.Windows }
}

$script:RefHtml = $null
$script:RefFetchFailed = $false
$script:OnlineCache = @{}

function Get-BugCheckNameOnline {
    param([uint32]$Code)
    $key = '{0:X8}' -f $Code
    if ($script:OnlineCache.ContainsKey($key)) { return $script:OnlineCache[$key] }
    $found = $null
    if (-not $script:RefFetchFailed) {
        try {
            if (-not $script:RefHtml) {
                try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}
                $resp = Invoke-WebRequest -Uri $script:RefLink -UseBasicParsing -TimeoutSec 15 -ErrorAction Stop
                $script:RefHtml = [string]$resp.Content
            }
            $opt = [System.Text.RegularExpressions.RegexOptions]'IgnoreCase,Singleline'
            $m = [regex]::Match($script:RefHtml, ('0x' + $key + '.{0,300}?<a[^>]+href="([^"]+)"[^>]*>([^<]+)</a>'), $opt)
            if ($m.Success) { $found = $m.Groups[2].Value.Trim() }
        } catch {
            $script:RefFetchFailed = $true
        }
    }
    $script:OnlineCache[$key] = $found
    return $found
}

function Get-BugCheckInfo {
    param([uint32]$Code)
    $key  = '{0:X8}' -f $Code
    $hex  = '0x' + $key
    $name = $script:BugNames[$key]
    $cur  = $script:BugCurated[$key]
    $how  = ''
    $grp  = $null

    if ($cur) {
        $grp = @{ Nhom = $cur.Nhom; ThietBi = $cur.ThietBi; GhiChu = $cur.GhiChu; BoQua = $cur.BoQua }
        $how = 'Bảng chuẩn (đã kiểm tra thủ công)'
    } else {
        if (-not $name) {
            $name = Get-BugCheckNameOnline -Code $Code
            if ($name) { $how = 'Tra online từ trang Microsoft' }
        } else {
            $how = 'Suy luận theo tên lỗi (bảng Microsoft)'
        }
        if ($name) {
            $g = Get-BugCheckGroupFromName -Name $name
            $grp = @{ Nhom = $g.Nhom; ThietBi = $g.ThietBi; GhiChu = $script:REC[$g.ThietBi]; BoQua = $false }
        } else {
            $name = '(chưa có trong bảng tra cứu)'
            $how = 'Không xác định'
            $grp = @{ Nhom = 'Chưa xác định'; ThietBi = $script:DEV.Unknown; GhiChu = 'Mã lỗi này chưa có trong bảng. Tra thủ công theo link Microsoft.'; BoQua = $false }
        }
    }
    $link = 'https://learn.microsoft.com/search/?terms=' + [uri]::EscapeDataString("bug check $hex $name")
    return [pscustomobject]@{
        Code = $Code; Hex = $hex; Name = $name; Nhom = $grp.Nhom; ThietBi = $grp.ThietBi
        GhiChu = $grp.GhiChu; Cach = $how; Link = $link; BoQua = [bool]$grp.BoQua
    }
}

function Get-BugRecFields {
    param($Info)
    return @{
        MaLoiNum = $Info.Code; MaLoi = $Info.Hex; TenLoi = $Info.Name; Nhom = $Info.Nhom
        ThietBi = $Info.ThietBi; GhiChu = $Info.GhiChu; CachPhanLoai = $Info.Cach
        Link = $Info.Link; BoQua = $Info.BoQua
    }
}

# ============================================================
#  CHUYỂN SỰ KIỆN THÀNH BẢN GHI
# ============================================================
function New-Rec {
    param($e, [string]$Computer, $Rule, [string]$Kind, [string]$Level, [hashtable]$Extra)
    $msg = ''
    try { $msg = ([string]$e.Message -replace '\s+', ' ').Trim() } catch {}
    $o = [ordered]@{
        May = $Computer; ThoiGian = $e.TimeCreated; EventID = [int]$e.Id; Nguon = [string]$e.ProviderName
        Key = $Rule.Key; Loai = $Kind; MucDo = $Level
        Trigger = $false; MaLoiNum = $null; MaLoi = ''; TenLoi = ''; Nhom = ''; ThietBi = ''
        GhiChu = ''; CachPhanLoai = ''; Link = ''; BoQua = $false
        NutNguon = $false; NguDong = $false
        EvLabel = ''; EvWeight = 0; EvCap = 0; EvDevice = ''
        NoiDung = $msg
    }
    if ($Extra) { foreach ($k in $Extra.Keys) { $o[$k] = $Extra[$k] } }
    return [pscustomobject]$o
}

function Convert-EventToRecord {
    param($Event, [string]$Computer, $Rule)
    $e = $Event
    $id = [int]$e.Id
    $L = $script:LV
    $D = $script:DEV

    switch ($Rule.Key) {

        'KP41' {
            $code = ConvertTo-UInt32OrNull (Get-EventDataByName $e 'BugcheckCode')
            $pbt  = Get-EventDataByName $e 'PowerButtonTimestamp'
            $nut  = $false
            if ($pbt -match '^\d+$') { try { $nut = ([uint64]$pbt -gt 0) } catch { $nut = $true } }
            $sl   = Get-EventDataByName $e 'SleepInProgress'
            $ngu  = $false
            if ($sl -match '^\d+$') { $ngu = ([int]$sl -gt 0) }
            $extra = @{ Trigger = $true; NutNguon = $nut; NguDong = $ngu }
            if ($null -ne $code -and $code -gt 0) {
                $extra += (Get-BugRecFields (Get-BugCheckInfo -Code $code))
                $kind = 'Khởi động lại sau BSOD (Kernel-Power 41)'
            } else {
                $kind = 'Khởi động lại bất thường, không có mã BSOD (Kernel-Power 41)'
                if ($nut) { $kind += ' - có giữ nút nguồn' }
                if ($ngu) { $kind += ' - xảy ra khi đang Sleep' }
            }
            return New-Rec $e $Computer $Rule $kind $L.High $extra
        }

        'BUGCHECK1001' {
            $src = Get-EventProp $e 0
            if ([string]::IsNullOrWhiteSpace($src) -or $src -notmatch '0x') { $src = [string]$e.Message }
            $code = $null
            foreach ($m in [regex]::Matches([string]$src, '0x[0-9A-Fa-f]{1,8}(?![0-9A-Fa-f])')) {
                $code = ConvertTo-UInt32OrNull $m.Value
                if ($null -ne $code) { break }
            }
            $extra = @{ Trigger = $true }
            if ($null -ne $code) {
                $extra += (Get-BugRecFields (Get-BugCheckInfo -Code $code))
                $kind = 'Báo cáo BSOD / bugcheck (Event 1001)'
            } else {
                $kind = 'Báo cáo BSOD / bugcheck (không đọc được mã lỗi)'
            }
            return New-Rec $e $Computer $Rule $kind $L.High $extra
        }

        'EVTLOG' {
            switch ($id) {
                6005 { return New-Rec $e $Computer $Rule 'Máy khởi động (dịch vụ Event Log bật)' $L.Info @{} }
                6006 { return New-Rec $e $Computer $Rule 'Tắt máy bình thường (dịch vụ Event Log tắt)' $L.Info @{} }
                6008 {
                    $t1 = ((Get-EventProp $e 0) -replace '[\u200e\u200f]', '')
                    $t2 = ((Get-EventProp $e 1) -replace '[\u200e\u200f]', '')
                    $note = ''
                    if ($t1 -or $t2) { $note = "Thời điểm tắt ghi trong log: $t1 $t2".Trim() }
                    return New-Rec $e $Computer $Rule 'Tắt máy không đúng cách (Event 6008)' $L.High @{ Trigger = $true; GhiChu = $note }
                }
            }
            return $null
        }

        'USER32' {
            if ($id -eq 1074) {
                $proc = Get-EventProp $e 0; $reason = Get-EventProp $e 2; $type = Get-EventProp $e 4; $usr = Get-EventProp $e 6
                $note = "Tiến trình: $proc | Lý do: $reason | Loại: $type | Người dùng: $usr"
                return New-Rec $e $Computer $Rule 'Restart/Shutdown có kế hoạch (Event 1074)' $L.Info @{ GhiChu = $note }
            }
            return New-Rec $e $Computer $Rule 'Lý do tắt máy do quản trị viên ghi nhận (Event 1076)' $L.Info @{}
        }

        'DISK' {
            $dev = ''
            if ([string]$e.Message -match '\\Device\\Harddisk\d+\\DR\d+') { $dev = $Matches[0] }
            $k = $null; $lv = $L.Low; $w = 1; $cap = 5
            switch ($id) {
                7   { $k = 'Ổ đĩa báo bad block (disk 7)';                 $lv = $L.Mid;  $w = 2;  $cap = 8 }
                11  { $k = 'Ổ đĩa: lỗi bộ điều khiển (disk 11)';           $lv = $L.Mid;  $w = 2;  $cap = 8 }
                15  { $k = 'Ổ đĩa: thiết bị chưa sẵn sàng (disk 15)';      $lv = $L.Low;  $w = 1;  $cap = 3 }
                51  { $k = 'Ổ đĩa: lỗi khi đọc/ghi paging (disk 51)';      $lv = $L.Mid;  $w = 2;  $cap = 8 }
                52  { $k = 'Ổ đĩa: SMART dự báo sắp hỏng (disk 52)';       $lv = $L.High; $w = 10; $cap = 10 }
                153 { $k = 'Ổ đĩa: thao tác I/O phải thử lại (disk 153)';  $lv = $L.Low;  $w = 1;  $cap = 5 }
            }
            if (-not $k) { return $null }
            $label = $k
            if ($dev) { $label = "$k - $dev" }
            return New-Rec $e $Computer $Rule $k $lv @{ EvLabel = $label; EvWeight = $w; EvCap = $cap; EvDevice = $D.Disk; GhiChu = $dev }
        }

        'NTFS' {
            $k = $null; $lv = $L.Mid; $w = 2; $cap = 6
            switch ($id) {
                55  { $k = 'Hỏng cấu trúc hệ thống tệp NTFS (Event 55)' }
                137 { $k = 'NTFS: lỗi tài nguyên giao dịch (Event 137)'; $lv = $L.Low; $w = 1; $cap = 3 }
                140 { $k = 'NTFS: không ghi được log giao dịch (Event 140)' }
            }
            if (-not $k) { return $null }
            return New-Rec $e $Computer $Rule $k $lv @{ EvLabel = $k; EvWeight = $w; EvCap = $cap; EvDevice = $D.Disk }
        }

        'STORRESET' {
            $k = 'Bộ điều khiển lưu trữ bị reset (Event 129)'
            return New-Rec $e $Computer $Rule $k $L.Mid @{ EvLabel = $k; EvWeight = 2; EvCap = 8; EvDevice = $D.Disk }
        }

        'DUMPFAIL' {
            $k = 'Không tạo được file dump khi crash'
            return New-Rec $e $Computer $Rule $k $L.Mid @{ EvLabel = $k; EvWeight = 1; EvCap = 2; EvDevice = $D.Windows; GhiChu = 'Kiểm tra pagefile và cấu hình Startup and Recovery.' }
        }

        'WHEA' {
            $msg = [string]$e.Message
            $fatal = ($id -eq 18 -or $id -eq 20 -or $msg -match '(?i)fatal')
            $dev = $D.Unknown; $what = 'phần cứng'
            switch ($id) {
                17 { $dev = $D.CPU; $what = 'PCIe/chipset' }
                18 { $dev = $D.CPU; $what = 'CPU (machine check)' }
                19 { $dev = $D.CPU; $what = 'CPU (machine check)' }
                20 { $dev = $D.CPU; $what = 'PCIe/chipset' }
                47 { $dev = $D.RAM; $what = 'bộ nhớ' }
            }
            if ($msg -match '(?i)memory|dimm')                     { $dev = $D.RAM; $what = 'bộ nhớ' }
            elseif ($msg -match '(?i)processor core|machine check') { $dev = $D.CPU; $what = 'CPU (machine check)' }
            elseif ($msg -match '(?i)pci express|pcie')             { $dev = $D.CPU; $what = 'PCIe/chipset' }
            if ($fatal) {
                $k = "Lỗi phần cứng NGHIÊM TRỌNG ($what) - WHEA $id"
                return New-Rec $e $Computer $Rule $k $L.High @{ EvLabel = $k; EvWeight = 6; EvCap = 12; EvDevice = $dev }
            }
            $k = "Lỗi phần cứng đã được sửa ($what) - WHEA $id"
            return New-Rec $e $Computer $Rule $k $L.Low @{ EvLabel = $k; EvWeight = 1; EvCap = 4; EvDevice = $dev }
        }

        'TDR' {
            $k = 'Driver card màn hình ngừng phản hồi rồi tự phục hồi (Display 4101)'
            return New-Rec $e $Computer $Rule $k $L.Low @{ EvLabel = $k; EvWeight = 1; EvCap = 5; EvDevice = $D.GPU }
        }

        'GPUDRV' {
            if ($Rule.MaxLevel -and $null -ne $e.Level -and [int]$e.Level -gt [int]$Rule.MaxLevel) { return $null }
            $k = "Lỗi driver card màn hình ($($e.ProviderName) $id)"
            return New-Rec $e $Computer $Rule $k $L.Low @{ EvLabel = $k; EvWeight = 1; EvCap = 5; EvDevice = $D.GPU }
        }

        'CPUTHROTTLE' {
            $k = 'CPU bị firmware giới hạn tốc độ (Processor-Power 37)'
            return New-Rec $e $Computer $Rule $k $L.Low @{ EvLabel = $k; EvWeight = 1; EvCap = 2; EvDevice = $D.CPU }
        }
    }
    return $null
}

function Get-EventRecords {
    param([string]$Computer, $Rule, [datetime]$From, [datetime]$To, $Warnings)
    $out = New-Object System.Collections.Generic.List[object]
    $filter = @{ LogName = $Rule.Log; StartTime = $From; EndTime = $To }
    if ($Rule.Ids)       { $filter['Id'] = [int[]]$Rule.Ids }
    if ($Rule.Providers) { $filter['ProviderName'] = [string[]]$Rule.Providers }
    $p = @{ FilterHashtable = $filter; ErrorAction = 'Stop' }
    if (-not (Test-IsLocalComputer $Computer)) { $p['ComputerName'] = $Computer }
    $events = $null
    try {
        $events = Get-WinEvent @p
    } catch {
        $eid = [string]$_.FullyQualifiedErrorId
        if ($eid -like 'NoMatchingEventsFound*' -or $_.Exception.Message -like '*No events were found*') { return ,$out }
        [void]$Warnings.Add("[$Computer] $($Rule.Name): $($_.Exception.Message)")
        return ,$out
    }
    foreach ($e in @($events)) {
        if ($null -eq $e) { continue }
        if ($Rule.Rx -and ([string]$e.ProviderName) -notmatch $Rule.Rx) { continue }
        $r = Convert-EventToRecord -Event $e -Computer $Computer -Rule $Rule
        if ($r) { $out.Add($r) }
    }
    return ,$out
}

function Get-LogStartTime {
    param([string]$Computer)
    try {
        $p = @{ LogName = 'System'; Oldest = $true; MaxEvents = 1; ErrorAction = 'Stop' }
        if (-not (Test-IsLocalComputer $Computer)) { $p['ComputerName'] = $Computer }
        $ev = Get-WinEvent @p
        if ($ev) { return $ev.TimeCreated }
    } catch {}
    return $null
}

function Get-DumpFileList {
    param([string]$Computer, [datetime]$From, [datetime]$To)
    $res = New-Object System.Collections.Generic.List[object]
    try {
        $base = $null
        if (Test-IsLocalComputer $Computer) { $base = $env:SystemRoot } else { $base = "\\$Computer\admin$" }
        if (-not $base) { return ,$res }
        $items = @()
        $full = Join-Path $base 'MEMORY.DMP'
        if (Test-Path -LiteralPath $full) { $items += , @((Get-Item -LiteralPath $full -ErrorAction SilentlyContinue), 'Full/Kernel dump (MEMORY.DMP)') }
        foreach ($pair in @(@('Minidump', 'Minidump'), @('LiveKernelReports', 'LiveKernelReport (treo phần cứng/driver)'))) {
            $dir = Join-Path $base $pair[0]
            if (Test-Path -LiteralPath $dir) {
                foreach ($f in @(Get-ChildItem -LiteralPath $dir -Recurse -Filter '*.dmp' -ErrorAction SilentlyContinue)) {
                    $items += , @($f, $pair[1])
                }
            }
        }
        foreach ($it in $items) {
            $f = $it[0]
            if ($f -and $f.LastWriteTime -ge $From -and $f.LastWriteTime -le $To) {
                $res.Add([pscustomobject]@{
                    May = $Computer; LoaiDump = $it[1]; TenFile = $f.Name; ThoiGian = $f.LastWriteTime
                    MB = [int][math]::Round($f.Length / 1MB); DuongDan = $f.FullName
                })
            }
        }
    } catch {}
    return ,$res
}

# ============================================================
#  GOM SỰ CỐ (INCIDENTS)
# ============================================================
function Complete-Incident {
    param($Cur, $Records)
    $L = $script:LV
    $D = $script:DEV
    $items = $Cur.Items.ToArray()
    $bug = $items | Where-Object { $null -ne $_.MaLoiNum } |
        Sort-Object @{ Expression = { if ($_.Key -eq 'BUGCHECK1001') { 0 } else { 1 } } } | Select-Object -First 1
    $kp  = $items | Where-Object { $_.Key -eq 'KP41' } | Select-Object -First 1
    $nKp = @($items | Where-Object { $_.Key -eq 'KP41' }).Count

    # Bằng chứng kèm theo: các sự kiện phần cứng/ổ đĩa/GPU trong 30 phút trước sự cố
    $w0 = $Cur.First.AddMinutes(-30)
    $w1 = $Cur.Last.AddMinutes(1)
    $sup = @($Records | Where-Object { $_.May -eq $Cur.May -and $_.EvDevice -and (-not $_.Trigger) -and $_.ThoiGian -ge $w0 -and $_.ThoiGian -le $w1 })
    $score = @{}
    $parts = @()
    foreach ($g in ($sup | Group-Object EvDevice)) {
        $sum = 0
        foreach ($s in $g.Group) { $sum += [int]$s.EvWeight }
        $score[$g.Name] = $sum
        $lbl = @($g.Group | Group-Object EvLabel | ForEach-Object { if ($_.Count -gt 1) { "$($_.Name) x$($_.Count)" } else { $_.Name } })
        $parts += ($g.Name + ': ' + ($lbl -join ', '))
    }
    $bangChung = 'Không có lỗi phần cứng/ổ đĩa/GPU nào được ghi trong 30 phút trước sự cố.'
    if ($parts.Count -gt 0) { $bangChung = 'Trong 30 phút trước sự cố - ' + ($parts -join ' | ') }

    $topDev = $null; $topScore = 0
    foreach ($k in $score.Keys) { if ($score[$k] -gt $topScore) { $topScore = $score[$k]; $topDev = $k } }

    $specific = @($D.RAM, $D.Disk, $D.GPU, $D.CPU, $D.Periph, $D.Bios, $D.Unknown)
    $kieu = ''; $loai = ''; $maLoi = ''; $tenLoi = ''; $nhom = ''; $dev = ''; $cach = ''; $link = ''; $note = ''; $tin = $L.Low; $boqua = $false

    if ($bug) {
        $kieu = 'BSOD'; $loai = 'BSOD (màn hình xanh) - Windows tự khởi động lại'
        $maLoi = $bug.MaLoi; $tenLoi = $bug.TenLoi; $nhom = $bug.Nhom; $dev = $bug.ThietBi
        $cach = $bug.CachPhanLoai; $link = $bug.Link; $note = $bug.GhiChu; $boqua = [bool]$bug.BoQua
        if ($boqua) {
            $kieu = 'MANUAL'; $loai = 'Crash do người dùng chủ động kích hoạt'; $tin = $L.Info; $bangChung = ''
        } elseif ($specific -contains $dev) {
            $tin = $L.Mid
            if ($score.ContainsKey($dev) -and $score[$dev] -ge 2) {
                $tin = $L.High
                $note += ' Có lỗi cùng nhóm thiết bị ghi nhận ngay trước sự cố nên độ tin cậy cao hơn.'
            }
        } else {
            if ($cach -like 'Bảng chuẩn*') { $tin = $L.Mid } else { $tin = $L.Low }
            if ($topDev -and $topScore -ge 6) {
                $note += " Lưu ý: có bằng chứng phần cứng ($topDev) ngay trước sự cố - nên kiểm tra thiết bị này."
            }
        }
    } elseif ($kp) {
        $nom = $D.Power
        if ($kp.NutNguon) {
            $kieu = 'HARDOFF'; $loai = 'Tắt cứng bằng nút nguồn (máy thường bị treo)'
            $nhom = 'Máy treo cứng, phải giữ nút nguồn'
            $note = 'Windows ghi nhận nút nguồn bị giữ - thường do máy treo. Kiểm tra driver, RAM, ổ đĩa và nhiệt độ.'
        } else {
            $kieu = 'POWERLOSS'; $loai = 'Mất nguồn / tắt đột ngột / treo cứng (không có mã BSOD)'
            $nhom = 'Mất nguồn hoặc treo cứng, Windows không kịp ghi mã lỗi'
            $note = 'Có thể do mất điện, nguồn máy (PSU) yếu, quá nhiệt tự tắt hoặc treo cứng.'
        }
        if ($kp.NguDong) { $note += ' Sự cố xảy ra khi máy đang Sleep - nghi driver quản lý nguồn.' }
        if ($nKp -gt 1) { $note += " Máy khởi động lại lặp $nKp lần trong vài phút." }
        $dev = $nom; $cach = 'Suy luận từ Kernel-Power 41'
        if ($topDev -and $topScore -ge 2) {
            $dev = $topDev; $tin = $L.Mid
            $nhom = 'Có lỗi phần cứng ngay trước sự cố'
            if ($topScore -ge 6) { $tin = $L.High }
        }
    } else {
        $kieu = 'UNCLEAN'; $loai = 'Tắt máy không đúng cách (Event 6008)'
        $nhom = 'Tắt máy không đúng cách'
        $dev = $D.Power; $cach = 'Suy luận từ Event 6008'
        $note = 'Windows ghi nhận lần tắt trước không đúng quy trình. ' + (@($items | Select-Object -First 1).GhiChu)
        if ($topDev -and $topScore -ge 2) { $dev = $topDev; $tin = $L.Mid }
    }

    return [pscustomobject]@{
        May = $Cur.May; ThoiGian = $Cur.First; Kieu = $kieu; Loai = $loai; MaLoi = $maLoi; TenLoi = $tenLoi
        Nhom = $nhom; ThietBi = $dev; TinCay = $tin; BangChung = $bangChung; GhiChu = $note.Trim()
        CachPhanLoai = $cach; Link = $link; SoLan = $items.Count; BoQua = $boqua
    }
}

function New-Incidents {
    param($Records, [int]$GapMinutes = 10)
    $incidents = New-Object System.Collections.Generic.List[object]
    $all  = @($Records)
    $trig = @($all | Where-Object { $_.Trigger } | Sort-Object May, ThoiGian)
    $cur = $null
    foreach ($r in $trig) {
        if ($cur -and $cur.May -eq $r.May -and (($r.ThoiGian - $cur.Last).TotalMinutes -le $GapMinutes)) {
            $cur.Items.Add($r)
            $cur.Last = $r.ThoiGian
        } else {
            if ($cur) { $incidents.Add((Complete-Incident -Cur $cur -Records $all)) }
            $cur = [pscustomobject]@{ May = $r.May; First = $r.ThoiGian; Last = $r.ThoiGian; Items = (New-Object System.Collections.Generic.List[object]) }
            $cur.Items.Add($r)
        }
    }
    if ($cur) { $incidents.Add((Complete-Incident -Cur $cur -Records $all)) }
    return ,$incidents
}

# ============================================================
#  CHẨN ĐOÁN THIẾT BỊ (điểm nghi ngờ theo bằng chứng)
# ============================================================
function New-Diagnosis {
    param($Records, $Incidents)
    $L = $script:LV
    $D = $script:DEV
    $acc = @{}
    $add = {
        param($may, $dev, $label, $w, $cap, $time)
        if (-not $dev -or $w -le 0) { return }
        $k = "$may|$dev"
        if (-not $acc.ContainsKey($k)) { $acc[$k] = @{ May = $may; Dev = $dev; Labels = @{}; Last = $time } }
        $a = $acc[$k]
        if (-not $a.Labels.ContainsKey($label)) { $a.Labels[$label] = @{ N = 0; W = [int]$w; Cap = [int]$cap } }
        $a.Labels[$label].N = $a.Labels[$label].N + 1
        if ($time -gt $a.Last) { $a.Last = $time }
    }

    foreach ($inc in @($Incidents)) {
        if ($inc.BoQua) { continue }
        switch ($inc.Kieu) {
            'BSOD' {
                $w = 3
                if ($inc.ThietBi -eq $D.Driver -or $inc.ThietBi -eq $D.Windows) { $w = 2 }
                & $add $inc.May $inc.ThietBi ("BSOD $($inc.MaLoi) $($inc.TenLoi)") $w 12 $inc.ThoiGian
            }
            'POWERLOSS' { & $add $inc.May $D.Power 'Khởi động lại bất thường, không có mã BSOD' 2 8 $inc.ThoiGian }
            'HARDOFF'   { & $add $inc.May $D.Power 'Phải giữ nút nguồn để tắt máy (máy treo cứng)' 2 8 $inc.ThoiGian }
            'UNCLEAN'   { & $add $inc.May $D.Power 'Tắt máy không đúng cách (Event 6008)' 1 4 $inc.ThoiGian }
        }
    }
    foreach ($r in @($Records)) {
        if ($r.EvDevice -and [int]$r.EvWeight -gt 0) {
            & $add $r.May $r.EvDevice $r.EvLabel $r.EvWeight $r.EvCap $r.ThoiGian
        }
    }

    $out = New-Object System.Collections.Generic.List[object]
    foreach ($k in $acc.Keys) {
        $a = $acc[$k]
        $score = 0; $nLabels = 0; $texts = @()
        foreach ($lbl in ($a.Labels.Keys | Sort-Object { -1 * [math]::Min($a.Labels[$_].N * $a.Labels[$_].W, $a.Labels[$_].Cap) })) {
            $x = $a.Labels[$lbl]
            $c = [math]::Min($x.N * $x.W, $x.Cap)
            $score += $c
            if ($x.N -gt 0) { $nLabels++ }
            if ($x.N -gt 1) { $texts += "$lbl (x$($x.N))" } else { $texts += $lbl }
        }
        if ($score -le 0) { continue }
        $lv = $L.Low
        if ($score -ge 8 -or ($score -ge 5 -and $nLabels -ge 2)) { $lv = $L.High }
        elseif ($score -ge 3) { $lv = $L.Mid }
        $out.Add([pscustomobject]@{
            May = $a.May; ThietBi = $a.Dev; TinCay = $lv; Diem = [int]$score
            BangChung = ($texts -join '; '); LanCuoi = $a.Last; KhuyenNghi = [string]$script:REC[$a.Dev]
        })
    }
    $sorted = @($out | Sort-Object @{ Expression = 'May'; Descending = $false }, @{ Expression = 'Diem'; Descending = $true })
    return ,$sorted
}

function New-CodeSummary {
    param($Incidents)
    $res = New-Object System.Collections.Generic.List[object]
    $with = @($Incidents | Where-Object { $_.MaLoi })
    foreach ($g in ($with | Group-Object MaLoi)) {
        $first = $g.Group | Sort-Object ThoiGian | Select-Object -First 1
        $last  = $g.Group | Sort-Object ThoiGian -Descending | Select-Object -First 1
        $res.Add([pscustomobject]@{
            MaLoi = $g.Name; TenLoi = $first.TenLoi; Nhom = $first.Nhom; ThietBi = $first.ThietBi
            SoLan = [int]$g.Count; LanDau = $first.ThoiGian; LanCuoi = $last.ThoiGian
            May = (@($g.Group | ForEach-Object { $_.May } | Sort-Object -Unique) -join ', ')
            CachPhanLoai = $first.CachPhanLoai; GhiChu = $first.GhiChu; Link = $first.Link
        })
    }
    $sorted = @($res | Sort-Object SoLan -Descending)
    return ,$sorted
}

# ============================================================
#  CẤU TRÚC CỘT CỦA CÁC BẢNG (N=tên, H=tiêu đề, T=s/i/d, W=độ rộng)
# ============================================================
$script:SpecEvents = @(
    @{ N = 'May';      H = 'Máy';               T = 's'; W = 110 }
    @{ N = 'ThoiGian'; H = 'Thời gian';         T = 'd'; W = 140 }
    @{ N = 'EventID';  H = 'Event ID';          T = 'i'; W = 65 }
    @{ N = 'Nguon';    H = 'Nguồn';             T = 's'; W = 170 }
    @{ N = 'Loai';     H = 'Loại sự kiện';      T = 's'; W = 300 }
    @{ N = 'MucDo';    H = 'Mức độ';            T = 's'; W = 80 }
    @{ N = 'MaLoi';    H = 'Mã lỗi';            T = 's'; W = 95 }
    @{ N = 'TenLoi';   H = 'Tên lỗi';           T = 's'; W = 230 }
    @{ N = 'NoiDung';  H = 'Nội dung chi tiết'; T = 's'; W = 600 }
)
$script:SpecIncidents = @(
    @{ N = 'May';          H = 'Máy';                   T = 's'; W = 100 }
    @{ N = 'ThoiGian';     H = 'Thời điểm ghi nhận';    T = 'd'; W = 140 }
    @{ N = 'Loai';         H = 'Loại sự cố';            T = 's'; W = 210; Wrap = $true }
    @{ N = 'MaLoi';        H = 'Mã lỗi';                T = 's'; W = 95 }
    @{ N = 'TenLoi';       H = 'Tên lỗi';               T = 's'; W = 190; Wrap = $true }
    @{ N = 'Nhom';         H = 'Nhóm nguyên nhân';      T = 's'; W = 210; Wrap = $true }
    @{ N = 'ThietBi';      H = 'Thiết bị nghi ngờ';     T = 's'; W = 170; Wrap = $true }
    @{ N = 'TinCay';       H = 'Mức tin cậy';           T = 's'; W = 90 }
    @{ N = 'BangChung';    H = 'Bằng chứng kèm theo';   T = 's'; W = 300; Wrap = $true }
    @{ N = 'GhiChu';       H = 'Ghi chú / hướng xử lý'; T = 's'; W = 320; Wrap = $true }
    @{ N = 'CachPhanLoai'; H = 'Cách phân loại';        T = 's'; W = 160; Wrap = $true }
)
$script:SpecDiag = @(
    @{ N = 'May';        H = 'Máy';                     T = 's'; W = 100 }
    @{ N = 'ThietBi';    H = 'Thiết bị nghi ngờ';       T = 's'; W = 200; Wrap = $true }
    @{ N = 'TinCay';     H = 'Mức tin cậy';             T = 's'; W = 90 }
    @{ N = 'Diem';       H = 'Điểm nghi ngờ';           T = 'i'; W = 80 }
    @{ N = 'BangChung';  H = 'Bằng chứng trong log';    T = 's'; W = 420; Wrap = $true }
    @{ N = 'LanCuoi';    H = 'Lần gần nhất';            T = 'd'; W = 140 }
    @{ N = 'KhuyenNghi'; H = 'Cách kiểm tra / xử lý';   T = 's'; W = 430; Wrap = $true }
)
$script:SpecCodes = @(
    @{ N = 'MaLoi';        H = 'Mã lỗi';               T = 's'; W = 95 }
    @{ N = 'TenLoi';       H = 'Tên lỗi';              T = 's'; W = 260; Wrap = $true }
    @{ N = 'Nhom';         H = 'Nhóm nguyên nhân';     T = 's'; W = 230; Wrap = $true }
    @{ N = 'ThietBi';      H = 'Thiết bị nghi ngờ';    T = 's'; W = 170; Wrap = $true }
    @{ N = 'SoLan';        H = 'Số lần';               T = 'i'; W = 60 }
    @{ N = 'LanDau';       H = 'Lần đầu';              T = 'd'; W = 140 }
    @{ N = 'LanCuoi';      H = 'Lần cuối';             T = 'd'; W = 140 }
    @{ N = 'May';          H = 'Máy';                  T = 's'; W = 120; Wrap = $true }
    @{ N = 'CachPhanLoai'; H = 'Cách phân loại';       T = 's'; W = 170; Wrap = $true }
    @{ N = 'GhiChu';       H = 'Ghi chú';              T = 's'; W = 320; Wrap = $true }
    @{ N = 'Link';         H = 'Link tra cứu (bấm đúp)'; T = 's'; W = 260 }
)
$script:SpecDumps = @(
    @{ N = 'May';      H = 'Máy';           T = 's'; W = 110 }
    @{ N = 'LoaiDump'; H = 'Loại file dump'; T = 's'; W = 260 }
    @{ N = 'TenFile';  H = 'Tên file';      T = 's'; W = 200 }
    @{ N = 'ThoiGian'; H = 'Thời gian tạo'; T = 'd'; W = 140 }
    @{ N = 'MB';       H = 'Dung lượng (MB)'; T = 'i'; W = 100 }
    @{ N = 'DuongDan'; H = 'Đường dẫn';     T = 's'; W = 450 }
)

function New-DataTableFromObjects {
    param($Objects, $Spec)
    $dt = New-Object System.Data.DataTable
    foreach ($c in $Spec) {
        $type = [string]
        if ($c.T -eq 'i') { $type = [int] } elseif ($c.T -eq 'd') { $type = [datetime] }
        $col = New-Object System.Data.DataColumn($c.N, $type)
        $col.Caption = $c.H
        [void]$dt.Columns.Add($col)
    }
    foreach ($o in @($Objects)) {
        if ($null -eq $o) { continue }
        $row = $dt.NewRow()
        foreach ($c in $Spec) {
            $v = $o.($c.N)
            if ($null -eq $v) { $row[$c.N] = [DBNull]::Value }
            elseif ($c.T -eq 'i') { $row[$c.N] = [int]$v }
            elseif ($c.T -eq 'd') { if ($v -is [datetime]) { $row[$c.N] = $v } else { $row[$c.N] = [DBNull]::Value } }
            else { $row[$c.N] = [string]$v }
        }
        [void]$dt.Rows.Add($row)
    }
    return ,$dt
}

# ============================================================
#  TỔNG KẾT (tab Tổng quan + báo cáo)
# ============================================================
function New-SummaryLines {
    param($Computers, $Incidents, $Diag, $Records, [datetime]$From, [datetime]$To, $Warnings, $LogStarts, $DumpFiles)
    $lv = $script:LV
    $L = New-Object System.Collections.Generic.List[object]
    $add = { param($t, $c, $b) $L.Add(@{ T = [string]$t; C = [string]$c; B = [bool]$b }) }

    & $add ('KẾT QUẢ PHÂN TÍCH:  {0:dd/MM/yyyy HH:mm}  đến  {1:dd/MM/yyyy HH:mm}' -f $From, $To) 'blue' $true
    & $add '' 'black' $false

    foreach ($pc in @($Computers)) {
        $inc  = @($Incidents | Where-Object { $_.May -eq $pc -and $_.Kieu -ne 'MANUAL' })
        $nB   = @($inc | Where-Object { $_.Kieu -eq 'BSOD' }).Count
        $nP   = @($inc | Where-Object { $_.Kieu -eq 'POWERLOSS' }).Count
        $nH   = @($inc | Where-Object { $_.Kieu -eq 'HARDOFF' }).Count
        $nU   = @($inc | Where-Object { $_.Kieu -eq 'UNCLEAN' }).Count
        $nPl  = @($Records | Where-Object { $_.May -eq $pc -and $_.Key -eq 'USER32' -and $_.EventID -eq 1074 }).Count
        $nAll = @($Records | Where-Object { $_.May -eq $pc }).Count
        $dg   = @($Diag | Where-Object { $_.May -eq $pc })
        $hi   = @($dg | Where-Object { $_.TinCay -eq $lv.High })
        $mid  = @($dg | Where-Object { $_.TinCay -eq $lv.Mid })

        $verdict = 'ỔN ĐỊNH'; $vc = 'green'
        if ($hi.Count -gt 0 -or $inc.Count -ge 3) { $verdict = 'CẦN XỬ LÝ'; $vc = 'red' }
        elseif ($inc.Count -ge 1 -or $mid.Count -gt 0) { $verdict = 'CẦN THEO DÕI'; $vc = 'orange' }

        & $add ("MÁY: $pc   -   $verdict") $vc $true
        if ($nAll -eq 0) {
            & $add '   Không có sự kiện nào trong khoảng thời gian này (hoặc không đọc được log - xem phần cảnh báo bên dưới).' 'gray' $false
        }
        & $add ("   Số sự cố: {0}   (BSOD: {1};  mất nguồn/treo cứng: {2};  giữ nút nguồn: {3};  tắt không đúng cách: {4})" -f $inc.Count, $nB, $nP, $nH, $nU) 'black' $false
        & $add ("   Restart/Shutdown có kế hoạch (bình thường): $nPl lần") 'gray' $false
        if ($inc.Count -gt 0) {
            $lastInc = $inc | Sort-Object ThoiGian -Descending | Select-Object -First 1
            & $add ("   Sự cố gần nhất: {0:dd/MM/yyyy HH:mm} - {1} {2}" -f $lastInc.ThoiGian, $lastInc.Loai, $lastInc.MaLoi) 'black' $false
        }
        $top = @($dg | Select-Object -First 3)
        if ($top.Count -gt 0) {
            & $add '   Thiết bị nghi ngờ hàng đầu:' 'black' $true
            foreach ($t in $top) {
                $col = 'gray'
                if ($t.TinCay -eq $lv.High) { $col = 'red' } elseif ($t.TinCay -eq $lv.Mid) { $col = 'orange' }
                & $add ("      - {0}  (tin cậy: {1}, {2} điểm)" -f $t.ThietBi, $t.TinCay, $t.Diem) $col $false
                & $add ("        Bằng chứng: {0}" -f $t.BangChung) 'gray' $false
            }
            & $add "   Xem tab 'Chẩn đoán thiết bị' để biết cách kiểm tra từng thiết bị." 'blue' $false
        }
        if ($LogStarts -and $LogStarts.ContainsKey($pc) -and $LogStarts[$pc]) {
            $ls = [datetime]$LogStarts[$pc]
            if ($ls -gt $From) {
                & $add ("   Lưu ý: log System của máy này chỉ còn dữ liệu từ {0:dd/MM/yyyy HH:mm}. Sự cố trước thời điểm đó đã bị Windows ghi đè nên không thể phân tích." -f $ls) 'orange' $false
            }
        }
        & $add '' 'black' $false
    }

    $dumpN = @($DumpFiles).Count
    & $add ("File dump tìm thấy trong khoảng thời gian: $dumpN  (xem tab 'File dump')") 'gray' $false
    if ($Warnings -and @($Warnings).Count -gt 0) {
        & $add '' 'black' $false
        & $add 'CẢNH BÁO KHI QUÉT:' 'orange' $true
        foreach ($w in $Warnings) { & $add ("   - $w") 'orange' $false }
    }
    & $add '' 'black' $false
    & $add 'LƯU Ý QUAN TRỌNG' 'blue' $true
    & $add '  - Thời điểm sự cố là lúc Windows ghi nhận sau khi khởi động lại; sự cố thực tế có thể xảy ra sớm hơn.' 'gray' $false
    & $add '  - Phần "thiết bị nghi ngờ" là suy luận theo quy tắc từ bằng chứng trong log, KHÔNG phải kết luận phần cứng hỏng.' 'gray' $false
    & $add '    Hãy kiểm tra thực tế (SMART, MemTest, nhiệt độ...) trước khi thay thiết bị.' 'gray' $false
    & $add '  - Muốn biết chính xác driver nào gây BSOD: mở file .dmp bằng BlueScreenView (NirSoft) hoặc WinDbg.' 'gray' $false
    return ,$L
}

# ============================================================
#  XUẤT CSV / HTML
# ============================================================
function ConvertTo-CsvText {
    param($dt)
    $sb = New-Object System.Text.StringBuilder
    $hdr = New-Object System.Collections.Generic.List[string]
    foreach ($c in $dt.Columns) { $hdr.Add('"' + ($c.Caption -replace '"', '""') + '"') }
    [void]$sb.AppendLine(($hdr -join ','))
    foreach ($r in $dt.Rows) {
        $f = New-Object System.Collections.Generic.List[string]
        foreach ($c in $dt.Columns) {
            $v = $r[$c.ColumnName]
            $s = ''
            if ($v -is [DBNull]) { $s = '' }
            elseif ($v -is [datetime]) { $s = $v.ToString('yyyy-MM-dd HH:mm:ss') }
            else { $s = [string]$v }
            $f.Add('"' + ($s -replace '"', '""') + '"')
        }
        [void]$sb.AppendLine(($f -join ','))
    }
    return $sb.ToString()
}

function Save-TextUtf8Bom {
    param([string]$Path, [string]$Text)
    [System.IO.File]::WriteAllText($Path, $Text, (New-Object System.Text.UTF8Encoding($true)))
}

function Export-CsvFiles {
    param($State, [string]$Folder)
    $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $files = @()
    $map = @(
        @{ Dt = $State.DtIncidents; Name = "SuCo_$stamp.csv" }
        @{ Dt = $State.DtDiag;      Name = "ChanDoanThietBi_$stamp.csv" }
        @{ Dt = $State.DtCodes;     Name = "MaLoiBSOD_$stamp.csv" }
        @{ Dt = $State.DtEvents;    Name = "ToanBoSuKien_$stamp.csv" }
        @{ Dt = $State.DtDumps;     Name = "FileDump_$stamp.csv" }
    )
    foreach ($m in $map) {
        if ($m.Dt) {
            $p = Join-Path $Folder $m.Name
            Save-TextUtf8Bom -Path $p -Text (ConvertTo-CsvText $m.Dt)
            $files += $p
        }
    }
    return $files
}

function ConvertTo-HtmlTable {
    param($dt, [string]$LevelCol)
    $enc = { param($s) [System.Net.WebUtility]::HtmlEncode([string]$s) }
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('<table><thead><tr>')
    foreach ($c in $dt.Columns) { [void]$sb.Append('<th>' + (& $enc $c.Caption) + '</th>') }
    [void]$sb.AppendLine('</tr></thead><tbody>')
    foreach ($r in $dt.Rows) {
        $cls = ''
        if ($LevelCol -and $dt.Columns.Contains($LevelCol)) {
            $lvv = [string]$r[$LevelCol]
            if ($lvv -eq $script:LV.High) { $cls = ' class="hi"' } elseif ($lvv -eq $script:LV.Mid) { $cls = ' class="mid"' } elseif ($lvv -eq $script:LV.Low) { $cls = ' class="low"' }
        }
        [void]$sb.Append("<tr$cls>")
        foreach ($c in $dt.Columns) {
            $v = $r[$c.ColumnName]
            $s = ''
            if ($v -is [DBNull]) { $s = '' } elseif ($v -is [datetime]) { $s = $v.ToString('dd/MM/yyyy HH:mm:ss') } else { $s = [string]$v }
            [void]$sb.Append('<td>' + (& $enc $s) + '</td>')
        }
        [void]$sb.AppendLine('</tr>')
    }
    [void]$sb.AppendLine('</tbody></table>')
    return $sb.ToString()
}

function New-HtmlReport {
    param($State)
    $enc = { param($s) [System.Net.WebUtility]::HtmlEncode([string]$s) }
    $sb = New-Object System.Text.StringBuilder
    $css = @'
body{font-family:"Segoe UI",Arial,sans-serif;margin:24px;color:#222}
h1{font-size:22px;color:#1f4e79} h2{font-size:17px;color:#1f4e79;border-bottom:2px solid #1f4e79;padding-bottom:4px;margin-top:32px}
table{border-collapse:collapse;width:100%;font-size:12.5px;margin-top:8px}
th{background:#1f4e79;color:#fff;text-align:left;padding:6px;position:sticky;top:0}
td{border:1px solid #ccc;padding:5px;vertical-align:top}
tr.hi td{background:#ffd6d6} tr.mid td{background:#ffecbe} tr.low td{background:#fffacd}
p{margin:2px 0;white-space:pre-wrap}
.blue{color:#1f4e79}.red{color:#c00000}.orange{color:#c55a00}.green{color:#2e7d32}.gray{color:#666}.black{color:#222}
.b{font-weight:bold}
'@
    [void]$sb.AppendLine('<!DOCTYPE html><html lang="vi"><head><meta charset="utf-8"><title>Báo cáo Event Log</title><style>' + $css + '</style></head><body>')
    [void]$sb.AppendLine('<h1>Báo cáo phân tích Windows Event Log</h1>')
    [void]$sb.AppendLine('<p class="gray">Tạo lúc ' + (Get-Date).ToString('dd/MM/yyyy HH:mm') + ' bởi ' + (& $enc $script:AppName) + ' ' + $script:AppVer + '</p>')
    foreach ($l in $State.SummaryLines) {
        $b = ''
        if ($l.B) { $b = ' b' }
        [void]$sb.AppendLine('<p class="' + $l.C + $b + '">' + (& $enc $l.T) + '</p>')
    }
    [void]$sb.AppendLine('<h2>Chẩn đoán thiết bị</h2>' + (ConvertTo-HtmlTable $State.DtDiag 'TinCay'))
    [void]$sb.AppendLine('<h2>Danh sách sự cố</h2>' + (ConvertTo-HtmlTable $State.DtIncidents 'TinCay'))
    [void]$sb.AppendLine('<h2>Thống kê theo mã lỗi BSOD</h2>' + (ConvertTo-HtmlTable $State.DtCodes ''))
    [void]$sb.AppendLine('<h2>File dump</h2>' + (ConvertTo-HtmlTable $State.DtDumps ''))
    [void]$sb.AppendLine('<h2>Toàn bộ sự kiện liên quan</h2>' + (ConvertTo-HtmlTable $State.DtEvents 'MucDo'))
    [void]$sb.AppendLine('</body></html>')
    return $sb.ToString()
}

# ============================================================
#  GIAO DIỆN (Windows Forms)
# ============================================================
function Get-UiColor {
    param([string]$Name)
    switch ($Name) {
        'red'    { return [System.Drawing.Color]::FromArgb(192, 0, 0) }
        'orange' { return [System.Drawing.Color]::FromArgb(197, 90, 17) }
        'green'  { return [System.Drawing.Color]::FromArgb(46, 125, 50) }
        'blue'   { return [System.Drawing.Color]::FromArgb(31, 78, 121) }
        'gray'   { return [System.Drawing.Color]::FromArgb(100, 100, 100) }
        default  { return [System.Drawing.Color]::FromArgb(30, 30, 30) }
    }
}

function Set-RowColors {
    param($grid)
    $col = [string]$grid.Tag
    if (-not $col -or -not $grid.Columns.Contains($col)) { return }
    $cHigh = [System.Drawing.Color]::FromArgb(255, 214, 214)
    $cMid  = [System.Drawing.Color]::FromArgb(255, 236, 190)
    $cLow  = [System.Drawing.Color]::FromArgb(255, 250, 205)
    foreach ($row in $grid.Rows) {
        $v = [string]$row.Cells[$col].Value
        if ($v -eq $script:LV.High)     { $row.DefaultCellStyle.BackColor = $cHigh }
        elseif ($v -eq $script:LV.Mid)  { $row.DefaultCellStyle.BackColor = $cMid }
        elseif ($v -eq $script:LV.Low)  { $row.DefaultCellStyle.BackColor = $cLow }
        else                            { $row.DefaultCellStyle.BackColor = [System.Drawing.Color]::White }
    }
}

function New-Grid {
    $g = New-Object System.Windows.Forms.DataGridView
    $g.Dock = 'Fill'
    $g.ReadOnly = $true
    $g.AllowUserToAddRows = $false
    $g.AllowUserToDeleteRows = $false
    $g.AllowUserToResizeRows = $false
    $g.SelectionMode = 'FullRowSelect'
    $g.MultiSelect = $false
    $g.RowHeadersVisible = $false
    $g.BackgroundColor = [System.Drawing.Color]::White
    $g.AutoSizeColumnsMode = 'None'
    $g.ColumnHeadersHeightSizeMode = 'AutoSize'
    $g.Add_DataBindingComplete({ param($s, $e) Set-RowColors $s })
    $g.Add_Sorted({ param($s, $e) Set-RowColors $s })
    return $g
}

function Set-GridData {
    param($grid, $dt, $spec, [string]$levelCol, [bool]$wrapRows = $false)
    $grid.SuspendLayout()
    $grid.DataSource = $null
    $grid.Columns.Clear()
    $grid.Tag = $levelCol
    $grid.DataSource = $dt.DefaultView
    foreach ($c in $spec) {
        if ($grid.Columns.Contains($c.N)) {
            $col = $grid.Columns[$c.N]
            $col.HeaderText = $c.H
            if ($c.W) { $col.Width = [int]$c.W }
            if ($c.T -eq 'd') { $col.DefaultCellStyle.Format = 'dd/MM/yyyy HH:mm:ss' }
            if ($c.Wrap) { $col.DefaultCellStyle.WrapMode = 'True' }
        }
    }
    if ($wrapRows) { $grid.AutoSizeRowsMode = 'AllCells' } else { $grid.AutoSizeRowsMode = 'None' }
    $grid.ResumeLayout()
    Set-RowColors $grid
}

function Write-SummaryBox {
    param($rtb, $lines)
    $rtb.Clear()
    foreach ($l in $lines) {
        $style = [System.Drawing.FontStyle]::Regular
        if ($l.B) { $style = [System.Drawing.FontStyle]::Bold }
        $rtb.SelectionStart = $rtb.TextLength
        $rtb.SelectionLength = 0
        $rtb.SelectionColor = Get-UiColor $l.C
        $rtb.SelectionFont = New-Object System.Drawing.Font('Segoe UI', 10, $style)
        $rtb.AppendText($l.T + "`r`n")
    }
    $rtb.SelectionStart = 0
    $rtb.ScrollToCaret()
}

function ConvertTo-LikeText {
    param([string]$s)
    $s = $s -replace '([\[\]%*])', '[$1]'
    $s = $s -replace "'", "''"
    return $s
}

function Update-EventFilter {
    $dt = $script:State.DtEvents
    if (-not $dt) { return }
    $parts = @()
    $txt = $script:ui.txtFilter.Text.Trim()
    if ($txt) {
        $t = ConvertTo-LikeText $txt
        $parts += "(NoiDung LIKE '%$t%' OR Loai LIKE '%$t%' OR MaLoi LIKE '%$t%' OR TenLoi LIKE '%$t%' OR May LIKE '%$t%' OR Nguon LIKE '%$t%')"
    }
    $lv = [string]$script:ui.cboLevel.SelectedItem
    if ($lv -and $lv -ne 'Tất cả mức độ') { $parts += ("MucDo = '" + ($lv -replace "'", "''") + "'") }
    try { $dt.DefaultView.RowFilter = ($parts -join ' AND ') } catch {}
}

function Invoke-Analysis {
    $ui = $script:ui
    $computers = @(($ui.txtPC.Text -split '[,;\s]+') | Where-Object { $_ })
    if ($computers.Count -eq 0) { $computers = @($script:LocalName) }
    $from = $ui.dtFrom.Value
    $to   = $ui.dtTo.Value
    if ($from -ge $to) {
        [void][System.Windows.Forms.MessageBox]::Show("Khoảng thời gian không hợp lệ: 'Từ' phải nhỏ hơn 'Đến'.", $script:AppName, 'OK', 'Warning')
        return
    }
    $ui.btnRun.Enabled = $false
    $ui.btnStop.Enabled = $true
    $script:CancelRequested = $false
    $all = New-Object System.Collections.Generic.List[object]
    $warnings = New-Object System.Collections.Generic.List[string]
    $dumps = New-Object System.Collections.Generic.List[object]
    $logStarts = @{}
    $rules = @($script:EventRules)
    $ui.progress.Minimum = 0
    $ui.progress.Maximum = [math]::Max(1, $computers.Count * ($rules.Count + 2))
    $ui.progress.Value = 0
    $step = 0
    try {
        foreach ($pc in $computers) {
            if ($script:CancelRequested) { break }
            $ui.lblStatus.Text = "Đang kiểm tra log của $pc ..."
            [System.Windows.Forms.Application]::DoEvents()
            $logStarts[$pc] = Get-LogStartTime -Computer $pc
            $step++; $ui.progress.Value = [math]::Min($ui.progress.Maximum, $step)
            foreach ($rule in $rules) {
                if ($script:CancelRequested) { break }
                $ui.lblStatus.Text = "Đang quét $pc : $($rule.Name) ..."
                [System.Windows.Forms.Application]::DoEvents()
                $recs = Get-EventRecords -Computer $pc -Rule $rule -From $from -To $to -Warnings $warnings
                foreach ($r in $recs) { $all.Add($r) }
                $step++; $ui.progress.Value = [math]::Min($ui.progress.Maximum, $step)
                [System.Windows.Forms.Application]::DoEvents()
            }
            $ui.lblStatus.Text = "Đang tìm file dump trên $pc ..."
            [System.Windows.Forms.Application]::DoEvents()
            foreach ($d in (Get-DumpFileList -Computer $pc -From $from -To $to)) { $dumps.Add($d) }
            $step++; $ui.progress.Value = [math]::Min($ui.progress.Maximum, $step)
        }
        if ($script:CancelRequested) { $warnings.Add('Bạn đã dừng phân tích giữa chừng - kết quả có thể chưa đầy đủ.') }

        $ui.lblStatus.Text = 'Đang phân tích và chẩn đoán ...'
        [System.Windows.Forms.Application]::DoEvents()
        $recs2 = @($all.ToArray() | Sort-Object ThoiGian)
        $incs  = New-Incidents -Records $recs2
        $diag  = New-Diagnosis -Records $recs2 -Incidents $incs
        $codes = New-CodeSummary -Incidents $incs
        $sum   = New-SummaryLines -Computers $computers -Incidents $incs -Diag $diag -Records $recs2 -From $from -To $to -Warnings $warnings -LogStarts $logStarts -DumpFiles $dumps

        $incSorted = @($incs | Sort-Object ThoiGian -Descending)
        $evSorted  = @($recs2 | Sort-Object ThoiGian -Descending)
        $dtInc  = New-DataTableFromObjects $incSorted $script:SpecIncidents
        $dtDiag = New-DataTableFromObjects $diag $script:SpecDiag
        $dtCode = New-DataTableFromObjects $codes $script:SpecCodes
        $dtEv   = New-DataTableFromObjects $evSorted $script:SpecEvents
        $dtDump = New-DataTableFromObjects @($dumps.ToArray() | Sort-Object ThoiGian -Descending) $script:SpecDumps

        $script:State.Records = $recs2; $script:State.Incidents = $incs; $script:State.Diag = $diag
        $script:State.DtIncidents = $dtInc; $script:State.DtDiag = $dtDiag; $script:State.DtCodes = $dtCode
        $script:State.DtEvents = $dtEv; $script:State.DtDumps = $dtDump
        $script:State.SummaryLines = $sum; $script:State.Ready = $true

        Write-SummaryBox $ui.rtbSummary $sum
        Set-GridData $ui.gIncidents $dtInc $script:SpecIncidents 'TinCay' $true
        Set-GridData $ui.gDiag $dtDiag $script:SpecDiag 'TinCay' $true
        Set-GridData $ui.gCodes $dtCode $script:SpecCodes '' $true
        Set-GridData $ui.gEvents $dtEv $script:SpecEvents 'MucDo' $false
        Set-GridData $ui.gDumps $dtDump $script:SpecDumps '' $false
        Update-EventFilter

        $ui.tabs.SelectedIndex = 0
        $ui.lblStatus.Text = ("Xong: {0} sự kiện, {1} sự cố, {2} thiết bị nghi ngờ." -f $recs2.Count, @($incs).Count, @($diag).Count)
    } catch {
        $ui.lblStatus.Text = 'Có lỗi khi phân tích.'
        [void][System.Windows.Forms.MessageBox]::Show(("Lỗi khi phân tích:`r`n" + ($_ | Out-String)), $script:AppName, 'OK', 'Error')
        [Console]::Error.WriteLine(($_ | Out-String))
    } finally {
        $ui.btnRun.Enabled = $true
        $ui.btnStop.Enabled = $false
        $ui.progress.Value = 0
    }
}

function Show-MainForm {
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    [System.Windows.Forms.Application]::EnableVisualStyles()

    $script:ui = @{}
    $script:State = @{ Ready = $false; DtEvents = $null }
    $script:CancelRequested = $false
    $ui = $script:ui

    $form = New-Object System.Windows.Forms.Form
    $form.Text = "$($script:AppName) - Phân tích Dump / Reset / Restart bất thường"
    $form.Size = New-Object System.Drawing.Size(1280, 800)
    $form.StartPosition = 'CenterScreen'
    $form.Font = New-Object System.Drawing.Font('Segoe UI', 9)
    $form.Add_FormClosing({ $script:CancelRequested = $true })

    # ----- Tab control (Fill: thêm trước) -----
    $tabs = New-Object System.Windows.Forms.TabControl
    $tabs.Dock = 'Fill'
    $ui.tabs = $tabs

    $tpSum  = New-Object System.Windows.Forms.TabPage; $tpSum.Text  = 'Tổng quan'
    $tpInc  = New-Object System.Windows.Forms.TabPage; $tpInc.Text  = 'Sự cố'
    $tpDiag = New-Object System.Windows.Forms.TabPage; $tpDiag.Text = 'Chẩn đoán thiết bị'
    $tpCode = New-Object System.Windows.Forms.TabPage; $tpCode.Text = 'Mã lỗi BSOD'
    $tpEv   = New-Object System.Windows.Forms.TabPage; $tpEv.Text   = 'Toàn bộ sự kiện'
    $tpDump = New-Object System.Windows.Forms.TabPage; $tpDump.Text = 'File dump'
    foreach ($tp in @($tpSum, $tpInc, $tpDiag, $tpCode, $tpEv, $tpDump)) { [void]$tabs.TabPages.Add($tp) }

    $rtb = New-Object System.Windows.Forms.RichTextBox
    $rtb.Dock = 'Fill'; $rtb.ReadOnly = $true; $rtb.BackColor = [System.Drawing.Color]::White
    $rtb.BorderStyle = 'None'; $rtb.Font = New-Object System.Drawing.Font('Segoe UI', 10)
    $rtb.Text = "Chọn máy tính và khoảng thời gian ở phía trên, rồi bấm 'Phân tích'.`r`n`r`nỨng dụng sẽ:`r`n  - Tìm các lần BSOD (dump), mất nguồn, treo cứng, tắt máy không đúng cách trong khoảng thời gian bạn chọn`r`n  - Tra mã lỗi BSOD theo bảng của Microsoft và phân nhóm nguyên nhân`r`n  - Phỏng đoán thiết bị nghi ngờ (RAM, ổ đĩa, card màn hình, CPU/mainboard, nguồn, driver...) kèm bằng chứng"
    $tpSum.Controls.Add($rtb); $ui.rtbSummary = $rtb

    $gInc = New-Grid;  $tpInc.Controls.Add($gInc);   $ui.gIncidents = $gInc
    $gDiag = New-Grid; $tpDiag.Controls.Add($gDiag); $ui.gDiag = $gDiag
    $gCodes = New-Grid; $tpCode.Controls.Add($gCodes); $ui.gCodes = $gCodes
    $gDumps = New-Grid; $tpDump.Controls.Add($gDumps); $ui.gDumps = $gDumps

    $gCodes.Add_CellDoubleClick({
        param($s, $e)
        if ($e.RowIndex -ge 0 -and $s.Columns.Contains('Link')) {
            $l = [string]$s.Rows[$e.RowIndex].Cells['Link'].Value
            if ($l) { try { Start-Process $l } catch {} }
        }
    })

    # Tab sự kiện: lưới + ô chi tiết + thanh lọc
    $gEv = New-Grid; $ui.gEvents = $gEv
    $txtDetail = New-Object System.Windows.Forms.TextBox
    $txtDetail.Multiline = $true; $txtDetail.ReadOnly = $true; $txtDetail.ScrollBars = 'Vertical'
    $txtDetail.Dock = 'Bottom'; $txtDetail.Height = 100; $ui.txtDetail = $txtDetail
    $pnlFilter = New-Object System.Windows.Forms.Panel
    $pnlFilter.Dock = 'Top'; $pnlFilter.Height = 34
    $lblF = New-Object System.Windows.Forms.Label
    $lblF.Text = 'Tìm:'; $lblF.Location = New-Object System.Drawing.Point(8, 9); $lblF.AutoSize = $true
    $txtFilter = New-Object System.Windows.Forms.TextBox
    $txtFilter.Location = New-Object System.Drawing.Point(45, 6); $txtFilter.Width = 320; $ui.txtFilter = $txtFilter
    $cboLevel = New-Object System.Windows.Forms.ComboBox
    $cboLevel.DropDownStyle = 'DropDownList'; $cboLevel.Location = New-Object System.Drawing.Point(380, 6); $cboLevel.Width = 150
    [void]$cboLevel.Items.AddRange(@('Tất cả mức độ', 'Cao', 'Trung bình', 'Thấp', 'Thông tin'))
    $cboLevel.SelectedIndex = 0; $ui.cboLevel = $cboLevel
    $pnlFilter.Controls.AddRange(@($lblF, $txtFilter, $cboLevel))
    $tpEv.Controls.Add($gEv); $tpEv.Controls.Add($txtDetail); $tpEv.Controls.Add($pnlFilter)
    $txtFilter.Add_TextChanged({ Update-EventFilter })
    $cboLevel.Add_SelectedIndexChanged({ Update-EventFilter })
    $gEv.Add_SelectionChanged({
        param($s, $e)
        try {
            if ($s.CurrentRow -and $s.Columns.Contains('NoiDung')) {
                $script:ui.txtDetail.Text = [string]$s.CurrentRow.Cells['NoiDung'].Value
            }
        } catch {}
    })

    # ----- Thanh trên cùng -----
    $top = New-Object System.Windows.Forms.Panel
    $top.Dock = 'Top'; $top.Height = 92; $top.BackColor = [System.Drawing.Color]::FromArgb(238, 243, 250)

    $mk = {
        param($type, $text, $x, $y, $w, $h)
        $c = New-Object $type
        $c.Text = $text
        $c.Location = New-Object System.Drawing.Point($x, $y)
        $c.Size = New-Object System.Drawing.Size($w, $h)
        return $c
    }
    $lb1 = & $mk 'System.Windows.Forms.Label' 'Máy tính:' 10 15 65 20
    $txtPC = & $mk 'System.Windows.Forms.TextBox' $script:LocalName 78 12 250 24
    $ui.txtPC = $txtPC
    $tip = New-Object System.Windows.Forms.ToolTip
    $tip.SetToolTip($txtPC, 'Nhiều máy: cách nhau bằng dấu phẩy. Máy từ xa cần quyền Admin và bật Remote Event Log Management.')
    $lb2 = & $mk 'System.Windows.Forms.Label' 'Từ:' 345 15 30 20
    $dtFrom = New-Object System.Windows.Forms.DateTimePicker
    $dtFrom.Format = 'Custom'; $dtFrom.CustomFormat = 'dd/MM/yyyy HH:mm'
    $dtFrom.Location = New-Object System.Drawing.Point(375, 12); $dtFrom.Width = 145
    $dtFrom.Value = (Get-Date).Date.AddDays(-30)
    $ui.dtFrom = $dtFrom
    $lb3 = & $mk 'System.Windows.Forms.Label' 'Đến:' 535 15 35 20
    $dtTo = New-Object System.Windows.Forms.DateTimePicker
    $dtTo.Format = 'Custom'; $dtTo.CustomFormat = 'dd/MM/yyyy HH:mm'
    $dtTo.Location = New-Object System.Drawing.Point(572, 12); $dtTo.Width = 145
    $dtTo.Value = Get-Date
    $ui.dtTo = $dtTo

    $quick = @(@('24 giờ', 24), @('7 ngày', 168), @('30 ngày', 720), @('90 ngày', 2160))
    $qx = 735
    foreach ($q in $quick) {
        $b = & $mk 'System.Windows.Forms.Button' $q[0] $qx 10 72 28
        $b.Tag = [int]$q[1]
        $b.Add_Click({
            param($s, $e)
            $script:ui.dtTo.Value = Get-Date
            $script:ui.dtFrom.Value = (Get-Date).AddHours(-1 * [int]$s.Tag)
        })
        $top.Controls.Add($b)
        $qx += 78
    }

    $btnRun = & $mk 'System.Windows.Forms.Button' 'Phân tích' 10 48 130 34
    $btnRun.BackColor = [System.Drawing.Color]::FromArgb(31, 78, 121); $btnRun.ForeColor = [System.Drawing.Color]::White
    $btnRun.FlatStyle = 'Flat'; $btnRun.Font = New-Object System.Drawing.Font('Segoe UI', 10, [System.Drawing.FontStyle]::Bold)
    $ui.btnRun = $btnRun
    $btnRun.Add_Click({ Invoke-Analysis })

    $btnStop = & $mk 'System.Windows.Forms.Button' 'Dừng' 148 48 70 34
    $btnStop.Enabled = $false; $ui.btnStop = $btnStop
    $btnStop.Add_Click({ $script:CancelRequested = $true })

    $btnCsv = & $mk 'System.Windows.Forms.Button' 'Xuất CSV' 232 48 100 34
    $btnCsv.Add_Click({
        if (-not $script:State.Ready) { [void][System.Windows.Forms.MessageBox]::Show('Chưa có dữ liệu. Hãy bấm Phân tích trước.', $script:AppName, 'OK', 'Information'); return }
        $fbd = New-Object System.Windows.Forms.FolderBrowserDialog
        $fbd.Description = 'Chọn thư mục để lưu các file CSV'
        if ($fbd.ShowDialog() -eq 'OK') {
            try {
                $files = Export-CsvFiles -State $script:State -Folder $fbd.SelectedPath
                [void][System.Windows.Forms.MessageBox]::Show(("Đã lưu {0} file CSV vào:`r`n{1}" -f @($files).Count, $fbd.SelectedPath), $script:AppName, 'OK', 'Information')
                Start-Process $fbd.SelectedPath
            } catch { [void][System.Windows.Forms.MessageBox]::Show("Không lưu được: $($_.Exception.Message)", $script:AppName, 'OK', 'Error') }
        }
    })

    $btnHtml = & $mk 'System.Windows.Forms.Button' 'Xuất báo cáo HTML' 340 48 150 34
    $btnHtml.Add_Click({
        if (-not $script:State.Ready) { [void][System.Windows.Forms.MessageBox]::Show('Chưa có dữ liệu. Hãy bấm Phân tích trước.', $script:AppName, 'OK', 'Information'); return }
        $sfd = New-Object System.Windows.Forms.SaveFileDialog
        $sfd.Filter = 'Báo cáo HTML (*.html)|*.html'
        $sfd.FileName = 'BaoCao_EventLog_' + (Get-Date -Format 'yyyyMMdd_HHmm') + '.html'
        if ($sfd.ShowDialog() -eq 'OK') {
            try {
                Save-TextUtf8Bom -Path $sfd.FileName -Text (New-HtmlReport -State $script:State)
                Start-Process $sfd.FileName
            } catch { [void][System.Windows.Forms.MessageBox]::Show("Không lưu được: $($_.Exception.Message)", $script:AppName, 'OK', 'Error') }
        }
    })

    $progress = New-Object System.Windows.Forms.ProgressBar
    $progress.Location = New-Object System.Drawing.Point(510, 54); $progress.Size = New-Object System.Drawing.Size(320, 22)
    $ui.progress = $progress

    $top.Controls.AddRange(@($lb1, $txtPC, $lb2, $dtFrom, $lb3, $dtTo, $btnRun, $btnStop, $btnCsv, $btnHtml, $progress))

    # ----- Thanh trạng thái -----
    $status = New-Object System.Windows.Forms.StatusStrip
    $lblStatus = New-Object System.Windows.Forms.ToolStripStatusLabel
    $lblStatus.Text = 'Sẵn sàng.'
    [void]$status.Items.Add($lblStatus)
    $ui.lblStatus = $lblStatus

    # Thứ tự thêm: control Fill trước, rồi tới các control bám cạnh
    $form.Controls.Add($tabs)
    $form.Controls.Add($top)
    $form.Controls.Add($status)

    [void]$form.ShowDialog()
}

# ============================================================
#  CHẠY CHÍNH
# ============================================================
if (-not $NoGui) {
    try {
        Show-MainForm
    } catch {
        $msg = $_ | Out-String
        try {
            Add-Type -AssemblyName System.Windows.Forms
            [void][System.Windows.Forms.MessageBox]::Show("Ứng dụng gặp lỗi:`r`n$msg", $script:AppName, 'OK', 'Error')
        } catch {}
        [Console]::Error.WriteLine($msg)
    }
}
