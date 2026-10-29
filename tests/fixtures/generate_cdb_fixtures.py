"""
Tạo 10 file output !analyze -v mẫu làm fixtures để kiểm thử CdbParser mà không cần cdb.exe thật.
Bao gồm:
1. WHEA 0x124 (phần cứng CPU/Memory AuthenticAMD).
2. Driver IRQL 0xD1 với GPU NVIDIA (nvlddmkm.sys).
3. Driver IRQL 0xD1 với Card mạng Realtek (rt640x64.sys).
4. Memory Management 0x1A: IMAGE_NAME là ntoskrnl.exe (nạn nhân), stack chứa driver diệt virus klif.sys.
5. DPC Watchdog 0x133 với SSD NVMe (stornvme.sys).
6. Page Fault 0x50: ntoskrnl.exe, stack thuần tuý Microsoft (lỗi phần cứng RAM).
7. Output thiếu trường và thiếu symbols (Symbol file could not be found).
8. Kernel Security Check 0x139 với driver âm thanh rtkvhd64.sys.
9. Output hoàn chỉnh với vertarget, .time, lm t n và System Uptime.
10. Output bị gián đoạn do timeout.
"""

from pathlib import Path


def generate_all_fixtures():
    out_dir = Path(__file__).resolve().parent / "cdb_outputs"
    out_dir.mkdir(parents=True, exist_ok=True)

    # 1. whea_0x124.txt
    (out_dir / "whea_0x124.txt").write_text(
        "Microsoft (R) Windows Debugger Version 10.0.22621.1 AMD64\n"
        "Loading Dump File [C:\\dumps\\whea.dmp]\n"
        "Debug session time: Tue Oct 20 10:00:00.123 2026 (UTC + 7:00)\n"
        "System Uptime: 2 days 4:15:30.000\n\n"
        "WHEA_UNCORRECTABLE_ERROR (124)\n"
        "A fatal hardware error has occurred.\n"
        "Arguments:\n"
        "Arg1: 0000000000000000, Machine Check Exception\n"
        "Arg2: ffff800012345678, Address of the nt!_WHEA_ERROR_RECORD structure.\n"
        "Arg3: b200000000000000, High order 32-bits of the MCi_STATUS value.\n"
        "Arg4: 0000000000000175, Low order 32-bits of the MCi_STATUS value.\n\n"
        "BUGCHECK_CODE: 124\n"
        "BUGCHECK_P1: 0\n"
        "BUGCHECK_P2: ffff800012345678\n"
        "BUGCHECK_P3: b200000000000000\n"
        "BUGCHECK_P4: 175\n\n"
        "PROCESS_NAME: System\n"
        "IMAGE_NAME: AuthenticAMD.sys\n"
        "MODULE_NAME: AuthenticAMD\n"
        "FAILURE_BUCKET_ID: 0x124_AuthenticAMD_MEMORY__UNKNOWN_FATAL\n\n"
        "STACK_TEXT:\n"
        "ffff8000`11111111 fffff800`22222222 nt!KeBugCheckEx+0x0\n"
        "ffff8000`11111119 fffff800`33333333 nt!HalpMcaReportError+0x100\n"
        "ffff8000`11111120 fffff800`44444444 AuthenticAMD+0x1234\n"
        "ffff8000`11111128 fffff800`55555555 nt!HalHandleMcheck+0x50\n\n"
        "start             end                 module name\n"
        "fffff800`20000000 fffff800`21000000   nt\n"
        "fffff800`22000000 fffff800`22050000   AuthenticAMD\n",
        encoding="utf-8",
    )

    # 2. gpu_nvidia_0xd1.txt
    (out_dir / "gpu_nvidia_0xd1.txt").write_text(
        "DRIVER_IRQL_NOT_LESS_OR_EQUAL (d1)\n"
        "An attempt was made to access a pageable address at high IRQL.\n"
        "Arguments:\n"
        "Arg1: 0000000000000028\n"
        "Arg2: 0000000000000002\n"
        "Arg3: 0000000000000000\n"
        "Arg4: fffff801456789ab\n\n"
        "BUGCHECK_CODE: d1\n"
        "BUGCHECK_P1: 28\n"
        "BUGCHECK_P2: 2\n"
        "BUGCHECK_P3: 0\n"
        "BUGCHECK_P4: fffff801456789ab\n\n"
        "PROCESS_NAME: dwm.exe\n"
        "IMAGE_NAME: nvlddmkm.sys\n"
        "MODULE_NAME: nvlddmkm\n"
        "FAILURE_BUCKET_ID: AV_nvlddmkm!unknown_function\n\n"
        "STACK_TEXT:\n"
        "fffff801`11111111 fffff800`00000000 nt!KeBugCheckEx\n"
        "fffff801`11111119 fffff801`456789ab nt!KiPageFault+0x440\n"
        "fffff801`11111120 fffff801`45678000 nvlddmkm+0x12345\n"
        "fffff801`11111128 fffff801`45670000 nvlddmkm+0x45678\n"
        "fffff801`11111130 fffff800`11111111 dxgkrnl!DxgkSubmitCommandVirtual+0x200\n",
        encoding="utf-8",
    )

    # 3. network_realtek_0xd1.txt
    (out_dir / "network_realtek_0xd1.txt").write_text(
        "DRIVER_IRQL_NOT_LESS_OR_EQUAL (d1)\n"
        "BUGCHECK_CODE: d1\n"
        "BUGCHECK_P1: 10\n"
        "BUGCHECK_P2: 2\n"
        "BUGCHECK_P3: 1\n"
        "BUGCHECK_P4: fffff80212340000\n\n"
        "PROCESS_NAME: System\n"
        "IMAGE_NAME: rt640x64.sys\n"
        "MODULE_NAME: rt640x64\n"
        "FAILURE_BUCKET_ID: 0xD1_rt640x64!ProcessTxPacket\n\n"
        "STACK_TEXT:\n"
        "fffff802`00000000 fffff800`00000000 nt!KeBugCheckEx\n"
        "fffff802`00000008 fffff802`12340000 rt640x64+0x23456\n"
        "fffff802`00000010 fffff800`11111111 ndis!ndisSendNetBufferLists+0x50\n",
        encoding="utf-8",
    )

    # 4. mem_management_ms_ntoskrnl_with_antivirus.txt
    (out_dir / "mem_management_ms_ntoskrnl_with_antivirus.txt").write_text(
        "MEMORY_MANAGEMENT (1a)\n"
        "Arguments:\n"
        "Arg1: 0000000000041792, A corrupted PTE has been detected.\n"
        "Arg2: fffff00000000000\n"
        "Arg3: 0000000000000001\n"
        "Arg4: 0000000000000000\n\n"
        "BUGCHECK_CODE: 1a\n"
        "BUGCHECK_P1: 41792\n"
        "BUGCHECK_P2: fffff00000000000\n"
        "BUGCHECK_P3: 1\n"
        "BUGCHECK_P4: 0\n\n"
        "PROCESS_NAME: avp.exe\n"
        "IMAGE_NAME: ntoskrnl.exe\n"
        "MODULE_NAME: nt\n"
        "FAILURE_BUCKET_ID: 0x1a_41792_nt!MiDeleteVa\n\n"
        "STACK_TEXT:\n"
        "fffff800`11111111 fffff800`22222222 nt!KeBugCheckEx\n"
        "fffff800`11111119 fffff800`33333333 nt!MiDeleteVa+0x120\n"
        "fffff800`11111120 fffff803`44444444 klif.sys+0x12345\n"
        "fffff800`11111128 fffff800`55555555 fltmgr!FltpPerformPreCallbacks+0x80\n",
        encoding="utf-8",
    )

    # 5. dpc_watchdog_ssd_0x133.txt
    (out_dir / "dpc_watchdog_ssd_0x133.txt").write_text(
        "DPC_WATCHDOG_VIOLATION (133)\n"
        "BUGCHECK_CODE: 133\n"
        "BUGCHECK_P1: 1\n"
        "BUGCHECK_P2: 1e00\n"
        "BUGCHECK_P3: 0\n"
        "BUGCHECK_P4: 0\n\n"
        "PROCESS_NAME: System\n"
        "IMAGE_NAME: stornvme.sys\n"
        "MODULE_NAME: stornvme\n"
        "FAILURE_BUCKET_ID: 0x133_DPC_stornvme!ProcessInterrupt\n\n"
        "STACK_TEXT:\n"
        "fffff800`00000000 fffff800`11111111 nt!KeBugCheckEx\n"
        "fffff800`00000008 fffff804`22222222 stornvme+0x15432\n"
        "fffff800`00000010 fffff800`33333333 storport!StorPortNotification+0x100\n",
        encoding="utf-8",
    )

    # 6. pagefault_pure_hardware_0x50.txt
    (out_dir / "pagefault_pure_hardware_0x50.txt").write_text(
        "PAGE_FAULT_IN_NONPAGED_AREA (50)\n"
        "BUGCHECK_CODE: 50\n"
        "BUGCHECK_P1: fffff800deadbeef\n"
        "BUGCHECK_P2: 0\n"
        "BUGCHECK_P3: fffff80012345678\n"
        "BUGCHECK_P4: 2\n\n"
        "PROCESS_NAME: svchost.exe\n"
        "IMAGE_NAME: ntoskrnl.exe\n"
        "MODULE_NAME: nt\n"
        "FAILURE_BUCKET_ID: AV_R_INVALID_nt!MiSystemFault\n\n"
        "STACK_TEXT:\n"
        "fffff800`00000000 fffff800`11111111 nt!KeBugCheckEx\n"
        "fffff800`00000008 fffff800`22222222 nt!MiSystemFault+0x200\n"
        "fffff800`00000010 fffff800`33333333 nt!MmAccessFault+0x50\n"
        "fffff800`00000018 fffff800`44444444 hal!HalpApicInterrupt+0x20\n",
        encoding="utf-8",
    )

    # 7. missing_fields_no_symbols.txt
    (out_dir / "missing_fields_no_symbols.txt").write_text(
        "Microsoft (R) Windows Debugger Version 10.0.22621.1 AMD64\n"
        "*** ERROR: Symbol file could not be found.\n\n"
        "BUGCHECK_CODE: 3b\n"
        "BUGCHECK_P1: c0000005\n"
        "BUGCHECK_P2: fffff80000001234\n"
        "BUGCHECK_P3: fffff80000005678\n"
        "BUGCHECK_P4: 0\n\n"
        "IMAGE_NAME: unknown_image\n"
        "FAILURE_BUCKET_ID: NULL_CLASS\n",
        encoding="utf-8",
    )

    # 8. kernel_security_audio_0x139.txt
    (out_dir / "kernel_security_audio_0x139.txt").write_text(
        "KERNEL_SECURITY_CHECK_FAILURE (139)\n"
        "BUGCHECK_CODE: 139\n"
        "BUGCHECK_P1: 3\n"
        "BUGCHECK_P2: 0\n"
        "BUGCHECK_P3: 1\n"
        "BUGCHECK_P4: 0\n\n"
        "PROCESS_NAME: audiodg.exe\n"
        "IMAGE_NAME: rtkvhd64.sys\n"
        "MODULE_NAME: rtkvhd64\n"
        "FAILURE_BUCKET_ID: 0x139_3_CORRUPT_LIST_ENTRY_rtkvhd64!AudioProcess\n\n"
        "STACK_TEXT:\n"
        "ffff8000`00000000 fffff800`11111111 nt!KeBugCheckEx\n"
        "ffff8000`00000008 fffff805`12345678 rtkvhd64+0x43210\n"
        "ffff8000`00000010 fffff800`22222222 portcls!PcDispatchProperty+0x80\n",
        encoding="utf-8",
    )

    # 9. complete_output_with_vertarget_time_lm.txt
    (out_dir / "complete_output_with_vertarget_time_lm.txt").write_text(
        "Windows 10 Kernel Version 19045 MP (12 procs) Free x64\n"
        "Debug session time: Wed Oct 28 14:20:10.500 2026 (UTC + 7:00)\n"
        "System Uptime: 5 days 12:30:45.123\n\n"
        "BUGCHECK_CODE: 9f\n"
        "BUGCHECK_P1: 3\n"
        "BUGCHECK_P2: ffff900012345678\n"
        "BUGCHECK_P3: ffff900087654321\n"
        "BUGCHECK_P4: ffff900011111111\n\n"
        "PROCESS_NAME: System\n"
        "IMAGE_NAME: pci.sys\n"
        "MODULE_NAME: pci\n"
        "FAILURE_BUCKET_ID: 0x9F_3_POWER_TIMEOUT_pci!PciPowerDispatch\n\n"
        "STACK_TEXT:\n"
        "ffff9000`00000000 fffff800`00000000 nt!KeBugCheckEx\n"
        "ffff9000`00000008 fffff800`11111111 nt!PopIrpWatchdogBugcheck+0x100\n"
        "ffff9000`00000010 fffff806`22222222 pci+0x12345\n\n"
        "start             end                 module name\n"
        "fffff800`00000000 fffff800`01000000   nt\n"
        "fffff806`22000000 fffff806`22050000   pci\n",
        encoding="utf-8",
    )

    # 10. partial_timeout_output.txt
    (out_dir / "partial_timeout_output.txt").write_text(
        "Microsoft (R) Windows Debugger Version 10.0.22621.1 AMD64\n"
        "Loading symbols...\n"
        "BUGCHECK_CODE: 133\n"
        "BUGCHECK_P1: 1\n"
        "PROCESS_NAME: System\n"
        "[COMMAND TIMEOUT REACHED AFTER 300 SECONDS]\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    generate_all_fixtures()
    print("Done generating 10 cdb output fixtures.")
