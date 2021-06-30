## Table of Contents <!-- omit in toc -->

- [1. Introduction](#1-introduction)
  - [1.1. Reserved Values](#11-reserved-values)
  - [1.2. Document Revision](#12-document-revision)
  - [1.3. Glossary](#13-glossary)
  - [1.4. Scalar Types](#14-scalar-types)
  - [1.5. ID Types](#15-id-types)
  - [1.6. Constants, Structures, Enumerations, and Bit Fields](#16-constants-structures-enumerations-and-bit-fields)
    - [1.6.1. Null](#161-null)
    - [1.6.2. Handle Type](#162-handle-type)
    - [1.6.3. Register Type](#163-register-type)
    - [1.6.4. Exit Type](#164-exit-type)
    - [1.6.5. Bootstrap Callback Handler Type](#165-bootstrap-callback-handler-type)
    - [1.6.6. VMExit Callback Handler Type](#166-vmexit-callback-handler-type)
    - [1.6.7. Fast Fail Callback Handler Type](#167-fast-fail-callback-handler-type)
  - [1.7. Invalid ID](#17-invalid-id)
  - [1.8. Host PAT (Intel/AMD Only)](#18-host-pat-intelamd-only)
  - [1.9. Endianness](#19-endianness)
- [2. Syscall Interface](#2-syscall-interface)
  - [2.1. Legal Syscall Environments](#21-legal-syscall-environments)
  - [2.2. Syscall Status Codes](#22-syscall-status-codes)
    - [2.2.1. BF_STATUS_SUCCESS, VALUE=0](#221-bf_status_success-value0)
    - [2.2.2. BF_STATUS_FAILURE, VALUE=1](#222-bf_status_failure-value1)
    - [2.2.3. BF_STATUS_INVALID_PERM, VALUE=2](#223-bf_status_invalid_perm-value2)
    - [2.2.4. BF_STATUS_INVALID_PARAMS, VALUE=3](#224-bf_status_invalid_params-value3)
  - [2.3. Syscall Inputs](#23-syscall-inputs)
  - [2.4. Syscall Outputs](#24-syscall-outputs)
  - [2.5. Syscall Opcodes](#25-syscall-opcodes)
    - [2.5.1. Control Support](#251-control-support)
    - [2.5.2. Handle Support](#252-handle-support)
    - [2.5.3. Debug Support](#253-debug-support)
    - [2.5.4. Callback Support](#254-callback-support)
    - [2.5.5. VM Support](#255-vm-support)
    - [2.5.6. VP Support](#256-vp-support)
    - [2.5.7. VPS Support](#257-vps-support)
    - [2.5.8. Intrinsic Support](#258-intrinsic-support)
    - [2.5.9. Mem Support](#259-mem-support)
    - [2.5.10. Syscall Specification IDs](#2510-syscall-specification-ids)
  - [2.6. Thread Local Storage](#26-thread-local-storage)
    - [2.6.1. TLS Offsets](#261-tls-offsets)
  - [2.7. Control Syscalls](#27-control-syscalls)
    - [2.7.1. bf_control_op_exit, OP=0x0, IDX=0x0](#271-bf_control_op_exit-op0x0-idx0x0)
    - [2.10.1. bf_control_op_wait, OP=0x0, IDX=0x1](#2101-bf_control_op_wait-op0x0-idx0x1)
  - [2.8. Handle Syscalls](#28-handle-syscalls)
    - [2.8.1. bf_handle_op_open_handle, OP=0x1, IDX=0x0](#281-bf_handle_op_open_handle-op0x1-idx0x0)
    - [2.8.2. bf_handle_op_close_handle, OP=0x1, IDX=0x1](#282-bf_handle_op_close_handle-op0x1-idx0x1)
  - [2.9. Debug Syscalls](#29-debug-syscalls)
    - [2.9.1. bf_debug_op_out, OP=0x2, IDX=0x0](#291-bf_debug_op_out-op0x2-idx0x0)
    - [2.9.2. bf_debug_op_dump_vm, OP=0x2, IDX=0x1](#292-bf_debug_op_dump_vm-op0x2-idx0x1)
    - [2.9.3. bf_debug_op_dump_vp, OP=0x2, IDX=0x2](#293-bf_debug_op_dump_vp-op0x2-idx0x2)
    - [2.9.4. bf_debug_op_dump_vps, OP=0x2, IDX=0x3](#294-bf_debug_op_dump_vps-op0x2-idx0x3)
    - [2.9.5. bf_debug_op_dump_vmexit_log, OP=0x2, IDX=0x4](#295-bf_debug_op_dump_vmexit_log-op0x2-idx0x4)
    - [2.9.6. bf_debug_op_write_c, OP=0x2, IDX=0x5](#296-bf_debug_op_write_c-op0x2-idx0x5)
    - [2.9.7. bf_debug_op_write_str, OP=0x2, IDX=0x6](#297-bf_debug_op_write_str-op0x2-idx0x6)
    - [2.9.8. bf_debug_op_dump_ext, OP=0x2, IDX=0x7](#298-bf_debug_op_dump_ext-op0x2-idx0x7)
    - [2.9.9. bf_debug_op_dump_page_pool, OP=0x2, IDX=0x8](#299-bf_debug_op_dump_page_pool-op0x2-idx0x8)
    - [2.9.10. bf_debug_op_dump_huge_pool, OP=0x2, IDX=0x9](#2910-bf_debug_op_dump_huge_pool-op0x2-idx0x9)
  - [2.10. Callback Syscalls](#210-callback-syscalls)
    - [2.10.2. bf_callback_op_register_bootstrap, OP=0x3, IDX=0x2](#2102-bf_callback_op_register_bootstrap-op0x3-idx0x2)
    - [2.10.3. bf_callback_op_register_vmexit, OP=0x3, IDX=0x3](#2103-bf_callback_op_register_vmexit-op0x3-idx0x3)
    - [2.10.4. bf_callback_op_register_fail, OP=0x3, IDX=0x4](#2104-bf_callback_op_register_fail-op0x3-idx0x4)
  - [2.11. Virtual Machine Syscalls](#211-virtual-machine-syscalls)
    - [2.11.1. Virtual Machine ID (VMID)](#2111-virtual-machine-id-vmid)
    - [2.11.2. bf_vm_op_create_vm, OP=0x4, IDX=0x0](#2112-bf_vm_op_create_vm-op0x4-idx0x0)
    - [2.11.3. bf_vm_op_destroy_vm, OP=0x4, IDX=0x1](#2113-bf_vm_op_destroy_vm-op0x4-idx0x1)
  - [2.12. Virtual Processor Syscalls](#212-virtual-processor-syscalls)
    - [2.12.1. Virtual Processor ID (VPID)](#2121-virtual-processor-id-vpid)
    - [2.12.2. bf_vp_op_create_vp, OP=0x5, IDX=0x0](#2122-bf_vp_op_create_vp-op0x5-idx0x0)
    - [2.12.3. bf_vp_op_destroy_vp, OP=0x5, IDX=0x1](#2123-bf_vp_op_destroy_vp-op0x5-idx0x1)
    - [2.12.3. bf_vp_op_migrate, OP=0x5, IDX=0x2](#2123-bf_vp_op_migrate-op0x5-idx0x2)
    - [2.12.4. Virtual Processor State Syscalls](#2124-virtual-processor-state-syscalls)
    - [2.12.5. Virtual Processor State ID (VPSID)](#2125-virtual-processor-state-id-vpsid)
    - [2.12.6. bf_vps_op_create_vps, OP=0x6, IDX=0x0](#2126-bf_vps_op_create_vps-op0x6-idx0x0)
    - [2.12.7. bf_vps_op_destroy_vps, OP=0x6, IDX=0x1](#2127-bf_vps_op_destroy_vps-op0x6-idx0x1)
    - [2.12.8. bf_vps_op_init_as_root, OP=0x6, IDX=0x2](#2128-bf_vps_op_init_as_root-op0x6-idx0x2)
    - [2.12.9. bf_vps_op_read8, OP=0x6, IDX=0x3](#2129-bf_vps_op_read8-op0x6-idx0x3)
    - [2.12.10. bf_vps_op_read16, OP=0x6, IDX=0x4](#21210-bf_vps_op_read16-op0x6-idx0x4)
    - [2.12.11. bf_vps_op_read32, OP=0x6, IDX=0x5](#21211-bf_vps_op_read32-op0x6-idx0x5)
    - [2.12.12. bf_vps_op_read64, OP=0x6, IDX=0x6](#21212-bf_vps_op_read64-op0x6-idx0x6)
    - [2.12.13. bf_vps_op_write8, OP=0x6, IDX=0x7](#21213-bf_vps_op_write8-op0x6-idx0x7)
    - [2.12.14. bf_vps_op_write16, OP=0x6, IDX=0x8](#21214-bf_vps_op_write16-op0x6-idx0x8)
    - [2.12.15. bf_vps_op_write32, OP=0x6, IDX=0x9](#21215-bf_vps_op_write32-op0x6-idx0x9)
    - [2.12.16. bf_vps_op_write64, OP=0x6, IDX=0xA](#21216-bf_vps_op_write64-op0x6-idx0xa)
    - [2.12.17. bf_vps_op_read_reg, OP=0x6, IDX=0xB](#21217-bf_vps_op_read_reg-op0x6-idx0xb)
    - [2.12.18. bf_vps_op_write_reg, OP=0x6, IDX=0xC](#21218-bf_vps_op_write_reg-op0x6-idx0xc)
    - [2.12.19. bf_vps_op_run, OP=0x5, IDX=0xD](#21219-bf_vps_op_run-op0x5-idx0xd)
    - [2.12.20. bf_vps_op_run_current, OP=0x5, IDX=0xE](#21220-bf_vps_op_run_current-op0x5-idx0xe)
    - [2.12.21. bf_vps_op_advance_ip, OP=0x5, IDX=0xF](#21221-bf_vps_op_advance_ip-op0x5-idx0xf)
    - [2.12.22. bf_vps_op_advance_ip_and_run_current, OP=0x5, IDX=0x10](#21222-bf_vps_op_advance_ip_and_run_current-op0x5-idx0x10)
    - [2.12.23. bf_vps_op_promote, OP=0x5, IDX=0x11](#21223-bf_vps_op_promote-op0x5-idx0x11)
    - [2.12.24. bf_vps_op_clear_vps, OP=0x5, IDX=0x11](#21224-bf_vps_op_clear_vps-op0x5-idx0x11)
  - [2.13. Intrinsic Syscalls](#213-intrinsic-syscalls)
    - [2.13.1. bf_intrinsic_op_rdmsr, OP=0x7, IDX=0x0](#2131-bf_intrinsic_op_rdmsr-op0x7-idx0x0)
    - [2.13.2. bf_intrinsic_op_wrmsr, OP=0x7, IDX=0x1](#2132-bf_intrinsic_op_wrmsr-op0x7-idx0x1)
    - [2.13.3. bf_intrinsic_op_invlpga, OP=0x7, IDX=0x2](#2133-bf_intrinsic_op_invlpga-op0x7-idx0x2)
    - [2.13.4. bf_intrinsic_op_invept, OP=0x7, IDX=0x3](#2134-bf_intrinsic_op_invept-op0x7-idx0x3)
    - [2.13.5. bf_intrinsic_op_invvpid, OP=0x7, IDX=0x4](#2135-bf_intrinsic_op_invvpid-op0x7-idx0x4)
  - [2.14. Mem Syscalls](#214-mem-syscalls)
    - [2.14.1. bf_mem_op_alloc_page, OP=0x7, IDX=0x0](#2141-bf_mem_op_alloc_page-op0x7-idx0x0)
    - [2.14.2. bf_mem_op_free_page, OP=0x7, IDX=0x1](#2142-bf_mem_op_free_page-op0x7-idx0x1)
    - [2.14.3. bf_mem_op_alloc_huge, OP=0x7, IDX=0x2](#2143-bf_mem_op_alloc_huge-op0x7-idx0x2)
    - [2.14.4. bf_mem_op_free_huge, OP=0x7, IDX=0x3](#2144-bf_mem_op_free_huge-op0x7-idx0x3)
    - [2.14.5. bf_mem_op_alloc_heap, OP=0x7, IDX=0x4](#2145-bf_mem_op_alloc_heap-op0x7-idx0x4)

# 1. Introduction

TBD

This specification is specific to 64bit Intel and AMD processors conforming to the amd64 specification. Future revisions of this specification may include ARM64 conforming to the aarch64 specification as well.

## 1.1. Reserved Values

| Name | Description |
| :--- | :---------- |
| REVZ | reserved zero |
| REVI | reserved ignore |

## 1.2. Document Revision

| Version | Description |
| :------ | :---------- |
| Mk#1 | The initial version of this specification |

## 1.3. Glossary

| Abbreviation | Description |
| :----------- | :---------- |
| VM | Virtual Machine |
| VP | Virtual Processor |
| VPS | Virtual Processor State |
| PP | Physical Processor |
| VMID | Virtual Machine Identifier |
| VPID | Virtual Processor Identifier |
| VPSID | Virtual Processor State Identifier |
| PPID | Physical Processor Identifier |
| OS | Operating System |
| BIOS | Basic Input/Output System |
| UEFI | Unified Extensible Firmware Interface |
| SPA | A System Physical Address (SPA) refers to a physical address as seen by the system without the addition of virtualization |
| GPA | A Guest Physical Address (GPA) refers to a physical address as seen by a VM and requires a translation to convert to a SPA |
| GVA | A Guest Virtual Address (GVA) refers to a virtual address as seen by a VM and requires a guest controlled translation to convert to a GPA |
| Page Aligned | A region of memory whose address is divisible by 0x1000 |
| Page | A page aligned region of memory that is 0x1000 bytes in size |

## 1.4. Scalar Types

| Name | Type | Description |
| :--- | :--- | :-----------|
| bf_status_t | uint64_t | Defines the type used for returning status from a function |
| bf_uint8_t | uint8_t | Defines an unsigned 8bit integer |
| bf_uint16_t | uint16_t | Defines an unsigned 16bit integer |
| bf_uint32_t | uint32_t | Defines an unsigned 32bit integer |
| bf_uint64_t | uint64_t | Defines an unsigned 64bit integer |
| bf_ptr_t | void * | Defines a raw pointer type |
| bf_cptr_t | void const * | Defines a raw const pointer type |

## 1.5. ID Types

| Name | Type |
| :--- | :--- |
| Virtual Machine ID (VMID) | bf_uint64_t |
| Virtual Processor ID (VPID) | bf_uint64_t |
| Virtual Processor State ID (VPSID) | bf_uint64_t |
| Physical Processor ID (PPID) | bf_uint64_t |

## 1.6. Constants, Structures, Enumerations, and Bit Fields

### 1.6.1. Null

**const, void *: BF_NULL**
| Value | Description |
| :---- | :---------- |
| 0 | Defines the value of a null pointer |

### 1.6.2. Handle Type

The bf_handle_t structure is an opaque structure containing the handle used by most of the syscalls in this specification. The opaque structure is used internally by the C wrapper interface and should not be accessed directly. The C wrapper is allowed to redefine the internal layout of this structure at any time (e.g., the C wrapper might provide an alternative layout for unit testing).

**struct: bf_handle_t**
| Name | Type | Offset | Size | Description |
| :--- | :--- | :----- | :--- | :---------- |
| hndl | bf_uint64_t | 0x0 | 8 bytes | The handle returned by bf_handle_op_open_handle |

### 1.6.3. Register Type

Defines which register a syscall is requesting.

**enum, bf_uint64_t: bf_reg_t**
| Name | Value | Description |
| :--- | :---- | :---------- |
| bf_reg_t_rax | 0 | defines the rax register |
| bf_reg_t_rbx | 1 | defines the rbx register |
| bf_reg_t_rcx | 2 | defines the rcx register |
| bf_reg_t_rdx | 3 | defines the rdx register |
| bf_reg_t_rbp | 4 | defines the rbp register |
| bf_reg_t_rsi | 5 | defines the rsi register |
| bf_reg_t_rdi | 6 | defines the rdi register |
| bf_reg_t_r8 | 7 | defines the r8 register |
| bf_reg_t_r9 | 8 | defines the r9 register |
| bf_reg_t_r10 | 9 | defines the r10 register |
| bf_reg_t_r11 | 10 | defines the r11 register |
| bf_reg_t_r12 | 11 | defines the r12 register |
| bf_reg_t_r13 | 12 | defines the r13 register |
| bf_reg_t_r14 | 13 | defines the r14 register |
| bf_reg_t_r15 | 14 | defines the r15 register |
| bf_reg_t_rip | 15 | defines the rip register |
| bf_reg_t_rsp | 16 | defines the rsp register |
| bf_reg_t_rflags | 17 | defines the rflags register |
| bf_reg_t_gdtr_base_addr | 18 | defines the gdtr_base_addr register |
| bf_reg_t_gdtr_limit | 19 | defines the gdtr_limit register |
| bf_reg_t_idtr_base_addr | 20 | defines the idtr_base_addr register |
| bf_reg_t_idtr_limit | 21 | defines the idtr_limit register |
| bf_reg_t_es | 22 | defines the es register |
| bf_reg_t_es_base_addr | 23 | defines the es_base_addr register |
| bf_reg_t_es_limit | 24 | defines the es_limit register |
| bf_reg_t_es_attributes | 25 | defines the es_attributes register |
| bf_reg_t_cs | 26 | defines the cs register |
| bf_reg_t_cs_base_addr | 27 | defines the cs_base_addr register |
| bf_reg_t_cs_limit | 28 | defines the cs_limit register |
| bf_reg_t_cs_attributes | 29 | defines the cs_attributes register |
| bf_reg_t_ss | 30 | defines the ss register |
| bf_reg_t_ss_base_addr | 31 | defines the ss_base_addr register |
| bf_reg_t_ss_limit | 32 | defines the ss_limit register |
| bf_reg_t_ss_attributes | 33 | defines the ss_attributes register |
| bf_reg_t_ds | 34 | defines the ds register |
| bf_reg_t_ds_base_addr | 35 | defines the ds_base_addr register |
| bf_reg_t_ds_limit | 36 | defines the ds_limit register |
| bf_reg_t_ds_attributes | 37 | defines the ds_attributes register |
| bf_reg_t_fs | 38 | defines the fs register |
| bf_reg_t_fs_base_addr | 39 | defines the fs_base_addr register |
| bf_reg_t_fs_limit | 40 | defines the fs_limit register |
| bf_reg_t_fs_attributes | 41 | defines the fs_attributes register |
| bf_reg_t_gs | 42 | defines the gs register |
| bf_reg_t_gs_base_addr | 43 | defines the gs_base_addr register |
| bf_reg_t_gs_limit | 44 | defines the gs_limit register |
| bf_reg_t_gs_attributes | 45 | defines the gs_attributes register |
| bf_reg_t_ldtr | 46 | defines the ldtr register |
| bf_reg_t_ldtr_base_addr | 47 | defines the ldtr_base_addr register |
| bf_reg_t_ldtr_limit | 48 | defines the ldtr_limit register |
| bf_reg_t_ldtr_attributes | 49 | defines the ldtr_attributes register |
| bf_reg_t_tr | 50 | defines the tr register |
| bf_reg_t_tr_base_addr | 51 | defines the tr_base_addr register |
| bf_reg_t_tr_limit | 52 | defines the tr_limit register |
| bf_reg_t_tr_attributes | 53 | defines the tr_attributes register |
| bf_reg_t_cr0 | 54 | defines the cr0 register |
| bf_reg_t_cr2 | 55 | defines the cr2 register |
| bf_reg_t_cr3 | 56 | defines the cr3 register |
| bf_reg_t_cr4 | 57 | defines the cr4 register |
| bf_reg_t_dr6 | 58 | defines the dr6 register |
| bf_reg_t_dr7 | 59 | defines the dr7 register |
| bf_reg_t_ia32_efer | 60 | defines the ia32_efer register |
| bf_reg_t_ia32_star | 61 | defines ia32_star register |
| bf_reg_t_ia32_lstar | 62 | defines ia32_lstar register |
| bf_reg_t_ia32_cstar | 63 | defines ia32_cstar register |
| bf_reg_t_ia32_fmask | 64 | defines ia32_fmask register |
| bf_reg_t_ia32_fs_base | 65 | defines ia32_fs_base register |
| bf_reg_t_ia32_gs_base | 66 | defines ia32_gs_base register |
| bf_reg_t_ia32_kernel_gs_base | 67 | defines ia32_kernel_gs_base register |
| bf_reg_t_ia32_sysenter_cs | 68 | defines ia32_sysenter_cs register |
| bf_reg_t_ia32_sysenter_esp | 69 | defines ia32_sysenter_esp register |
| bf_reg_t_ia32_sysenter_eip | 70 | defines ia32_sysenter_eip register |
| bf_reg_t_ia32_pat | 71 | defines ia32_pat register |
| bf_reg_t_ia32_debugctl | 72 | defines ia32_debugctl register |

### 1.6.4. Exit Type

Defines the exit type used by bf_control_op_exit

**enum, bf_uint64_t: bf_exit_status_t**
| Name | Value | Description |
| :--- | :---- | :---------- |
| bf_exit_status_t_success | 0 | Exit with a success code |
| bf_exit_status_t_failure | 1 | Exit with a failure code |

### 1.6.5. Bootstrap Callback Handler Type

Defines the signature of the bootstrap callback handler

**typedef, void(*bf_callback_handler_bootstrap_t)(bf_uint16_t)**

### 1.6.6. VMExit Callback Handler Type

Defines the signature of the VM exit callback handler

**typedef, void(*bf_callback_handler_vmexit_t)(bsl::bf_uint16_t, bf_uint64_t)**

### 1.6.7. Fast Fail Callback Handler Type

Defines the signature of the fast fail callback handler

**typedef, void(*bf_callback_handler_fail_t)(bf_status_t)**

## 1.7. Invalid ID

The following defines an invalid ID which can be used for all ID types.

**const, bf_uint16_t: BF_INVALID_ID**
| Value | Description |
| :---- | :---------- |
| 0xFFFF | Defines an invalid ID for an extension, VM, VP and VPS |

**const, bf_uint16_t: BF_BS_PPID**
| Value | Description |
| :---- | :---------- |
| 0x0 | Defines the bootstrap physical processor ID |

**const, bf_uint16_t: BF_ROOT_VMID**
| Value | Description |
| :---- | :---------- |
| 0x0 | Defines the root virtual machine ID |

## 1.8. Host PAT (Intel/AMD Only)

The host PAT has the following layout. Indexes marked as XX are reserved for future use.

**const, bf_uint64_t: BF_HOST_PAT**
| Value | Description |
| :---- | :---------- |
| 0xXXXXXXXX00XXXX06 | Defines the host PAT value |

## 1.9. Endianness

This document only applies to 64bit Intel and AMD systems conforming to the amd64 architecture. As such, this document conforms to little-endian.

# 2. Syscall Interface

The following section defines the syscall interface used by this specification, and therefore Bareflank.

## 2.1. Legal Syscall Environments

Kernel and user-space can execute syscalls from 64bit mode.

## 2.2. Syscall Status Codes

Every syscall returns a bf_status_t to indicate the success or failure of a syscall after execution. The following defines the layout of bf_status_t:

| Bits | Name | Description |
| :--- | :--- | :---------- |
| 63:48 | BF_STATUS_SIG | Contains 0x0000 on success, 0xDEAD on failure |
| 47:16 | BF_STATUS_FLAGS | Contains the flags associated with the bf_status_t |
| 15:0 | BF_STATUS_VALUE | Contains the value of the bf_status_t |

BF_STATUS_VALUE defines success or which type of error occurred. BF_STATUS_FLAGS provides additional information about why the error occurred. BF_STATUS_FLAGS is optional and used solely for diagnostics. As such, the microkernel may or may not provide it.

### 2.2.1. BF_STATUS_SUCCESS, VALUE=0

**const, bf_status_t: BF_STATUS_SUCCESS**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000000 | Used to indicated that the syscall returned successfully |

### 2.2.2. BF_STATUS_FAILURE, VALUE=1

**const, bf_status_t: BF_STATUS_FAILURE_UNKNOWN**
| Value | Description |
| :---- | :---------- |
| 0xDEAD000000010001 | Indicates an unknown error occurred |

**const, bf_status_t: BF_STATUS_FAILURE_UNSUPPORTED**
| Value | Description |
| :---- | :---------- |
| 0xDEAD000000020001 | Indicates the syscall is unsupported |

**const, bf_status_t: BF_STATUS_FAILURE_INVALID_HANDLE**
| Value | Description |
| :---- | :---------- |
| 0xDEAD000000040001 | Indicates the provided handle is invalid |

### 2.2.3. BF_STATUS_INVALID_PERM, VALUE=2

BF_STATUS_INVALID_PERM defines a permissions failure.

**const, bf_status_t: BF_STATUS_INVALID_PERM_EXT**
| Value | Description |
| :---- | :---------- |
| 0xDEAD000000010002 | Indicates the extension is not allowed to execute this syscall |

**const, bf_status_t: BF_STATUS_INVALID_PERM_DENIED**
| Value | Description |
| :---- | :---------- |
| 0xDEAD000000020002 | Indicates the policy engine denied the syscall |

### 2.2.4. BF_STATUS_INVALID_PARAMS, VALUE=3

BF_STATUS_INVALID_PARAMS defines that one or more input/output parameters provided to the C wrapper was invalid.

**const, bf_status_t: BF_STATUS_INVALID_PARAMS0**
| Value | Description |
| :---- | :---------- |
| 0xDEAD000000010003 | Indicates param 0 is invalid |

**const, bf_status_t: BF_STATUS_INVALID_PARAMS1**
| Value | Description |
| :---- | :---------- |
| 0xDEAD000000020003 | Indicates param 1 is invalid |

**const, bf_status_t: BF_STATUS_INVALID_PARAMS2**
| Value | Description |
| :---- | :---------- |
| 0xDEAD000000040003 | Indicates param 2 is invalid |

**const, bf_status_t: BF_STATUS_INVALID_PARAMS3**
| Value | Description |
| :---- | :---------- |
| 0xDEAD000000080003 | Indicates param 3 is invalid |

**const, bf_status_t: BF_STATUS_INVALID_PARAMS4**
| Value | Description |
| :---- | :---------- |
| 0xDEAD000000100003 | Indicates param 4 is invalid |

**const, bf_status_t: BF_STATUS_INVALID_PARAMS5**
| Value | Description |
| :---- | :---------- |
| 0xDEAD000000200003 | Indicates param 5 is invalid |

## 2.3. Syscall Inputs

Before software can execute a syscall, it must first open a handle to the syscall interface by executing the bf_handle_op_open_handle syscall. This handle must be provided as the first argument to each syscall in RDI (i.e., REG0) and can be released using the bf_handle_op_close_handle syscall.

**RDI:**
| Bits | Name | Description |
| :--- | :--- | :---------- |
| 63:0 | BF_HANDLE | The result of bf_handle_op_open_handle |

Every syscall must provide information about the syscall by filling out RAX as follows:

**RAX:**
| Bits | Name | Description |
| :--- | :--- | :---------- |
| 63:48 | BF_SYSCALL_SIG | 0x6642 = "Bf" |
| 47:32 | BF_SYSCALL_FLAGS | Contains the syscall's flags |
| 31:16 | BF_SYSCALL_OP | Contains the syscall's opcode |
| 15:0 | BF_SYSCALL_IDX | Contains the syscall's index |

**const, bf_uint64_t: BF_SYSCALL_SIG_VAL**
| Value | Description |
| :---- | :---------- |
| 0x6642000000000000 | Defines the BF_SYSCALL_SIG field for RAX |

**const, bf_uint64_t: BF_HYPERCALL_SIG_MASK**
| Value | Description |
| :---- | :---------- |
| 0xFFFF000000000000 | Defines a mask for BF_SYSCALL_SIG |

**const, bf_uint64_t: BF_HYPERCALL_FLAGS_MASK**
| Value | Description |
| :---- | :---------- |
| 0x0000FFFF00000000 | Defines a mask for BF_SYSCALL_FLAGS |

**const, bf_uint64_t: BF_HYPERCALL_OPCODE_MASK**
| Value | Description |
| :---- | :---------- |
| 0xFFFF0000FFFF0000 | Defines a mask for BF_SYSCALL_OP |

**const, bf_uint64_t: BF_HYPERCALL_OPCODE_NOSIG_MASK**
| Value | Description |
| :---- | :---------- |
| 0x00000000FFFF0000 | Defines a mask for BF_SYSCALL_OP (with no signature added) |

**const, bf_uint64_t: BF_HYPERCALL_INDEX_MASK**
| Value | Description |
| :---- | :---------- |
| 0x000000000000FFFF | Defines a mask for BF_SYSCALL_IDX |

BF_SYSCALL_SIG is used to ensure the syscall is, in fact, a Bareflank specific syscall. BF_SYSCALL_FLAGS is used to provide additional syscall options.

BF_SYSCALL_OP determines which opcode the syscall belongs to, logically grouping syscalls based on their function. BF_SYSCALL_OP is also used internally within the microkernel to dispatch the syscall to the proper handler. BF_SYSCALL_IDX, when combined with BF_SYSCALL_OP, uniquely identifies a specific syscall. This specification tightly packs the values assigned to both BF_SYSCALL_IDX and BF_SYSCALL_OP to ensure Bareflank (and variants) can use jump tables instead of branch logic (depends on the trade-off between retpoline mitigations and branch induced pipeline stalls).

The following defines the input registers for x64 based systems (i.e., x86_64 and amd64):

**Arguments:**
| Register Name | Description |
| :------------ | :---------- |
| RDI | Set to the result of bf_handle_op_open_handle |
| RSI | Stores the value of REG1 (syscall specific) |
| RDX | Stores the value of REG2 (syscall specific) |
| R10 | Stores the value of REG3 (syscall specific) |
| R8  | Stores the value of REG4 (syscall specific) |
| R9  | Stores the value of REG5 (syscall specific) |

All unused registers by any syscall are considered REVI.

## 2.4. Syscall Outputs

After executing a syscall, a bf_status_t is returned in RAX to indicate if the syscall succeeded or failed and why.

**RAX:**
| Bits | Name | Description |
| :--- | :--- | :---------- |
| 63:0 | BF_STATUS | Contains the value of bf_status_t |

The following defines the output registers for x64 based systems (i.e., x86_64 and amd64):

**Arguments:**
| Register Name | Description |
| :------------ | :---------- |
| RDI | Stores the value of REG0 (syscall specific) |
| RSI | Stores the value of REG1 (syscall specific) |
| RDX | Stores the value of REG2 (syscall specific) |
| R10 | Stores the value of REG3 (syscall specific) |
| R8  | Stores the value of REG4 (syscall specific) |
| R9  | Stores the value of REG5 (syscall specific) |

## 2.5. Syscall Opcodes

The following sections define the different opcodes that are supported by this specification. Note that each opcode includes the syscall signature making it easier to validate if the syscall is supported or not.

### 2.5.1. Control Support

**const, bf_uint64_t: BF_CONTROL_OP_VAL**
| Value | Description |
| :---- | :---------- |
| 0x6642000000000000 | Defines the syscall opcode for bf_control_op |

**const, bf_uint64_t: BF_CONTROL_OP_NOSIG_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000000 | Defines the syscall opcode for bf_control_op (nosig) |

### 2.5.2. Handle Support

**const, bf_uint64_t: BF_HANDLE_OP_VAL**
| Value | Description |
| :---- | :---------- |
| 0x6642000000010000 | Defines the syscall opcode for bf_handle_op |

**const, bf_uint64_t: BF_HANDLE_OP_NOSIG_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000010000 | Defines the syscall opcode for bf_handle_op (nosig) |

### 2.5.3. Debug Support

**const, bf_uint64_t: BF_DEBUG_OP_VAL**
| Value | Description |
| :---- | :---------- |
| 0x6642000000020000 | Defines the syscall opcode for bf_debug_op |

**const, bf_uint64_t: BF_DEBUG_OP_NOSIG_VAL**
| Value | Description |
| :---- | :---------- |
| 0x00000000000020000 | Defines the syscall opcode for bf_debug_op (nosig) |

### 2.5.4. Callback Support

**const, bf_uint64_t: BF_CALLBACK_OP_VAL**
| Value | Description |
| :---- | :---------- |
| 0x6642000000030000 | Defines the syscall opcode for bf_callback_op |

**const, bf_uint64_t: BF_CALLBACK_OP_NOSIG_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000030000 | Defines the syscall opcode for bf_callback_op (nosig) |

### 2.5.5. VM Support

**const, bf_uint64_t: BF_VM_OP_VAL**
| Value | Description |
| :---- | :---------- |
| 0x6642000000040000 | Defines the syscall opcode for bf_vm_op |

**const, bf_uint64_t: BF_VM_OP_NOSIG_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000040000 | Defines the syscall opcode for bf_vm_op (nosig) |

### 2.5.6. VP Support

**const, bf_uint64_t: BF_VP_OP_VAL**
| Value | Description |
| :---- | :---------- |
| 0x6642000000050000 | Defines the syscall opcode for bf_vp_op |

**const, bf_uint64_t: BF_VP_OP_NOSIG_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000050000 | Defines the syscall opcode for bf_vp_op (nosig) |

### 2.5.7. VPS Support

**const, bf_uint64_t: BF_VPS_OP_VAL**
| Value | Description |
| :---- | :---------- |
| 0x6642000000060000 | Defines the syscall opcode for bf_vps_op |

**const, bf_uint64_t: BF_VPS_OP_NOSIG_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000060000 | Defines the syscall opcode for bf_vps_op (nosig) |

### 2.5.8. Intrinsic Support

**const, bf_uint64_t: BF_INTRINSIC_OP_VAL**
| Value | Description |
| :---- | :---------- |
| 0x6642000000070000 | Defines the syscall opcode for bf_intrinsic_op |

**const, bf_uint64_t: BF_INTRINSIC_OP_NOSIG_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000070000 | Defines the syscall opcode for bf_intrinsic_op (nosig) |

### 2.5.9. Mem Support

**const, bf_uint64_t: BF_MEM_OP_VAL**
| Value | Description |
| :---- | :---------- |
| 0x6642000000080000 | Defines the syscall opcode for bf_mem_op |

**const, bf_uint64_t: BF_MEM_OP_NOSIG_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000080000 | Defines the syscall opcode for bf_mem_op (nosig) |

### 2.5.10. Syscall Specification IDs

The following defines the specification IDs used when opening a handle. These provide software with a means to define which specification it implements. bf_handle_op_version defines which version of this spec the microkernel supports. For example, if bf_handle_op_version returns 0x2, it means that it supports version #1 of this spec, in which case, an extension can open a handle with BF_SPEC_ID1_VAL. If bf_handle_op_version returns a value of 0x6, it would mean that an extension could open a handle with BF_SPEC_ID1_VAL or BF_SPEC_ID2_VAL. Likewise, if bf_handle_op_version returns 0x4, it means that BF_SPEC_ID1_VAL is no longer supported, and the extension must open the handle with BF_SPEC_ID2_VAL.

**const, bf_uint32_t: BF_SPEC_ID1_VAL**
| Value | Description |
| :---- | :---------- |
| 0x31236642 | Defines the ID for version #1 of this spec |

**const, bf_uint32_t: BF_SPEC_ID1_MASK**
| Value | Description |
| :---- | :---------- |
| 0x2 | Defines the mask for checking support for version #1 of this spec |

**const, bf_uint32_t: BF_ALL_SPECS_SUPPORTED_VAL**
| Value | Description |
| :---- | :---------- |
| 0x2 | Defines the value likely returned by bf_handle_op_version |

## 2.6. Thread Local Storage

The microkernel defines a "thread" the same way both Intel and AMD define a thread (i.e., a logical core). For example, some Intel CPUs have 4 cores and 8 threads when hyper-threading is enabled, or 4 cores and 4 threads when hyper-threading is disabled. Each logical core is given one "thread" and that thread always executes on that logical core. The microkernel defines these logical cores as physical processors (i.e., PP).

The layout of the TLS block provided to each extension uses a scheme similar to the ELF TLS specification, but with some modifications. Unlike the ELF TLS specification, each TLS block is limited to two pages. The lower half of the page is dedicated to "thread_local" storage. The upper half is defined by this specification, and provides access to registers shared between the microkernel and the extension to improve performance. For example, access to a VM's general purpose registers is available from the TLS block. Each TLS register defined by this specific is an offset into the upper half of the TLS block (which can be located using the fs segment register on Intel/AMD).

**IMPORTANT:**
The general purpose registers are always accessible to an extension to read and write, but it is up to the extension to ensure the correct VPS state is being modified. Accesses to the TLS block modifies the active VPS only. For example, while an extension is executing its bootstrap handler, there is no active VPS, in which case any reads/writes to the general purpose registers from the TLS block will be lost. When an extension is executing from a VMExit handler, reads/writes to the general purpose registers from the TLS block are made to the VPS that generated the VMExit. If an extension then creates a VPS, the only way to modify the general purpose registers for the newly created VPS is through the read_reg/write_reg ABIs. Attempting to use the TLS block will modify the registers for the active VPS, not the newly created VPS. The only way to set a VPS to "active" is to use the run ABI, which on success does not return, meaning the extension has to wait for a VMExit before the newly create VPS's general purpose registers can be accessed from the TLS block.

Although this seems overly complicated, this optimization works well for the majority of the VMExits an extension will have to handle, especially the VMExits that execute frequently as most of the time an extension will only be modifying the general purpose registers for the active VPS.

### 2.6.1. TLS Offsets

**consts, void *: bf_uint64_t**
| Name | Value | Description |
| :--- | :---- | :---------- |
| TLS_OFFSET_RAX | 0x800U | stores the offset for rax |
| TLS_OFFSET_RBX | 0x808U | stores the offset for rbx |
| TLS_OFFSET_RCX | 0x810U | stores the offset for rcx |
| TLS_OFFSET_RDX | 0x818U | stores the offset for rdx |
| TLS_OFFSET_RBP | 0x820U | stores the offset for rbp |
| TLS_OFFSET_RSI | 0x828U | stores the offset for rsi |
| TLS_OFFSET_RDI | 0x830U | stores the offset for rdi |
| TLS_OFFSET_R8 | 0x838U | stores the offset for r8 |
| TLS_OFFSET_R9 | 0x840U | stores the offset for r9 |
| TLS_OFFSET_R10 | 0x848U | stores the offset for r10 |
| TLS_OFFSET_R11 | 0x850U | stores the offset for r11 |
| TLS_OFFSET_R12 | 0x858U | stores the offset for r12 |
| TLS_OFFSET_R13 | 0x860U | stores the offset for r13 |
| TLS_OFFSET_R14 | 0x868U | stores the offset for r14 |
| TLS_OFFSET_R15 | 0x870U | stores the offset for r15 |
| TLS_OFFSET_ACTIVE_EXTID | 0xFF0U | stores the offset of the active extid |
| TLS_OFFSET_ACTIVE_VMID | 0xFF2U | stores the offset of the active vmid |
| TLS_OFFSET_ACTIVE_VPID | 0xFF4U | stores the offset of the active vpid |
| TLS_OFFSET_ACTIVE_VPSID | 0xFF6U | stores the offset of the active vpsid |
| TLS_OFFSET_ACTIVE_PPID | 0xFF8U | stores the offset of the active ppid |
| TLS_OFFSET_ONLINE_PPS | 0xFFAU | stores the number of PPs that are online |

## 2.7. Control Syscalls

### 2.7.1. bf_control_op_exit, OP=0x0, IDX=0x0

This syscall tells the microkernel to stop the execution of an extension, providing a means to fast fail.

**const, bf_uint64_t: BF_CONTROL_OP_EXIT_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000000 | Defines the syscall index for bf_control_op_exit |

### 2.10.1. bf_control_op_wait, OP=0x0, IDX=0x1

This syscall tells the microkernel that the extension would like to wait for a callback. This syscall is a blocking syscall that never returns and should be used to return from the _start function.

**const, bf_uint64_t: BF_CONTROL_OP_WAIT_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000001 | Defines the syscall index for bf_control_op_wait |

## 2.8. Handle Syscalls

### 2.8.1. bf_handle_op_open_handle, OP=0x1, IDX=0x0

This syscall returns the handle that is required to execute the remaining syscalls. Some versions of Bareflank might provide a certain degree of backward compatibility, queried using bf_handle_op_version. The version argument of this syscall indicates to the microkernel which version of this spec the software supports. If the software provides a version that Bareflank doesn't support (i.e., a version that is not listed by bf_handle_op_version), this syscall will fail.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 31:0 | The version of this spec that software supports |
| REG0 | 63:32 | REVI |

**Output:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | The value to set REG0 to for most other syscalls |

**const, bf_uint64_t: BF_HANDLE_OP_OPEN_HANDLE_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000000 | Defines the syscall index for bf_handle_op_open_handle |

### 2.8.2. bf_handle_op_close_handle, OP=0x1, IDX=0x1

This syscall closes a previously opened handle.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of bf_handle_op_open_handle |

**const, bf_uint64_t: BF_HANDLE_OP_CLOSE_HANDLE_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000001 | Defines the syscall index for bf_handle_op_close_handle |

## 2.9. Debug Syscalls

### 2.9.1. bf_debug_op_out, OP=0x2, IDX=0x0

This syscall tells the microkernel to output RDI and RSI to the console device the microkernel is currently using for debugging.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | The first value to output to the microkernel's console |
| REG1 | 63:0 | The second value to output to the microkernel's console |

**const, bf_uint64_t: BF_DEBUG_OP_OUT_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000000 | Defines the syscall index for bf_debug_op_out |

### 2.9.2. bf_debug_op_dump_vm, OP=0x2, IDX=0x1

This syscall tells the microkernel to output a VM's state to the console device the microkernel is currently using for debugging.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | The VMID of the VM's state to output |

**const, bf_uint64_t: BF_DEBUG_OP_DUMP_VM_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000001 | Defines the syscall index for bf_debug_op_dump_vm |

### 2.9.3. bf_debug_op_dump_vp, OP=0x2, IDX=0x2

This syscall tells the microkernel to output a VP's state to the console device the microkernel is currently using for debugging.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | The VPID of the VP's state to output |

**const, bf_uint64_t: BF_DEBUG_OP_DUMP_VP_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000002 | Defines the syscall index for bf_debug_op_dump_vp |

### 2.9.4. bf_debug_op_dump_vps, OP=0x2, IDX=0x3

This syscall tells the microkernel to output a VPS's state to the console device the microkernel is currently using for debugging.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | The VPSID of the VPS's state to output |

**const, bf_uint64_t: BF_DEBUG_OP_DUMP_VPS_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000003 | Defines the syscall index for bf_debug_op_dump_vps |

### 2.9.5. bf_debug_op_dump_vmexit_log, OP=0x2, IDX=0x4

This syscall tells the microkernel to output the VMExit log. The VMExit log is a chronological log of the "X" number of exits that have occurred on a specific physical processor.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | The PPID of the PP to dump the log from |

**const, bf_uint64_t: BF_DEBUG_OP_DUMP_VMEXIT_LOG_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000003 | Defines the syscall index for bf_debug_op_dump_vmexit_log |

### 2.9.6. bf_debug_op_write_c, OP=0x2, IDX=0x5

This syscall tells the microkernel to output a provided character to the microkernel's console.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 7:0 | The character to output |
| REG0 | 63:8 | REVI |

**const, bf_uint64_t: BF_DEBUG_OP_WRITE_C_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000005 | Defines the syscall index for bf_debug_op_write_c |

### 2.9.7. bf_debug_op_write_str, OP=0x2, IDX=0x6

This syscall tells the microkernel to output a provided string to the microkernel's console.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | The virtual address of a null terminated string to output |

**const, bf_uint64_t: BF_DEBUG_OP_WRITE_STR_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000006 | Defines the syscall index for bf_debug_op_write_str |

### 2.9.8. bf_debug_op_dump_ext, OP=0x2, IDX=0x7

This syscall tells the microkernel to output an extension's state to the console device the microkernel is currently using for debugging.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | The EXTID of the extensions's state to output |

**const, bf_uint64_t: BF_DEBUG_OP_DUMP_EXT_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000007 | Defines the syscall index for bf_debug_op_dump_ext |

### 2.9.9. bf_debug_op_dump_page_pool, OP=0x2, IDX=0x8

This syscall tells the microkernel to output the page pool's stats to the console device the microkernel is currently using for debugging.

**const, bf_uint64_t: BF_DEBUG_OP_DUMP_PAGE_POOL_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000008 | Defines the syscall index for bf_debug_op_dump_page_pool |

### 2.9.10. bf_debug_op_dump_huge_pool, OP=0x2, IDX=0x9

This syscall tells the microkernel to output the huge pool's stats to the console device the microkernel is currently using for debugging.

**const, bf_uint64_t: BF_DEBUG_OP_DUMP_HUGE_POOL_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000009 | Defines the syscall index for bf_debug_op_dump_huge_pool |

## 2.10. Callback Syscalls

### 2.10.2. bf_callback_op_register_bootstrap, OP=0x3, IDX=0x2

This syscall tells the microkernel that the extension would like to receive callbacks for bootstrap events.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of bf_handle_op_open_handle |
| REG1 | 63:0 | Set to the virtual address of the callback |

**const, bf_uint64_t: BF_CALLBACK_OP_REGISTER_BOOTSTRAP_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000002 | Defines the syscall index for bf_callback_op_register_bootstrap |

### 2.10.3. bf_callback_op_register_vmexit, OP=0x3, IDX=0x3

This syscall tells the microkernel that the extension would like to receive callbacks for VM exits.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of bf_handle_op_open_handle |
| REG1 | 63:0 | Set to the virtual address of the callback |

**const, bf_uint64_t: BF_CALLBACK_OP_REGISTER_VMEXIT_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000003 | Defines the syscall index for bf_callback_op_register_vmexit |

### 2.10.4. bf_callback_op_register_fail, OP=0x3, IDX=0x4

This syscall tells the microkernel that the extension would like to receive callbacks for fast fail events. If a fast fail event occurs, something terrible has happened, and the extension must take action, or the physical processor will halt.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of bf_handle_op_open_handle |
| REG1 | 63:0 | Set to the virtual address of the callback |

**const, bf_uint64_t: BF_CALLBACK_OP_REGISTER_FAIL_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000004 | Defines the syscall index for bf_callback_op_register_fail |

## 2.11. Virtual Machine Syscalls

A Virtual Machine or VM virtually represents a physical computer. Although the microkernel has an internal representation of a VM, it doesn't understand what a VM is outside of resource management, and it is up to the extension to define what a VM is and how it should operate.

One important resource within the microkernel that changes when a VM changes is the direct map each extension is given. When a VM changes, the direct map an extension uses to access physical memory also changes.

### 2.11.1. Virtual Machine ID (VMID)

The Virtual Machine ID  (VMID) is a 16bit number that uniquely identifies a VM.

### 2.11.2. bf_vm_op_create_vm, OP=0x4, IDX=0x0

This syscall tells the microkernel to create a VM and return its ID.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of bf_handle_op_open_handle |

**Output:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 15:0 | The resulting VMID of the newly created VM |
| REG0 | 63:16 | REVI |

**const, bf_uint64_t: BF_VM_OP_CREATE_VM_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000000 | Defines the syscall index for bf_vm_op_create_vm |

### 2.11.3. bf_vm_op_destroy_vm, OP=0x4, IDX=0x1

This syscall tells the microkernel to destroy a VM given an ID.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of bf_handle_op_open_handle |
| REG1 | 15:0 | The VMID of the VM to destroy |
| REG1 | 63:16 | REVI |

**const, bf_uint64_t: BF_VM_OP_DESTROY_VM_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000001 | Defines the syscall index for bf_vm_op_destroy_vm |

## 2.12. Virtual Processor Syscalls

A Virtual Processor or VP virtually represents a logical core. Although the microkernel has an internal representation of a VP, it doesn't understand what a VP is outside of resource management, and it is up to the extension to define what a VM is and how it should operate.

Once a VP is run, it is assigned to the VM it was run on, and cannot be run on any other VM for the remainder of it's lifetime. A VP is also assigned to a specific PP (physical processor). Unlike the assigned VM, the assigned PP can be changed by migrating the VP to another PP.

### 2.12.1. Virtual Processor ID (VPID)

The Virtual Processor ID (VPID) is a 16bit number that uniquely identifies a VP.

### 2.12.2. bf_vp_op_create_vp, OP=0x5, IDX=0x0

This syscall tells the microkernel to create a VP given the IDs of the VM and PP the VP will be assigned to. Upon success, this syscall returns the ID of the newly created VP.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of bf_handle_op_open_handle |
| REG1 | 15:0 | The ID of the VM to assign the newly created VP to |
| REG1 | 63:16 | REVI |
| REG2 | 15:0 | The ID of the PP to assign the newly created VP to |
| REG2 | 63:16 | REVI |

**Output:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 15:0 | The resulting VPID of the newly created VP |
| REG0 | 63:16 | REVI |

**const, bf_uint64_t: BF_VP_OP_CREATE_VP_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000000 | Defines the syscall index for bf_vp_op_create_vp |

### 2.12.3. bf_vp_op_destroy_vp, OP=0x5, IDX=0x1

This syscall tells the microkernel to destroy a VP given an ID.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of bf_handle_op_open_handle |
| REG1 | 15:0 | The VPID of the VP to destroy |
| REG1 | 63:16 | REVI |

**const, bf_uint64_t: BF_VP_OP_DESTROY_VP_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000001 | Defines the syscall index for bf_vp_op_destroy_vp |

### 2.12.3. bf_vp_op_migrate, OP=0x5, IDX=0x2

This syscall tells the microkernel to migrate a VP from one PP to another PP. This function does not execute the VP (use bf_vps_op_run for that), but instead allows bf_vps_op_run to execute a VP on a PP that it was not originally assigned to.

When a VP is migrated, all of the VPSs that are assigned to the requested VP are also migrated to this new PP as well. From an AMD/Intel point of view, this clears the VMCS/VMCB for each VPS assigned to the VP. On Intel, it also loads the newly cleared VPS and sets the launched state to false, ensuring the next bf_vps_op_run will use VMLaunch instead of VMResume.

It should be noted that the migration of a VPS from one PP to another does not happen during the execution of this ABI. This ABI simply tells the microkernel that the requested VP may now execute on the requested PP. This will cause a mismatch between the assigned PP for a VP and the assigned PP for a VPS. The microkernel will detect this mismatch when an extension attempts to execute bf_vps_op_run. When this occurs, the microkernel will ensure the VP is being run on the PP it was assigned to during migration, and then it will check to see if the PP of the VPS matches. If it doesn't, it will then perform a migration of that VPS at that time. This ensures that the microkernel is only migrations VPSs when it needs to, and it ensures the VPS is cleared an loaded (in the case of Intel) on the PP it will be executed on, which is a requirement for VMCS migration. An extension can determine which VPSs have been migrated by looking at the assigned PP of a VPS. If it doesn't match the VP it was assigned to, it has not been migrated. Finally, an extension is free to read/write to the VPSs state, even if it has not been migrated. The only requirement for migration is execution (meaning VMRun/VMLaunch/VMResume).

Any additional migration responsibilities, like TSC synchronization, must be performed by the extension.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of bf_handle_op_open_handle |
| REG1 | 15:0 | The VPID of the VP to migrate |
| REG1 | 63:16 | REVI |
| REG2 | 15:0 | The ID of the PP to assign the provided VP to |
| REG2 | 63:16 | REVI |

**const, bf_uint64_t: BF_VP_OP_MIGRATE_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000002 | Defines the syscall index for bf_vp_op_migrate |

### 2.12.4. Virtual Processor State Syscalls

A Virtual Processor State or VPS encapsulates the state associated with a virtual process. For example, on Intel this would be the VMCS, the registers that must be saved that the VMCS does not manage, and the general purpose registers.

Once a VPS is run, it is assigned to the VP it was run on, and cannot be run on any other VP for the remainder of it's lifetime. Since a VP is also assigned to a specific PP (physical processor), so is the VPS. When a VP is migrated, all VPSs assigned to that VP are also migrated.

### 2.12.5. Virtual Processor State ID (VPSID)

The Virtual Processor State ID (VPSID) is a 16bit number that uniquely identifies a VPS.

### 2.12.6. bf_vps_op_create_vps, OP=0x6, IDX=0x0

This syscall tells the microkernel to create a VPS given the IDs of the VP and PP the VPS will be assigned to. Upon success, this syscall returns the ID of the newly created VPS.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of bf_handle_op_open_handle |
| REG1 | 15:0 | The ID of the VP to assign the newly created VPS to |
| REG1 | 63:16 | REVI |
| REG2 | 15:0 | The ID of the PP to assign the newly created VPS to |
| REG2 | 63:16 | REVI |

**Output:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 15:0 | The resulting VPSID of the newly created VPS |
| REG0 | 63:16 | REVI |

**const, bf_uint64_t: BF_VPS_OP_CREATE_VPS_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000000 | Defines the syscall index for bf_vps_op_create_vps |

### 2.12.7. bf_vps_op_destroy_vps, OP=0x6, IDX=0x1

This syscall tells the microkernel to destroy a VPS given an ID.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of bf_handle_op_open_handle |
| REG1 | 15:0 | The VPSID of the VPS to destroy |
| REG1 | 63:16 | REVI |

**const, bf_uint64_t: BF_VPS_OP_DESTROY_VPS_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000001 | Defines the syscall index for bf_vps_op_destroy_vps |

### 2.12.8. bf_vps_op_init_as_root, OP=0x6, IDX=0x2

This syscall tells the microkernel to initialize a VPS using the root VP state provided by the loader using the current PPID.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of bf_handle_op_open_handle |
| REG1 | 15:0 | The VPSID of the VPS to initialize |
| REG1 | 63:16 | REVI |

**const, bf_uint64_t: BF_VPS_OP_INIT_AS_ROOT_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000002 | Defines the syscall index for bf_vps_op_init_as_root |

### 2.12.9. bf_vps_op_read8, OP=0x6, IDX=0x3

Reads an 8bit field from the VPS and returns the value. The "index" is architecture-specific. For Intel, Appendix B, "Field Encoding in VMCS," defines the index (or encoding). For AMD, Appendix B, "Layout of VMCB," defines the index (or offset).

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of bf_handle_op_open_handle |
| REG1 | 15:0 | The VPSID of the VPS to read from |
| REG1 | 63:16 | REVI |
| REG2 | 63:0 | The HVE specific index defining which field to read |

**Output:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 7:0 | The resulting value |
| REG1 | 63:8 | REVI |

**const, bf_uint64_t: BF_VPS_OP_READ8_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000003 | Defines the syscall index for bf_vps_op_read8 |

### 2.12.10. bf_vps_op_read16, OP=0x6, IDX=0x4

Reads a 16bit field from the VPS and returns the value. The "index" is architecture-specific. For Intel, Appendix B, "Field Encoding in VMCS," defines the index (or encoding). For AMD, Appendix B, "Layout of VMCB," defines the index (or offset).

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of bf_handle_op_open_handle |
| REG1 | 15:0 | The VPSID of the VPS to read from |
| REG1 | 63:16 | REVI |
| REG2 | 63:0 | The HVE specific index defining which field to read |

**Output:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 15:0 | The resulting value |
| REG1 | 63:16 | REVI |

**const, bf_uint64_t: BF_VPS_OP_READ16_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000004 | Defines the syscall index for bf_vps_op_read16 |

### 2.12.11. bf_vps_op_read32, OP=0x6, IDX=0x5

Reads a 32bit field from the VPS and returns the value. The "index" is architecture-specific. For Intel, Appendix B, "Field Encoding in VMCS," defines the index (or encoding). For AMD, Appendix B, "Layout of VMCB," defines the index (or offset).

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of bf_handle_op_open_handle |
| REG1 | 15:0 | The VPSID of the VPS to read from |
| REG1 | 63:16 | REVI |
| REG2 | 63:0 | The HVE specific index defining which field to read |

**Output:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 31:0 | The resulting value |
| REG1 | 63:32 | REVI |

**const, bf_uint64_t: BF_VPS_OP_READ32_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000005 | Defines the syscall index for bf_vps_op_read32 |

### 2.12.12. bf_vps_op_read64, OP=0x6, IDX=0x6

Reads a 64bit field from the VPS and returns the value. The "index" is architecture-specific. For Intel, Appendix B, "Field Encoding in VMCS," defines the index (or encoding). For AMD, Appendix B, "Layout of VMCB," defines the index (or offset).

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of bf_handle_op_open_handle |
| REG1 | 15:0 | The VPSID of the VPS to read from |
| REG1 | 63:16 | REVI |
| REG2 | 63:0 | The HVE specific index defining which field to read |

**Output:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | The resulting value |

**const, bf_uint64_t: BF_VPS_OP_READ64_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000006 | Defines the syscall index for bf_vps_op_read64 |

### 2.12.13. bf_vps_op_write8, OP=0x6, IDX=0x7

Writes to an 8bit field in the VPS. The "index" is architecture-specific. For Intel, Appendix B, "Field Encoding in VMCS," defines the index (or encoding). For AMD, Appendix B, "Layout of VMCB," defines the index (or offset).

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of bf_handle_op_open_handle |
| REG1 | 15:0 | The VPSID of the VPS to write |
| REG1 | 63:16 | REVI |
| REG2 | 63:0 | The HVE specific index defining which field to write |
| REG3 | 7:0 | The value to write to the requested field |
| REG3 | 63:8 | REVI |

**const, bf_uint64_t: BF_VPS_OP_WRITE8_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000007 | Defines the syscall index for bf_vps_op_write8 |

### 2.12.14. bf_vps_op_write16, OP=0x6, IDX=0x8

Writes to a 16bit field in the VPS. The "index" is architecture-specific. For Intel, Appendix B, "Field Encoding in VMCS," defines the index (or encoding). For AMD, Appendix B, "Layout of VMCB," defines the index (or offset).

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of bf_handle_op_open_handle |
| REG1 | 15:0 | The VPSID of the VPS to write |
| REG1 | 63:16 | REVI |
| REG2 | 63:0 | The HVE specific index defining which field to write |
| REG3 | 15:0 | The value to write to the requested field |
| REG3 | 63:16 | REVI |

**const, bf_uint64_t: BF_VPS_OP_WRITE16_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000008 | Defines the syscall index for bf_vps_op_write16 |

### 2.12.15. bf_vps_op_write32, OP=0x6, IDX=0x9

Writes to a 32bit field in the VPS. The "index" is architecture-specific. For Intel, Appendix B, "Field Encoding in VMCS," defines the index (or encoding). For AMD, Appendix B, "Layout of VMCB," defines the index (or offset).

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of bf_handle_op_open_handle |
| REG1 | 15:0 | The VPSID of the VPS to write |
| REG1 | 63:16 | REVI |
| REG2 | 63:0 | The HVE specific index defining which field to write |
| REG3 | 7:0 | The value to write to the requested field |
| REG3 | 63:32 | REVI |

**const, bf_uint64_t: BF_VPS_OP_WRITE32_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000009 | Defines the syscall index for bf_vps_op_write32 |

### 2.12.16. bf_vps_op_write64, OP=0x6, IDX=0xA

Writes to a 64bit field in the VPS. The "index" is architecture-specific. For Intel, Appendix B, "Field Encoding in VMCS," defines the index (or encoding). For AMD, Appendix B, "Layout of VMCB," defines the index (or offset).

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of bf_handle_op_open_handle |
| REG1 | 15:0 | The VPSID of the VPS to write |
| REG1 | 63:16 | REVI |
| REG2 | 63:0 | The HVE specific index defining which field to write |
| REG3 | 63:0 | The value to write to the requested field |

**const, bf_uint64_t: BF_VPS_OP_WRITE64_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x000000000000000A | Defines the syscall index for bf_vps_op_write64 |

### 2.12.17. bf_vps_op_read_reg, OP=0x6, IDX=0xB

Reads a CPU register from the VPS given a bf_reg_t. Note that the bf_reg_t is architecture-specific.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of bf_handle_op_open_handle |
| REG1 | 15:0 | The VPSID of the VPS to read from |
| REG1 | 63:16 | REVI |
| REG2 | 63:0 | A bf_reg_t defining which register to read |

**Output:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | The resulting value |

**const, bf_uint64_t: BF_VPS_OP_READ_REG_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x000000000000000B | Defines the syscall index for bf_vps_op_read_reg |

### 2.12.18. bf_vps_op_write_reg, OP=0x6, IDX=0xC

Writes to a CPU register in the VPS given a bf_reg_t and the value to write. Note that the bf_reg_t is architecture-specific.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of bf_handle_op_open_handle |
| REG1 | 15:0 | The VPSID of the VPS to write to |
| REG1 | 63:16 | REVI |
| REG2 | 63:0 | A bf_reg_t defining which register to write to |
| REG3 | 63:0 | The value to write to the requested register |

**const, bf_uint64_t: BF_VPS_OP_WRITE_REG_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x000000000000000C | Defines the syscall index for bf_vps_op_write_reg |

### 2.12.19. bf_vps_op_run, OP=0x5, IDX=0xD

bf_vps_op_run tells the microkernel to execute a given VPS on behalf of a given VP and VM. This system call only returns if an error occurs. On success, this system call will physically execute the requested VM and VP using the requested VPS, and the extension will only execute again on the next VMExit.

Unless an extension needs to change the active VM, VP or VPS, the extension should use bf_vps_op_run_current instead of bf_vps_op_run. bf_vps_op_run is slow as it must perform a series of checks to determine if it has any work to perform before execution of a VM can occur.

Unlike bf_vps_op_run_current which is really just a return to microkernel execution, bf_vps_op_run must perform the following operations:
- It first verifies that the provided VM, VP and VPS are all created. Meaning, and extension must first use the create ABI to properly create a VM, VP and VPS before it may be used.
- Next, it must ensure VM, VP and VPS assignment is correct. A newly created VP and VPS are unassigned. Once bf_vps_op_run is executed, the VP is assigned to the provided VM and the VPS is assigned to the provided VP. The VP and VPS are also both assigned to the PP bf_vps_op_run is executed on. Once these assignments take place, an extension cannot change them, and any attempt to run a VP or VPS on a VM, VP or PP they are not assigned to will fail. It is impossible to change the assigned of a VM or VP, but an extension can change the assignment of a VP and VPSs PP by using the bf_vp_op_migrate function.
- Next, bf_vps_op_run must determine if it needs to migrate a VPS to the PP the VPS is being executed on by bf_vps_op_run. For more information about how this works, please see bf_vp_op_migrate.
- Finally, bf_vps_op_run must ensure the active VM, VP and VPS are set to the VM, VP and VPS provided to this ABI. Any changes in the active state could cause additional operations to take place. For example, the VPS must transfer the TLS state of the general purpose registers to its internal cache so that the VPS that is about to become active can use the TLS block instead.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of bf_handle_op_open_handle |
| REG1 | 15:0 | The VMID of the VM to run |
| REG1 | 63:16 | REVI |
| REG2 | 15:0 | The VPID of the VP to run |
| REG2 | 63:16 | REVI |
| REG3 | 15:0 | The VPSID of the VPS to run |
| REG3 | 63:16 | REVI |

**const, bf_uint64_t: BF_VPS_OP_RUN_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x000000000000000D | Defines the syscall index for bf_vps_op_run |

### 2.12.20. bf_vps_op_run_current, OP=0x5, IDX=0xE

bf_vps_op_run_current tells the microkernel to execute the currently active VPS, VP and VM.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of bf_handle_op_open_handle |

**const, bf_uint64_t: BF_VPS_OP_RUN_CURRENT_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x000000000000000E | Defines the syscall index for bf_vps_op_run_current |

### 2.12.21. bf_vps_op_advance_ip, OP=0x5, IDX=0xF

This syscall tells the microkernel to advance the instruction pointer in the requested VPS.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of bf_handle_op_open_handle |
| REG1 | 15:0 | The VPSID of the VPS advance the IP in |
| REG1 | 63:16 | REVI |

**const, bf_uint64_t: BF_VPS_OP_ADVANCE_IP_AND_RUN_CURRENT_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x000000000000000F | Defines the syscall index for bf_vps_op_advance_ip |

### 2.12.22. bf_vps_op_advance_ip_and_run_current, OP=0x5, IDX=0x10

This syscall tells the microkernel to advance the instruction pointer in the currently active VPS and run the currently active VPS, VP and VM (i.e., this combines bf_vps_op_advance_ip and bf_vps_op_advance_ip).

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of bf_handle_op_open_handle |

**const, bf_uint64_t: BF_VPS_OP_ADVANCE_IP_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000010 | Defines the syscall index for bf_vps_op_advance_ip_and_run_current |

### 2.12.23. bf_vps_op_promote, OP=0x5, IDX=0x11

bf_vps_op_promote tells the microkernel to promote the requested VPS. bf_vps_op_promote will stop the hypervisor on the physical processor and replace its state with the state in the given VPS. Note that this syscall only returns on error.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of bf_handle_op_open_handle |
| REG1 | 15:0 | The VPSID of the VPS to promote |
| REG1 | 63:16 | REVI |

**const, bf_uint64_t: BF_VPS_OP_PROMOTE_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000011 | Defines the syscall index for bf_vps_op_promote |

### 2.12.24. bf_vps_op_clear_vps, OP=0x5, IDX=0x11

bf_vps_op_clear_vps tells the microkernel to clear the VPS's hardware cache, if one exists. How this is used depends entirely on the hardware and is associated with AMD's VMCB Clean Bits, and Intel's VMClear instruction. See the associated documentation for more details. On AMD, this ABI clears the entire VMCB. For more fine grained control, use the write ABIs to manually modify the VMCB.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of bf_handle_op_open_handle |
| REG1 | 15:0 | The VPSID of the VPS to clear |
| REG1 | 63:16 | REVI |

**const, bf_uint64_t: BF_VPS_OP_CLEAR_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000012 | Defines the syscall index for bf_vps_op_clear_vps |

## 2.13. Intrinsic Syscalls

### 2.13.1. bf_intrinsic_op_rdmsr, OP=0x7, IDX=0x0

Reads an MSR directly from the CPU given the address of the MSR to read. Note that this is specific to Intel/AMD only. Also note that not all MSRs can be written to, and which MSRs that can be written to is up to the microkernel's internal policy as well as which architecture the hypervisor is running on.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of bf_handle_op_open_handle |
| REG1 | 31:0 | The address of the MSR to read |
| REG1 | 63:32 | REVI |

**Output:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | The resulting value |

**const, bf_uint64_t: BF_INTRINSIC_OP_RDMSR_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000000 | Defines the syscall index for bf_intrinsic_op_rdmsr |

### 2.13.2. bf_intrinsic_op_wrmsr, OP=0x7, IDX=0x1

Writes to an MSR directly from the CPU given the address of the MSR to write and the value to write. Note that this is specific to Intel/AMD only. Also note that not all MSRs can be written to, and which MSRs that can be written to is up to the microkernel's internal policy as well as which architecture the hypervisor is running on.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of bf_handle_op_open_handle |
| REG1 | 31:0 | The address of the MSR to write to |
| REG1 | 63:32 | REVI |
| REG2 | 63:0 | The value to write to the requested MSR |

**const, bf_uint64_t: BF_INTRINSIC_OP_WRMSR_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000001 | Defines the syscall index for bf_intrinsic_op_wrmsr |

### 2.13.3. bf_intrinsic_op_invlpga, OP=0x7, IDX=0x2

Invalidates the TLB mapping for a given virtual page and a given ASID. Note that this is specific to AMD only.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of bf_handle_op_open_handle |
| REG1 | 63:0 | The address to invalidate |
| REG2 | 63:0 | The ASID to invalidate |

**const, bf_uint64_t: BF_INTRINSIC_OP_INVLPGA_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000002 | Defines the syscall index for bf_intrinsic_op_invlpga |

### 2.13.4. bf_intrinsic_op_invept, OP=0x7, IDX=0x3

Invalidates mappings in the translation lookaside buffers (TLBs) and paging-structure caches that were derived from extended page tables (EPT). Note that this is specific to Intel only.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of bf_handle_op_open_handle |
| REG1 | 63:0 | The EPTP to invalidate |
| REG2 | 63:0 | The INVEPT type (see the Intel SDM for details) |

**const, bf_uint64_t: BF_INTRINSIC_OP_INVEPT_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000003 | Defines the syscall index for bf_intrinsic_op_invept |

### 2.13.5. bf_intrinsic_op_invvpid, OP=0x7, IDX=0x4

Invalidates mappings in the translation lookaside buffers (TLBs) and paging-structure caches based on virtual-processor identifier (VPID). Note that this is specific to Intel only.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of bf_handle_op_open_handle |
| REG1 | 63:0 | The address to invalidate |
| REG2 | 15:0 | The VPID to invalidate |
| REG2 | 63:16 | REVI |
| REG3 | 63:0 | The INVVPID type (see the Intel SDM for details) |

**const, bf_uint64_t: BF_INTRINSIC_OP_INVVPID_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000004 | Defines the syscall index for bf_intrinsic_op_invvpid |

## 2.14. Mem Syscalls

Each extension has access to several different memory pools:
- The page pool (used for allocating pages)
- The huge pool (used for allocating physically contiguous pages)
- The heap pool (used for allocating heap memory)
- TLS (used for thread-local storage)
- The direct map

The page pool provides a means to allocate a page.

The huge pool provides a method for allocating physically contiguous memory. This pool is small and platform-dependent (as in less than a megabyte total).
It should be noted that some microkernels may choose not to implement bf_mem_op_free_huge which is optional.

The heap pool provides memory that can only be grown, meaning the memory must always remain virtually contiguous. An extension is free to use heap memory or the page pool. The only difference between these two pools is the page pool can only allocate a single page at a time and may or may not be fragmented (depends on the implementation). The heap pool can allocate memory of any size (must be a multiple of a page) and never fragments.

Thread-Local Storage (TLS) memory (typically allocated using `thread_local`) provides per-physical processor storage. The amount of TLS available to an extension is 1 page per physical processor.

The direct map provides an extension with a means to access any physical address by accessing the direct map region of the virtual address space (depends on the hypervisor's configuration). By default, on Intel/AMD with 4-level paging, this region starts at 0x0000600000000000, but it can be changed using CMake. An extension can access any physical address by simply adding 0x0000600000000000 to the physical address and dereferencing the resulting value. When a VM is destroyed, all physical memory maps associated with that VM will be removed. The direct map is also where page and huge page allocations are mapped, providing an extension with a simple means for performing a virtual address to physical address (and vice versa) translations.

### 2.14.1. bf_mem_op_alloc_page, OP=0x7, IDX=0x0

bf_mem_op_alloc_page allocates a page, and maps this page into the direct map of the VM.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of bf_handle_op_open_handle |

**Output:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | The virtual address of the resulting page |
| REG1 | 63:0 | The physical address of the resulting page |

**const, bf_uint64_t: BF_MEM_OP_ALLOC_PAGE_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000000 | Defines the syscall index for bf_mem_op_alloc_page |

### 2.14.2. bf_mem_op_free_page, OP=0x7, IDX=0x1

Frees a page previously allocated by bf_mem_op_alloc_page. This operation is optional and not all microkernels may implement it.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of bf_handle_op_open_handle |
| REG1 | 63:0 | The virtual address of the page to free |

**Output:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |

**const, bf_uint64_t: BF_MEM_OP_FREE_PAGE_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000001 | Defines the syscall index for bf_mem_op_free_page |


### 2.14.3. bf_mem_op_alloc_huge, OP=0x7, IDX=0x2

bf_mem_op_alloc_huge allocates a physically contiguous block of memory. When allocating a page, the extension should keep in mind the following:
- The total memory available to allocate from this pool is extremely limited. This should only be used when absolutely needed, and extensions should not expect more than 1 MB (might be less) of total memory available.
- Memory allocated from the huge pool might be allocated using different schemes. For example, the microkernel might allocate in increments of a page, or it might use a buddy allocator that would allocate in multiples of 2. If the allocation size doesn't match the algorithm, internal fragmentation could occur, further limiting the total number of allocations this pool can support.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of bf_handle_op_open_handle |
| REG1 | 63:0 | The total number of bytes to allocate |

**Output:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | The virtual address of the resulting memory |
| REG1 | 63:0 | The physical address of the resulting memory |

**const, bf_uint64_t: BF_MEM_OP_ALLOC_HUGE_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000002 | Defines the syscall index for bf_mem_op_alloc_huge |

### 2.14.4. bf_mem_op_free_huge, OP=0x7, IDX=0x3

Frees memory previously allocated by bf_mem_op_alloc_huge. This operation is optional and not all microkernels may implement it.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of bf_handle_op_open_handle |
| REG1 | 63:0 | The virtual address of the memory to free |

**Output:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |

**const, bf_uint64_t: BF_MEM_OP_FREE_HUGE_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000003 | Defines the syscall index for bf_mem_op_free_huge |

### 2.14.5. bf_mem_op_alloc_heap, OP=0x7, IDX=0x4

bf_mem_op_alloc_heap allocates heap memory. When allocating heap memory, the extension should keep in mind the following:
- This ABI is designed to work similar to sbrk() to support malloc/free implementations common with existing open source libraries.
- Calling this ABI with with a size of 0 will return the current heap location.
- Calling this ABI with a size (in bytes) will result in return the previous heap location. The current heap location will be set to the previous location, plus the provide size, rounded to the nearest page size.
- The heap is not mapped into the direct map, so virtual to physical (and vice versa) translations are not possible.
- There is no ability to free heap memory

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of bf_handle_op_open_handle |
| REG1 | 63:0 | The number of bytes to increase the heap by |

**Output:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | The virtual address of the previous heap location |

**const, bf_uint64_t: BF_MEM_OP_ALLOC_HEAP_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000004 | Defines the syscall index for bf_mem_op_alloc_heap |
