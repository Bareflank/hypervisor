## Table of Contents <!-- omit in toc -->

- [1. Introduction](#1-introduction)
  - [1.1. Reserved Values](#11-reserved-values)
  - [1.2. Document Revision](#12-document-revision)
  - [1.3. Glossary](#13-glossary)
  - [1.4. Scalar Types](#14-scalar-types)
  - [1.5. Memory Address Types](#15-memory-address-types)
  - [1.6. ID Types](#16-id-types)
  - [1.7. Constants, Structures, Enumerations, and Bit Fields](#17-constants-structures-enumerations-and-bit-fields)
    - [1.7.1. Null](#171-null)
    - [1.7.2. Handle Type](#172-handle-type)
    - [1.7.3. Register Type](#173-register-type)
    - [1.7.4. Exit Type](#174-exit-type)
    - [1.7.5. Bootstrap Callback Handler Type](#175-bootstrap-callback-handler-type)
    - [1.7.6. VMExit Callback Handler Type](#176-vmexit-callback-handler-type)
    - [1.7.7. Fast Fail Callback Handler Type](#177-fast-fail-callback-handler-type)
  - [1.8. Endianness](#18-endianness)
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
  - [2.7. Control Syscalls](#27-control-syscalls)
    - [2.7.1. bf_control_op_exit, OP=0x0, IDX=0x0](#271-bf_control_op_exit-op0x0-idx0x0)
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
  - [2.10. Callback Syscalls](#210-callback-syscalls)
    - [2.10.1. bf_callback_op_wait, OP=0x3, IDX=0x0](#2101-bf_callback_op_wait-op0x3-idx0x0)
    - [2.10.2. bf_callback_op_register_bootstrap, OP=0x3, IDX=0x2](#2102-bf_callback_op_register_bootstrap-op0x3-idx0x2)
    - [2.10.3. bf_callback_op_register_vmexit, OP=0x3, IDX=0x3](#2103-bf_callback_op_register_vmexit-op0x3-idx0x3)
    - [2.10.4. bf_callback_op_register_fail, OP=0x3, IDX=0x4](#2104-bf_callback_op_register_fail-op0x3-idx0x4)
  - [2.11. Virtual Machine (VM)](#211-virtual-machine-vm)
  - [2.12. Virtual Machine ID (VMID)](#212-virtual-machine-id-vmid)
  - [2.13. Virtual Machine Syscalls](#213-virtual-machine-syscalls)
    - [2.13.1. bf_vm_op_create_vm, OP=0x4, IDX=0x0](#2131-bf_vm_op_create_vm-op0x4-idx0x0)
    - [2.13.2. bf_vm_op_destroy_vm, OP=0x4, IDX=0x1](#2132-bf_vm_op_destroy_vm-op0x4-idx0x1)
  - [2.14. Virtual Processor (VP)](#214-virtual-processor-vp)
  - [2.15. Virtual Processor ID (VPID)](#215-virtual-processor-id-vpid)
  - [2.16. Virtual Processor Syscalls](#216-virtual-processor-syscalls)
    - [2.16.1. bf_vp_op_create_vp, OP=0x5, IDX=0x0](#2161-bf_vp_op_create_vp-op0x5-idx0x0)
    - [2.16.2. bf_vp_op_destroy_vp, OP=0x5, IDX=0x1](#2162-bf_vp_op_destroy_vp-op0x5-idx0x1)
  - [2.17. Virtual Processor State (VPS)](#217-virtual-processor-state-vps)
  - [2.18. Virtual Processor State ID (VPSID)](#218-virtual-processor-state-id-vpsid)
  - [2.19. Virtual Processor State Syscalls](#219-virtual-processor-state-syscalls)
    - [2.19.1. bf_vps_op_create_vps, OP=0x6, IDX=0x0](#2191-bf_vps_op_create_vps-op0x6-idx0x0)
    - [2.19.2. bf_vps_op_destroy_vps, OP=0x6, IDX=0x1](#2192-bf_vps_op_destroy_vps-op0x6-idx0x1)
    - [2.19.3. bf_vps_op_init_as_root, OP=0x6, IDX=0x2](#2193-bf_vps_op_init_as_root-op0x6-idx0x2)
    - [2.19.4. bf_vps_op_read8, OP=0x6, IDX=0x3](#2194-bf_vps_op_read8-op0x6-idx0x3)
    - [2.19.5. bf_vps_op_read16, OP=0x6, IDX=0x4](#2195-bf_vps_op_read16-op0x6-idx0x4)
    - [2.19.6. bf_vps_op_read32, OP=0x6, IDX=0x5](#2196-bf_vps_op_read32-op0x6-idx0x5)
    - [2.19.7. bf_vps_op_read64, OP=0x6, IDX=0x6](#2197-bf_vps_op_read64-op0x6-idx0x6)
    - [2.19.8. bf_vps_op_write8, OP=0x6, IDX=0x7](#2198-bf_vps_op_write8-op0x6-idx0x7)
    - [2.19.9. bf_vps_op_write16, OP=0x6, IDX=0x8](#2199-bf_vps_op_write16-op0x6-idx0x8)
    - [2.19.10. bf_vps_op_write32, OP=0x6, IDX=0x9](#21910-bf_vps_op_write32-op0x6-idx0x9)
    - [2.19.11. bf_vps_op_write64, OP=0x6, IDX=0xA](#21911-bf_vps_op_write64-op0x6-idx0xa)
    - [2.19.12. bf_vps_op_read_reg, OP=0x6, IDX=0xB](#21912-bf_vps_op_read_reg-op0x6-idx0xb)
    - [2.19.13. bf_vps_op_write_reg, OP=0x6, IDX=0xC](#21913-bf_vps_op_write_reg-op0x6-idx0xc)
    - [2.19.14. bf_vps_op_run, OP=0x5, IDX=0xD](#21914-bf_vps_op_run-op0x5-idx0xd)
    - [2.19.15. bf_vps_op_run_current, OP=0x5, IDX=0xE](#21915-bf_vps_op_run_current-op0x5-idx0xe)
    - [2.19.16. bf_vps_op_advance_ip, OP=0x5, IDX=0xF](#21916-bf_vps_op_advance_ip-op0x5-idx0xf)
    - [2.19.17. bf_vps_op_advance_ip_and_run_current, OP=0x5, IDX=0x10](#21917-bf_vps_op_advance_ip_and_run_current-op0x5-idx0x10)
    - [2.19.18. bf_vps_op_promote, OP=0x5, IDX=0x11](#21918-bf_vps_op_promote-op0x5-idx0x11)
  - [2.20. Intrinsic Syscalls](#220-intrinsic-syscalls)
    - [2.20.1. bf_intrinsic_op_read_msr, OP=0x7, IDX=0x0](#2201-bf_intrinsic_op_read_msr-op0x7-idx0x0)
    - [2.20.2. bf_intrinsic_op_write_msr, OP=0x7, IDX=0x1](#2202-bf_intrinsic_op_write_msr-op0x7-idx0x1)
  - [2.21. Mem Syscalls](#221-mem-syscalls)
    - [2.21.1. bf_mem_op_alloc_page, OP=0x7, IDX=0x0](#2211-bf_mem_op_alloc_page-op0x7-idx0x0)
    - [2.21.2. bf_mem_op_free_page, OP=0x7, IDX=0x1](#2212-bf_mem_op_free_page-op0x7-idx0x1)
    - [2.21.3. bf_mem_op_alloc_huge, OP=0x7, IDX=0x2](#2213-bf_mem_op_alloc_huge-op0x7-idx0x2)
    - [2.21.4. bf_mem_op_free_huge, OP=0x7, IDX=0x3](#2214-bf_mem_op_free_huge-op0x7-idx0x3)
    - [2.21.5. bf_mem_op_alloc_heap, OP=0x7, IDX=0x4](#2215-bf_mem_op_alloc_heap-op0x7-idx0x4)
    - [2.21.6. bf_mem_op_free_heap, OP=0x7, IDX=0x5](#2216-bf_mem_op_free_heap-op0x7-idx0x5)
    - [2.21.7. bf_mem_op_virt_to_phys, OP=0x7, IDX=0x6](#2217-bf_mem_op_virt_to_phys-op0x7-idx0x6)

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
| bf_ptr_t | void const * | Defines a raw pointer type |

## 1.5. Memory Address Types

| Name | Type |
| :--- | :--- |
| System Physical Address (SPA) | bf_uint64_t |
| Guest Physical Address (GPA) | bf_uint64_t |
| Guest Virtual Address (GVA) | bf_uint64_t |

## 1.6. ID Types

| Name | Type |
| :--- | :--- |
| Virtual Machine ID (VMID) | bf_uint64_t |
| Virtual Processor ID (VPID) | bf_uint64_t |
| Virtual Processor State ID (VPSID) | bf_uint64_t |
| Physical Processor ID (PPID) | bf_uint64_t |

## 1.7. Constants, Structures, Enumerations, and Bit Fields

### 1.7.1. Null

**const, void *: BF_NULL**
| Value | Description |
| :---- | :---------- |
| 0 | Defines the value of a null pointer |

### 1.7.2. Handle Type

The bf_handle_t structure is an opaque structure containing the handle used by most of the syscalls in this specification. The opaque structure is used internally by the C wrapper interface and should not be accessed directly. The C wrapper is allowed to redefine the internal layout of this structure at any time (e.g., the C wrapper might provide an alternative layout for unit testing).

**struct: bf_handle_t**
| Name | Type | Offset | Size | Description |
| :--- | :--- | :----- | :--- | :---------- |
| hndl | bf_uint64_t | 0x0 | 8 bytes | The handle returned by bf_handle_op_open_handle |

### 1.7.3. Register Type

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

### 1.7.4. Exit Type

Defines the exit type used by bf_control_op_exit

**enum, bf_uint64_t: bf_exit_status_t**
| Name | Value | Description |
| :--- | :---- | :---------- |
| bf_exit_status_t_success | 0 | Exit with a success code |
| bf_exit_status_t_failure | 1 | Exit with a failure code |

### 1.7.5. Bootstrap Callback Handler Type

Defines the signature of the bootstrap callback handler

**typedef, void(*bf_callback_handler_bootstrap_t)(bf_uint16_t)**

### 1.7.6. VMExit Callback Handler Type

Defines the signature of the VM exit callback handler

**typedef, void(*bf_callback_handler_vmexit_t)(bsl::bf_uint16_t, bf_uint64_t)**

### 1.7.7. Fast Fail Callback Handler Type

Defines the signature of the fast fail callback handler

**typedef, void(*bf_callback_handler_fail_t)()**

## 1.8. Endianness

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

**const, bf_uint64_t: BF_STATUS_SIG_MASK**
| Value | Description |
| :---- | :---------- |
| 0xFFFF000000000000 | Defines a mask for BF_STATUS_SIG |

**const, bf_uint32_t: BF_STATUS_FLAGS_MASK**
| Value | Description |
| :---- | :---------- |
| 0x0000FFFFFFFF0000 | Defines a mask for BF_STATUS_FLAGS |

**const, bf_uint32_t: BF_STATUS_VALUE_MASK**
| Value | Description |
| :---- | :---------- |
| 0x000000000000FFFF | Defines a mask for BF_STATUS_VALUE |

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

Although there is only one thread per PP, a thread's ID changes based on the active extension, VM and VP. If a thread's ID changes, it's TLS block does not, meaning an extension is given one TLS block per PP, regardless of which VM or VP is active.

In addition, the layout of the TLS block uses a scheme similar to the ELF TLS specification, but with some modifications. Unlike the ELF TLS specification, each TLS block is limited to two pages. The lower half of the page is dedicated to "thread_local" storage. The upper half is defined by this specification, and provides access to registers shared between the microkernel and the extension to improve performance. For example, access to a VM's general purpose registers is available from the TLS block.

## 2.7. Control Syscalls

### 2.7.1. bf_control_op_exit, OP=0x0, IDX=0x0

This syscall tells the microkernel to stop the execution of an extension, providing a means to fast fail.

**const, bf_uint64_t: BF_CONTROL_OP_EXIT_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000000 | Defines the syscall index for bf_control_op_exit |

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

**WARNING:**
In production builds of Bareflank, this syscall is not present.

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

**WARNING:**
In production builds of Bareflank, this syscall is not present.

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

**WARNING:**
In production builds of Bareflank, this syscall is not present.

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

**WARNING:**
In production builds of Bareflank, this syscall is not present.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | The VPSID of the VPS's state to output |

**const, bf_uint64_t: BF_DEBUG_OP_DUMP_VPS_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000003 | Defines the syscall index for bf_debug_op_dump_vps |

### 2.9.5. bf_debug_op_dump_vmexit_log, OP=0x2, IDX=0x4

This syscall tells the microkernel to output the VMExit log. The VMExit log is a chronological log of the "X" number of exits that have occurred. The total number of "X" logs is implementation-defined and not under the control of software.

**WARNING:**
In production builds of Bareflank, this syscall is not present.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | The VPID of the VP to dump the log from |

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

## 2.10. Callback Syscalls

### 2.10.1. bf_callback_op_wait, OP=0x3, IDX=0x0

This syscall tells the microkernel that the extension would like to wait for a callback. This syscall is a blocking syscall that never returns and should be used to return from the _start function.

**const, bf_uint64_t: BF_CALLBACK_OP_WAIT_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000000 | Defines the syscall index for bf_callback_op_wait |

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

## 2.11. Virtual Machine (VM)

A Virtual Machine or VM virtually represents a physical computer. Although the microkernel has an internal representation of a VM, it doesn't understand what a VM is outside of resource management, and it is up to the extension to define what a VM is and how it should operate.

## 2.12. Virtual Machine ID (VMID)

The Virtual Machine ID  (VMID) is a 16bit number that uniquely identifies a VM.

## 2.13. Virtual Machine Syscalls

### 2.13.1. bf_vm_op_create_vm, OP=0x4, IDX=0x0

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

### 2.13.2. bf_vm_op_destroy_vm, OP=0x4, IDX=0x1

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

## 2.14. Virtual Processor (VP)

TODO

## 2.15. Virtual Processor ID (VPID)

The Virtual Processor ID (VPID) is a 16bit number that uniquely identifies a VP.

## 2.16. Virtual Processor Syscalls

### 2.16.1. bf_vp_op_create_vp, OP=0x5, IDX=0x0

This syscall tells the microkernel to create a VP and return its ID.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of bf_handle_op_open_handle |

**Output:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 15:0 | The resulting VPID of the newly created VP |
| REG0 | 63:16 | REVI |

**const, bf_uint64_t: BF_VP_OP_CREATE_VP_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000000 | Defines the syscall index for bf_vp_op_create_vp |

### 2.16.2. bf_vp_op_destroy_vp, OP=0x5, IDX=0x1

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

## 2.17. Virtual Processor State (VPS)

TODO

## 2.18. Virtual Processor State ID (VPSID)

The Virtual Processor State ID (VPSID) is a 16bit number that uniquely identifies a VPS.

## 2.19. Virtual Processor State Syscalls

### 2.19.1. bf_vps_op_create_vps, OP=0x6, IDX=0x0

This syscall tells the microkernel to create a VPS and return its ID.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of bf_handle_op_open_handle |

**Output:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 15:0 | The resulting VPSID of the newly created VPS |
| REG0 | 63:16 | REVI |

**const, bf_uint64_t: BF_VPS_OP_CREATE_VPS_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000000 | Defines the syscall index for bf_vps_op_create_vps |

### 2.19.2. bf_vps_op_destroy_vps, OP=0x6, IDX=0x1

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

### 2.19.3. bf_vps_op_init_as_root, OP=0x6, IDX=0x2

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

### 2.19.4. bf_vps_op_read8, OP=0x6, IDX=0x3

bf_vps_op_read8 reads an 8bit field from the VPS and returns the value. The "index" is architecture-specific. For Intel, Appendix B, "Field Encoding in VMCS," defines the index (or encoding). For AMD, Appendix B, "Layout of VMCB," defines the index (or offset).

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

### 2.19.5. bf_vps_op_read16, OP=0x6, IDX=0x4

bf_vps_op_read16 reads a 16bit field from the VPS and returns the value. The "index" is architecture-specific. For Intel, Appendix B, "Field Encoding in VMCS," defines the index (or encoding). For AMD, Appendix B, "Layout of VMCB," defines the index (or offset).

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

### 2.19.6. bf_vps_op_read32, OP=0x6, IDX=0x5

bf_vps_op_read32 reads a 32bit field from the VPS and returns the value. The "index" is architecture-specific. For Intel, Appendix B, "Field Encoding in VMCS," defines the index (or encoding). For AMD, Appendix B, "Layout of VMCB," defines the index (or offset).

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

### 2.19.7. bf_vps_op_read64, OP=0x6, IDX=0x6

bf_vps_op_read64 reads a 64bit field from the VPS and returns the value. The "index" is architecture-specific. For Intel, Appendix B, "Field Encoding in VMCS," defines the index (or encoding). For AMD, Appendix B, "Layout of VMCB," defines the index (or offset).

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

### 2.19.8. bf_vps_op_write8, OP=0x6, IDX=0x7

bf_vps_op_write8 writes to an 8bit field in the VPS. The "index" is architecture-specific. For Intel, Appendix B, "Field Encoding in VMCS," defines the index (or encoding). For AMD, Appendix B, "Layout of VMCB," defines the index (or offset).

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

### 2.19.9. bf_vps_op_write16, OP=0x6, IDX=0x8

bf_vps_op_write16 writes to a 16bit field in the VPS. The "index" is architecture-specific. For Intel, Appendix B, "Field Encoding in VMCS," defines the index (or encoding). For AMD, Appendix B, "Layout of VMCB," defines the index (or offset).

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

### 2.19.10. bf_vps_op_write32, OP=0x6, IDX=0x9

bf_vps_op_write32 writes to a 32bit field in the VPS. The "index" is architecture-specific. For Intel, Appendix B, "Field Encoding in VMCS," defines the index (or encoding). For AMD, Appendix B, "Layout of VMCB," defines the index (or offset).

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

### 2.19.11. bf_vps_op_write64, OP=0x6, IDX=0xA

bf_vps_op_write64 writes to a 64bit field in the VPS. The "index" is architecture-specific. For Intel, Appendix B, "Field Encoding in VMCS," defines the index (or encoding). For AMD, Appendix B, "Layout of VMCB," defines the index (or offset).

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

### 2.19.12. bf_vps_op_read_reg, OP=0x6, IDX=0xB

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

### 2.19.13. bf_vps_op_write_reg, OP=0x6, IDX=0xC

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

### 2.19.14. bf_vps_op_run, OP=0x5, IDX=0xD

bf_vps_op_run tells the microkernel to execute a given VPS on behalf of a given VP and VM. This system call only returns if an error occurs. On success, this system call will physically execute the requested VP using the requested VPS, and the extension will only execute again on the next VMExit.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of bf_handle_op_open_handle |
| REG1 | 15:0 | The VPSID of the VPS to run |
| REG1 | 63:16 | REVI |
| REG2 | 15:0 | The VPID of the VP to run |
| REG2 | 63:16 | REVI |
| REG3 | 15:0 | The VMID of the VM to run |
| REG3 | 63:16 | REVI |

**const, bf_uint64_t: BF_VPS_OP_RUN_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x000000000000000D | Defines the syscall index for bf_vps_op_run |

### 2.19.15. bf_vps_op_run_current, OP=0x5, IDX=0xE

bf_vps_op_run_current tells the microkernel to execute the currently active VPS, VP and VM.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of bf_handle_op_open_handle |

**const, bf_uint64_t: BF_VPS_OP_RUN_CURRENT_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x000000000000000E | Defines the syscall index for bf_vps_op_run_current |

### 2.19.16. bf_vps_op_advance_ip, OP=0x5, IDX=0xF

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

### 2.19.17. bf_vps_op_advance_ip_and_run_current, OP=0x5, IDX=0x10

This syscall tells the microkernel to advance the instruction pointer in the requested VPS and run the currently active VPS, VP and VM (i.e., this combines bf_vps_op_advance_ip and bf_vps_op_advance_ip).

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of bf_handle_op_open_handle |
| REG1 | 15:0 | The VPSID of the VPS advance the IP in |
| REG1 | 63:16 | REVI |

**const, bf_uint64_t: BF_VPS_OP_ADVANCE_IP_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000010 | Defines the syscall index for bf_vps_op_advance_ip_and_run_current |

### 2.19.18. bf_vps_op_promote, OP=0x5, IDX=0x11

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

## 2.20. Intrinsic Syscalls

### 2.20.1. bf_intrinsic_op_read_msr, OP=0x7, IDX=0x0

Reads an MSR directly from the CPU given the address of the MSR to read. Note that this is specific to Intel/AMD only.

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

**const, bf_uint64_t: BF_INTRINSIC_OP_READ_MSR_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000000 | Defines the syscall index for bf_intrinsic_op_read_msr |

### 2.20.2. bf_intrinsic_op_write_msr, OP=0x7, IDX=0x1

Writes to an MSR directly from the CPU given the address of the MSR to write and the value to write. Note that this is specific to Intel/AMD only.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of bf_handle_op_open_handle |
| REG1 | 31:0 | The address of the MSR to write to |
| REG1 | 63:32 | REVI |
| REG2 | 63:0 | The value to write to the requested MSR |

**const, bf_uint64_t: BF_INTRINSIC_OP_WRITE_MSR_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000001 | Defines the syscall index for bf_intrinsic_op_write_msr |

## 2.21. Mem Syscalls

Each extension has access to several different memory pools:
- The page pool (used for allocating pages)
- The huge pool (used for allocating physically contiguous pages)
- The heap pool (used for allocating heap memory)
- TLS (used for thread-local storage)
- The direct map

The page pool provides a means to allocate a page. Allocated pages are **not** mapped into the microkernel, and therefore are safe for storing secrets if needed (at least as safe as it is going to get). Page allocation (and freeing) is a slow process as several different page walks are involved.

The huge pool provides a method for allocating physically contiguous memory. This pool is small and platform-dependent (as in less than a megabyte total).

The heap pool provides memory that can only be grown or shrunk, meaning the memory must always remain contiguous. An extension is free to use heap memory or the page pool. Both unmap any allocated pages from the microkernel, and both are slow. The only difference between these two pools is the page pool can only allocate a single page at a time and may or may not be fragmented (depends on the implementation). The heap pool can allocate memory of any size (must be a multiple of a page) and never fragments. Freeing memory is also different. An extension can free any page from the page pool (although the virtual address associated with the page may remain allocated, meaning the memory is reusable, but the virtual address is not, leading to potential exhaustion of the virtual memory space). The heap pool can only be grown or shrunk, meaning the free operation reduces the heap pool's size.

Allocations must all occur during the bootstrap phase of the extension. Once an extension has executed bf_vps_op_run, allocations are no longer allowed.

Thread-Local Storage (TLS) memory (typically allocated using `thread_local`) provides per-thread storage. The amount of TLS available to an extension depends on the configuration of the hypervisor.

The direct map provides an extension with a means to access any physical address by accessing the direct map region of the virtual address space (depends on the hypervisor's configuration). By default, on Intel/AMD with 4-level paging, this region starts at 0x0000400000000000. An extension can access any physical address by simply adding 0x0000400000000000 to the physical address and dereferencing the resulting value. Note that not all extensions can access the direct map (depends on the microkernel's security policy), and not all physical addresses are accessible. For example, any physical address mapped into the microkernel or another extension cannot be mapped (meaning a physical address can only be mapped once by the entire hypervisor). The microkernel also provides a per-VM direct map to provide additional mitigations for transient execution attacks. This feature is seamless to an extension, meaning, so long as an extension has the right to map a physical address, any attempt to access a legal, physical address will successfully map.

### 2.21.1. bf_mem_op_alloc_page, OP=0x7, IDX=0x0

bf_mem_op_alloc_page allocates a page. When allocating a page, the extension should keep in mind the following:
- The microkernel removes the page from its address space, which requires a page walk, which means that this operation is slow.
- Virtual address to physical address conversions require a page walk, so they are slow.
- The microkernel does not support physical address to virtual address conversions.
- Whether or not bf_mem_op_free_page frees the allocated virtual address is implementation-specific and not known to the extension, which could lead to the virtual address space's exhaustion.
- The execution of bf_mem_op_free_page is also slow, as a page walk is also needed.

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

### 2.21.2. bf_mem_op_free_page, OP=0x7, IDX=0x1

Frees a page previously allocated by bf_mem_op_alloc_page. For more information, please see bf_mem_op_alloc_page.

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


### 2.21.3. bf_mem_op_alloc_huge, OP=0x7, IDX=0x2

TBD

### 2.21.4. bf_mem_op_free_huge, OP=0x7, IDX=0x3

TBD

### 2.21.5. bf_mem_op_alloc_heap, OP=0x7, IDX=0x4

TBD

### 2.21.6. bf_mem_op_free_heap, OP=0x7, IDX=0x5

TBD

### 2.21.7. bf_mem_op_virt_to_phys, OP=0x7, IDX=0x6

bf_mem_op_virt_to_phys converts a provided virtual address to a physical address for any virtual address allocated using bf_mem_op_alloc_page, bf_mem_op_alloc_huge, bf_mem_op_alloc_heap or mapped using the direct map.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of bf_handle_op_open_handle |
| REG1 | 63:0 | The virtual address of the page to convert |

**Output:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | The physical address of the provided virtual address |

**const, bf_uint64_t: BF_MEM_OP_VIRT_TO_PHYS_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000006 | Defines the syscall index for bf_mem_op_virt_to_phys |
