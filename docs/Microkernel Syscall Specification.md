## Table of Contents <!-- omit in toc -->

- [1. Introduction](#1-introduction)
  - [1.1. Reserved Values](#11-reserved-values)
  - [1.2. Document Revision](#12-document-revision)
  - [1.3. Glossary](#13-glossary)
  - [1.4. Constants, Structures, Enumerations, and Bit Fields](#14-constants-structures-enumerations-and-bit-fields)
    - [1.4.1. Handle Type](#141-handle-type)
    - [1.4.2. Register Type](#142-register-type)
      - [1.4.2.1. AMD](#1421-amd)
      - [1.4.2.2. Intel](#1422-intel)
    - [1.4.3. Exit Type](#143-exit-type)
    - [1.4.4. Bootstrap Callback Handler Type](#144-bootstrap-callback-handler-type)
    - [1.4.5. VMExit Callback Handler Type](#145-vmexit-callback-handler-type)
    - [1.4.6. Fast Fail Callback Handler Type](#146-fast-fail-callback-handler-type)
  - [1.5. ID Constants](#15-id-constants)
  - [1.6. Endianness](#16-endianness)
  - [1.7. Host PAT (Intel/AMD Only)](#17-host-pat-intelamd-only)
- [2. Syscall Interface](#2-syscall-interface)
  - [2.1. Legal Syscall Environments](#21-legal-syscall-environments)
  - [2.2. Alignment Requirements](#22-alignment-requirements)
  - [2.3. Syscall Status Codes](#23-syscall-status-codes)
    - [2.3.1. BF_STATUS_SUCCESS, VALUE=0](#231-bf_status_success-value0)
    - [2.3.2. BF_STATUS_FAILURE, VALUE=1](#232-bf_status_failure-value1)
    - [2.3.3. BF_STATUS_INVALID_PERM, VALUE=2](#233-bf_status_invalid_perm-value2)
    - [2.3.4. BF_STATUS_INVALID_PARAMS, VALUE=3](#234-bf_status_invalid_params-value3)
  - [2.4. Syscall Inputs](#24-syscall-inputs)
  - [2.5. Syscall Outputs](#25-syscall-outputs)
  - [2.6. Syscall Opcodes](#26-syscall-opcodes)
    - [2.6.1. Control Support](#261-control-support)
    - [2.6.2. Handle Support](#262-handle-support)
    - [2.6.3. Debug Support](#263-debug-support)
    - [2.6.4. Callback Support](#264-callback-support)
    - [2.6.5. VM Support](#265-vm-support)
    - [2.6.6. VP Support](#266-vp-support)
    - [2.6.7. VS Support](#267-vs-support)
    - [2.6.8. Intrinsic Support](#268-intrinsic-support)
    - [2.6.9. Mem Support](#269-mem-support)
  - [2.7. Syscall Specification IDs](#27-syscall-specification-ids)
  - [2.8. Thread Local Storage](#28-thread-local-storage)
    - [2.8.1. TLS Offsets](#281-tls-offsets)
  - [2.9. Control Syscalls](#29-control-syscalls)
    - [2.9.1. bf_control_op_exit, OP=0x0, IDX=0x0](#291-bf_control_op_exit-op0x0-idx0x0)
    - [2.9.2. bf_control_op_wait, OP=0x0, IDX=0x1](#292-bf_control_op_wait-op0x0-idx0x1)
    - [2.9.3. bf_control_op_again, OP=0x0, IDX=0x2](#293-bf_control_op_again-op0x0-idx0x2)
  - [2.10. Handle Syscalls](#210-handle-syscalls)
    - [2.10.1. bf_handle_op_open_handle, OP=0x1, IDX=0x0](#2101-bf_handle_op_open_handle-op0x1-idx0x0)
    - [2.10.2. bf_handle_op_close_handle, OP=0x1, IDX=0x1](#2102-bf_handle_op_close_handle-op0x1-idx0x1)
  - [2.11. Debug Syscalls](#211-debug-syscalls)
    - [2.11.1. bf_debug_op_out, OP=0x2, IDX=0x0](#2111-bf_debug_op_out-op0x2-idx0x0)
    - [2.11.2. bf_debug_op_dump_vm, OP=0x2, IDX=0x1](#2112-bf_debug_op_dump_vm-op0x2-idx0x1)
    - [2.11.3. bf_debug_op_dump_vp, OP=0x2, IDX=0x2](#2113-bf_debug_op_dump_vp-op0x2-idx0x2)
    - [2.11.4. bf_debug_op_dump_vs, OP=0x2, IDX=0x3](#2114-bf_debug_op_dump_vs-op0x2-idx0x3)
    - [2.11.5. bf_debug_op_dump_vmexit_log, OP=0x2, IDX=0x4](#2115-bf_debug_op_dump_vmexit_log-op0x2-idx0x4)
    - [2.11.6. bf_debug_op_write_c, OP=0x2, IDX=0x5](#2116-bf_debug_op_write_c-op0x2-idx0x5)
    - [2.11.7. bf_debug_op_write_str, OP=0x2, IDX=0x6](#2117-bf_debug_op_write_str-op0x2-idx0x6)
    - [2.11.8. bf_debug_op_dump_ext, OP=0x2, IDX=0x7](#2118-bf_debug_op_dump_ext-op0x2-idx0x7)
    - [2.11.9. bf_debug_op_dump_page_pool, OP=0x2, IDX=0x8](#2119-bf_debug_op_dump_page_pool-op0x2-idx0x8)
    - [2.11.10. bf_debug_op_dump_huge_pool, OP=0x2, IDX=0x9](#21110-bf_debug_op_dump_huge_pool-op0x2-idx0x9)
  - [2.12. Callback Syscalls](#212-callback-syscalls)
    - [2.12.1. bf_callback_op_register_bootstrap, OP=0x3, IDX=0x0](#2121-bf_callback_op_register_bootstrap-op0x3-idx0x0)
    - [2.12.2. bf_callback_op_register_vmexit, OP=0x3, IDX=0x1](#2122-bf_callback_op_register_vmexit-op0x3-idx0x1)
    - [2.12.3. bf_callback_op_register_fail, OP=0x3, IDX=0x2](#2123-bf_callback_op_register_fail-op0x3-idx0x2)
  - [2.13. Virtual Machine Syscalls](#213-virtual-machine-syscalls)
    - [2.13.1. bf_vm_op_create_vm, OP=0x4, IDX=0x0](#2131-bf_vm_op_create_vm-op0x4-idx0x0)
    - [2.13.2. bf_vm_op_destroy_vm, OP=0x4, IDX=0x1](#2132-bf_vm_op_destroy_vm-op0x4-idx0x1)
    - [2.13.3. bf_vm_op_map_direct, OP=0x4, IDX=0x2](#2133-bf_vm_op_map_direct-op0x4-idx0x2)
    - [2.13.4. bf_vm_op_unmap_direct, OP=0x4, IDX=0x3](#2134-bf_vm_op_unmap_direct-op0x4-idx0x3)
    - [2.13.5. bf_vm_op_unmap_direct_broadcast, OP=0x4, IDX=0x4](#2135-bf_vm_op_unmap_direct_broadcast-op0x4-idx0x4)
    - [2.13.6. bf_vm_op_tlb_flush, OP=0x4, IDX=0x5](#2136-bf_vm_op_tlb_flush-op0x4-idx0x5)
  - [2.14. Virtual Processor Syscalls](#214-virtual-processor-syscalls)
    - [2.14.1. bf_vp_op_create_vp, OP=0x5, IDX=0x0](#2141-bf_vp_op_create_vp-op0x5-idx0x0)
    - [2.14.2. bf_vp_op_destroy_vp, OP=0x5, IDX=0x1](#2142-bf_vp_op_destroy_vp-op0x5-idx0x1)
  - [2.15. Virtual Processor State Syscalls](#215-virtual-processor-state-syscalls)
    - [2.15.1. bf_vs_op_create_vs, OP=0x6, IDX=0x0](#2151-bf_vs_op_create_vs-op0x6-idx0x0)
    - [2.15.2. bf_vs_op_destroy_vs, OP=0x6, IDX=0x1](#2152-bf_vs_op_destroy_vs-op0x6-idx0x1)
    - [2.15.3. bf_vs_op_init_as_root, OP=0x6, IDX=0x2](#2153-bf_vs_op_init_as_root-op0x6-idx0x2)
    - [2.15.4. bf_vs_op_read, OP=0x6, IDX=0x3](#2154-bf_vs_op_read-op0x6-idx0x3)
    - [2.15.5. bf_vs_op_write, OP=0x6, IDX=0x4](#2155-bf_vs_op_write-op0x6-idx0x4)
    - [2.15.6. bf_vs_op_run, OP=0x6, IDX=0x5](#2156-bf_vs_op_run-op0x6-idx0x5)
    - [2.15.7. bf_vs_op_run_current, OP=0x6, IDX=0x6](#2157-bf_vs_op_run_current-op0x6-idx0x6)
    - [2.15.8. bf_vs_op_advance_ip_and_run_impl, OP=0x6, IDX=0x7](#2158-bf_vs_op_advance_ip_and_run_impl-op0x6-idx0x7)
    - [2.15.9. bf_vs_op_advance_ip_and_run_current, OP=0x6, IDX=0x8](#2159-bf_vs_op_advance_ip_and_run_current-op0x6-idx0x8)
    - [2.15.10. bf_vs_op_promote, OP=0x6, IDX=0x9](#21510-bf_vs_op_promote-op0x6-idx0x9)
    - [2.15.11. bf_vs_op_clear, OP=0x6, IDX=0xA](#21511-bf_vs_op_clear-op0x6-idx0xa)
    - [2.15.12. bf_vs_op_migrate, OP=0x6, IDX=0xB](#21512-bf_vs_op_migrate-op0x6-idx0xb)
    - [2.15.13. bf_vs_op_set_active, OP=0x6, IDX=0xC](#21513-bf_vs_op_set_active-op0x6-idx0xc)
    - [2.15.14. bf_vs_op_advance_ip_and_set_active, OP=0x6, IDX=0xD](#21514-bf_vs_op_advance_ip_and_set_active-op0x6-idx0xd)
    - [2.15.15. bf_vs_op_tlb_flush, OP=0x6, IDX=0xE](#21515-bf_vs_op_tlb_flush-op0x6-idx0xe)
  - [2.16. Intrinsic Syscalls](#216-intrinsic-syscalls)
    - [2.16.1. bf_intrinsic_op_rdmsr, OP=0x7, IDX=0x0](#2161-bf_intrinsic_op_rdmsr-op0x7-idx0x0)
    - [2.16.2. bf_intrinsic_op_wrmsr, OP=0x7, IDX=0x1](#2162-bf_intrinsic_op_wrmsr-op0x7-idx0x1)
  - [2.17. Mem Syscalls](#217-mem-syscalls)
    - [2.17.1. bf_mem_op_alloc_page, OP=0x8, IDX=0x0](#2171-bf_mem_op_alloc_page-op0x8-idx0x0)
    - [2.17.2. bf_mem_op_free_page, OP=0x8, IDX=0x1](#2172-bf_mem_op_free_page-op0x8-idx0x1)
    - [2.17.3. bf_mem_op_alloc_huge, OP=0x8, IDX=0x2](#2173-bf_mem_op_alloc_huge-op0x8-idx0x2)
    - [2.17.4. bf_mem_op_free_huge, OP=0x8, IDX=0x3](#2174-bf_mem_op_free_huge-op0x8-idx0x3)

# 1. Introduction

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
| PP | Physical Processor |
| VM | Virtual Machine |
| VP | Virtual Processor |
| VS | Virtual processor State |
| PPID | Physical Processor Identifier |
| VMID | Virtual Machine Identifier |
| VPID | Virtual Processor Identifier |
| VSID | Virtual Processor State Identifier |
| OS | Operating System |
| BIOS | Basic Input/Output System |
| UEFI | Unified Extensible Firmware Interface |
| SPA | A System Physical Address (SPA) refers to a physical address as seen by the system without the addition of virtualization |
| GPA | A Guest Physical Address (GPA) refers to a physical address as seen by a VM and requires a translation to convert to a SPA |
| GVA | A Guest Virtual Address (GVA) refers to a virtual address as seen by a VM and requires a guest controlled translation to convert to a GPA |
| Page Aligned | A region of memory whose address is divisible by 0x1000 |
| Page | A page aligned region of memory that is 0x1000 bytes in size |

## 1.4. Constants, Structures, Enumerations, and Bit Fields

### 1.4.1. Handle Type

The bf_handle_t structure is an opaque structure containing the handle used by most of the syscalls in this specification.

**struct: bf_handle_t**
| Name | Type | Offset | Size | Description |
| :--- | :--- | :----- | :--- | :---------- |
| hndl | uint64_t | 0x0 | 8 bytes | The handle returned by bf_handle_op_open_handle |

### 1.4.2. Register Type

Defines which register a syscall is requesting.

#### 1.4.2.1. AMD

**enum, uint64_t: bf_reg_t**
| Name | Value | Description |
| :--- | :---- | :---------- |
| bf_reg_t_unsupported | 0 | defines the unsupported register |
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
| bf_reg_t_intercept_cr_read | 15 | defines the intercept_cr_read register |
| bf_reg_t_intercept_cr_write | 16 | defines the intercept_cr_write register |
| bf_reg_t_intercept_dr_read | 17 | defines the intercept_dr_read register |
| bf_reg_t_intercept_dr_write | 18 | defines the intercept_dr_write register |
| bf_reg_t_intercept_exception | 19 | defines the intercept_exception register |
| bf_reg_t_intercept_instruction1 | 20 | defines the intercept_instruction1 register |
| bf_reg_t_intercept_instruction2 | 21 | defines the intercept_instruction2 register |
| bf_reg_t_intercept_instruction3 | 22 | defines the intercept_instruction3 register |
| bf_reg_t_pause_filter_threshold | 23 | defines the pause_filter_threshold register |
| bf_reg_t_pause_filter_count | 24 | defines the pause_filter_count register |
| bf_reg_t_iopm_base_pa | 25 | defines the iopm_base_pa register |
| bf_reg_t_msrpm_base_pa | 26 | defines the msrpm_base_pa register |
| bf_reg_t_tsc_offset | 27 | defines the tsc_offset register |
| bf_reg_t_guest_asid | 28 | defines the guest_asid register |
| bf_reg_t_tlb_control | 29 | defines the tlb_control register |
| bf_reg_t_virtual_interrupt_a | 30 | defines the virtual_interrupt_a register |
| bf_reg_t_virtual_interrupt_b | 31 | defines the virtual_interrupt_b register |
| bf_reg_t_exitcode | 32 | defines the exitcode register |
| bf_reg_t_exitinfo1 | 33 | defines the exitinfo1 register |
| bf_reg_t_exitinfo2 | 34 | defines the exitinfo2 register |
| bf_reg_t_exitininfo | 35 | defines the exitininfo register |
| bf_reg_t_ctls1 | 36 | defines the ctls1 register |
| bf_reg_t_avic_apic_bar | 37 | defines the avic_apic_bar register |
| bf_reg_t_guest_pa_of_ghcb | 38 | defines the guest_pa_of_ghcb register |
| bf_reg_t_eventinj | 39 | defines the eventinj register |
| bf_reg_t_n_cr3 | 40 | defines the n_cr3 register |
| bf_reg_t_ctls2 | 41 | defines the ctls2 register |
| bf_reg_t_vmcb_clean_bits | 42 | defines the vmcb_clean_bits register |
| bf_reg_t_nrip | 43 | defines the nrip register |
| bf_reg_t_number_of_bytes_fetched | 44 | defines the number_of_bytes_fetched register |
| bf_reg_t_avic_apic_backing_page_ptr | 45 | defines the avic_apic_backing_page_ptr register |
| bf_reg_t_avic_logical_table_ptr | 46 | defines the avic_logical_table_ptr register |
| bf_reg_t_avic_physical_table_ptr | 47 | defines the avic_physical_table_ptr register |
| bf_reg_t_vmsa_ptr | 48 | defines the vmsa_ptr register |
| bf_reg_t_es_selector | 49 | defines the es_selector register |
| bf_reg_t_es_attrib | 50 | defines the es_attrib register |
| bf_reg_t_es_limit | 51 | defines the es_limit register |
| bf_reg_t_es_base | 52 | defines the es_base register |
| bf_reg_t_cs_selector | 53 | defines the cs_selector register |
| bf_reg_t_cs_attrib | 54 | defines the cs_attrib register |
| bf_reg_t_cs_limit | 55 | defines the cs_limit register |
| bf_reg_t_cs_base | 56 | defines the cs_base register |
| bf_reg_t_ss_selector | 57 | defines the ss_selector register |
| bf_reg_t_ss_attrib | 58 | defines the ss_attrib register |
| bf_reg_t_ss_limit | 59 | defines the ss_limit register |
| bf_reg_t_ss_base | 60 | defines the ss_base register |
| bf_reg_t_ds_selector | 61 | defines the ds_selector register |
| bf_reg_t_ds_attrib | 62 | defines the ds_attrib register |
| bf_reg_t_ds_limit | 63 | defines the ds_limit register |
| bf_reg_t_ds_base | 64 | defines the ds_base register |
| bf_reg_t_fs_selector | 65 | defines the fs_selector register |
| bf_reg_t_fs_attrib | 66 | defines the fs_attrib register |
| bf_reg_t_fs_limit | 67 | defines the fs_limit register |
| bf_reg_t_fs_base | 68 | defines the fs_base register |
| bf_reg_t_gs_selector | 69 | defines the gs_selector register |
| bf_reg_t_gs_attrib | 70 | defines the gs_attrib register |
| bf_reg_t_gs_limit | 71 | defines the gs_limit register |
| bf_reg_t_gs_base | 72 | defines the gs_base register |
| bf_reg_t_gdtr_selector | 73 | defines the gdtr_selector register |
| bf_reg_t_gdtr_attrib | 74 | defines the gdtr_attrib register |
| bf_reg_t_gdtr_limit | 75 | defines the gdtr_limit register |
| bf_reg_t_gdtr_base | 76 | defines the gdtr_base register |
| bf_reg_t_ldtr_selector | 77 | defines the ldtr_selector register |
| bf_reg_t_ldtr_attrib | 78 | defines the ldtr_attrib register |
| bf_reg_t_ldtr_limit | 79 | defines the ldtr_limit register |
| bf_reg_t_ldtr_base | 80 | defines the ldtr_base register |
| bf_reg_t_idtr_selector | 81 | defines the idtr_selector register |
| bf_reg_t_idtr_attrib | 82 | defines the idtr_attrib register |
| bf_reg_t_idtr_limit | 83 | defines the idtr_limit register |
| bf_reg_t_idtr_base | 84 | defines the idtr_base register |
| bf_reg_t_tr_selector | 85 | defines the tr_selector register |
| bf_reg_t_tr_attrib | 86 | defines the tr_attrib register |
| bf_reg_t_tr_limit | 87 | defines the tr_limit register |
| bf_reg_t_tr_base | 88 | defines the tr_base register |
| bf_reg_t_cpl | 89 | defines the cpl register |
| bf_reg_t_efer | 90 | defines the efer register |
| bf_reg_t_cr4 | 91 | defines the cr4 register |
| bf_reg_t_cr3 | 92 | defines the cr3 register |
| bf_reg_t_cr0 | 93 | defines the cr0 register |
| bf_reg_t_dr7 | 94 | defines the dr7 register |
| bf_reg_t_dr6 | 95 | defines the dr6 register |
| bf_reg_t_rflags | 96 | defines the rflags register |
| bf_reg_t_rip | 97 | defines the rip register |
| bf_reg_t_rsp | 98 | defines the rsp register |
| bf_reg_t_rax | 99 | defines the rax register |
| bf_reg_t_star | 100 | defines the star register |
| bf_reg_t_lstar | 101 | defines the lstar register |
| bf_reg_t_cstar | 102 | defines the cstar register |
| bf_reg_t_fmask | 103 | defines the fmask register |
| bf_reg_t_kernel_gs_base | 104 | defines the kernel_gs_base register |
| bf_reg_t_sysenter_cs | 105 | defines the sysenter_cs register |
| bf_reg_t_sysenter_esp | 106 | defines the sysenter_esp register |
| bf_reg_t_sysenter_eip | 107 | defines the sysenter_eip register |
| bf_reg_t_cr2 | 108 | defines the cr2 register |
| bf_reg_t_pat | 109 | defines the pat register |
| bf_reg_t_dbgctl | 110 | defines the dbgctl register |
| bf_reg_t_br_from | 111 | defines the br_from register |
| bf_reg_t_br_to | 112 | defines the br_to register |
| bf_reg_t_lastexcpfrom | 113 | defines the lastexcpfrom register |
| bf_reg_t_lastexcpto | 114 | defines the lastexcpto register |
| bf_reg_t_cr8 | 115 | defines the cr8 register |
| bf_reg_t_dr0 | 116 | defines the dr0 register |
| bf_reg_t_dr1 | 117 | defines the dr1 register |
| bf_reg_t_dr2 | 118 | defines the dr2 register |
| bf_reg_t_dr3 | 119 | defines the dr3 register |
| bf_reg_t_xcr0 | 120 | defines the xcr0 register |
| bf_reg_t_invalid | 121 | defines the invalid register |

#### 1.4.2.2. Intel

**enum, uint64_t: bf_reg_t**
| Name | Value | Description |
| :--- | :---- | :---------- |
| BF_REG_T_UNSUPPORTED | 0 | defines the unsupported register |
| BF_REG_T_RAX | 1 | defines the rax register |
| BF_REG_T_RBX | 2 | defines the rbx register |
| BF_REG_T_RCX | 3 | defines the rcx register |
| BF_REG_T_RDX | 4 | defines the rdx register |
| BF_REG_T_RBP | 5 | defines the rbp register |
| BF_REG_T_RSI | 6 | defines the rsi register |
| BF_REG_T_RDI | 7 | defines the rdi register |
| BF_REG_T_R8 | 8 | defines the r8 register |
| BF_REG_T_R9 | 9 | defines the r9 register |
| BF_REG_T_R10 | 10 | defines the r10 register |
| BF_REG_T_R11 | 11 | defines the r11 register |
| BF_REG_T_R12 | 12 | defines the r12 register |
| BF_REG_T_R13 | 13 | defines the r13 register |
| BF_REG_T_R14 | 14 | defines the r14 register |
| BF_REG_T_R15 | 15 | defines the r15 register |
| BF_REG_T_CR2 | 16 | defines the cr2 register |
| BF_REG_T_DR6 | 17 | defines the dr6 register |
| BF_REG_T_STAR | 18 | defines the star register |
| BF_REG_T_LSTAR | 19 | defines the lstar register |
| BF_REG_T_CSTAR | 20 | defines the cstar register |
| BF_REG_T_FMASK | 21 | defines the fmask register |
| BF_REG_T_KERNEL_GS_BASE | 22 | defines the kernel_gs_base register |
| BF_REG_T_VIRTUAL_PROCESSOR_IDENTIFIER | 23 | defines the virtual_processor_identifier register |
| BF_REG_T_POSTED_INTERRUPT_NOTIFICATION_VECTOR | 24 | defines the posted_interrupt_notification_vector register |
| BF_REG_T_EPTP_INDEX | 25 | defines the eptp_index register |
| BF_REG_T_ES_SELECTOR | 26 | defines the es_selector register |
| BF_REG_T_CS_SELECTOR | 27 | defines the cs_selector register |
| BF_REG_T_SS_SELECTOR | 28 | defines the ss_selector register |
| BF_REG_T_DS_SELECTOR | 29 | defines the ds_selector register |
| BF_REG_T_FS_SELECTOR | 30 | defines the fs_selector register |
| BF_REG_T_GS_SELECTOR | 31 | defines the gs_selector register |
| BF_REG_T_LDTR_SELECTOR | 32 | defines the ldtr_selector register |
| BF_REG_T_TR_SELECTOR | 33 | defines the tr_selector register |
| BF_REG_T_INTERRUPT_STATUS | 34 | defines the interrupt_status register |
| BF_REG_T_PML_INDEX | 35 | defines the pml_index register |
| BF_REG_T_ADDRESS_OF_IO_BITMAP_A | 36 | defines the address_of_io_bitmap_a register |
| BF_REG_T_ADDRESS_OF_IO_BITMAP_B | 37 | defines the address_of_io_bitmap_b register |
| BF_REG_T_ADDRESS_OF_MSR_BITMAPS | 38 | defines the address_of_msr_bitmaps register |
| BF_REG_T_VMEXIT_MSR_STORE_ADDRESS | 39 | defines the vmexit_msr_store_address register |
| BF_REG_T_VMEXIT_MSR_LOAD_ADDRESS | 40 | defines the vmexit_msr_load_address register |
| BF_REG_T_VMENTRY_MSR_LOAD_ADDRESS | 41 | defines the vmentry_msr_load_address register |
| BF_REG_T_EXECUTIVE_VMCS_POINTER | 42 | defines the executive_vmcs_pointer register |
| BF_REG_T_PML_ADDRESS | 43 | defines the pml_address register |
| BF_REG_T_TSC_OFFSET | 44 | defines the tsc_offset register |
| BF_REG_T_VIRTUAL_APIC_ADDRESS | 45 | defines the virtual_apic_address register |
| BF_REG_T_APIC_ACCESS_ADDRESS | 46 | defines the apic_access_address register |
| BF_REG_T_POSTED_INTERRUPT_DESCRIPTOR_ADDRESS | 47 | defines the posted_interrupt_descriptor_address register |
| BF_REG_T_VM_FUNCTION_CONTROLS | 48 | defines the vm_function_controls register |
| BF_REG_T_EPT_POINTER | 49 | defines the ept_pointer register |
| BF_REG_T_EOI_EXIT_BITMAP0 | 50 | defines the eoi_exit_bitmap0 register |
| BF_REG_T_EOI_EXIT_BITMAP1 | 51 | defines the eoi_exit_bitmap1 register |
| BF_REG_T_EOI_EXIT_BITMAP2 | 52 | defines the eoi_exit_bitmap2 register |
| BF_REG_T_EOI_EXIT_BITMAP3 | 53 | defines the eoi_exit_bitmap3 register |
| BF_REG_T_EPTP_LIST_ADDRESS | 54 | defines the eptp_list_address register |
| BF_REG_T_VMREAD_BITMAP_ADDRESS | 55 | defines the vmread_bitmap_address register |
| BF_REG_T_VMWRITE_BITMAP_ADDRESS | 56 | defines the vmwrite_bitmap_address register |
| BF_REG_T_VIRT_EXCEPTION_INFORMATION_ADDRESS | 57 | defines the virt_exception_information_address register |
| BF_REG_T_XSS_EXITING_BITMAP | 58 | defines the xss_exiting_bitmap register |
| BF_REG_T_ENCLS_EXITING_BITMAP | 59 | defines the encls_exiting_bitmap register |
| BF_REG_T_SUB_PAGE_PERMISSION_TABLE_POINTER | 60 | defines the sub_page_permission_table_pointer register |
| BF_REG_T_TSC_MULTIPLIER | 61 | defines the tsc_multiplier register |
| BF_REG_T_PHYSICAL_ADDRESS | 62 | defines the physical_address register |
| BF_REG_T_VMCS_LINK_POINTER | 63 | defines the vmcs_link_pointer register |
| BF_REG_T_DEBUGCTL | 64 | defines the debugctl register |
| BF_REG_T_PAT | 65 | defines the pat register |
| BF_REG_T_EFER | 66 | defines the efer register |
| BF_REG_T_PERF_GLOBAL_CTRL | 67 | defines the perf_global_ctrl register |
| BF_REG_T_PDPTE0 | 68 | defines the pdpte0 register |
| BF_REG_T_PDPTE1 | 69 | defines the pdpte1 register |
| BF_REG_T_PDPTE2 | 70 | defines the pdpte2 register |
| BF_REG_T_PDPTE3 | 71 | defines the pdpte3 register |
| BF_REG_T_BNDCFGS | 72 | defines the bndcfgs register |
| BF_REG_T_RTIT_CTL | 73 | defines the rtit_ctl register |
| BF_REG_T_PIN_BASED_VM_EXECUTION_CTLS | 74 | defines the pin_based_vm_execution_ctls register |
| BF_REG_T_PRIMARY_PROC_BASED_VM_EXECUTION_CTLS | 75 | defines the primary_proc_based_vm_execution_ctls register |
| BF_REG_T_EXCEPTION_BITMAP | 76 | defines the exception_bitmap register |
| BF_REG_T_PAGE_FAULT_ERROR_CODE_MASK | 77 | defines the page_fault_error_code_mask register |
| BF_REG_T_PAGE_FAULT_ERROR_CODE_MATCH | 78 | defines the page_fault_error_code_match register |
| BF_REG_T_CR3_TARGET_COUNT | 79 | defines the cr3_target_count register |
| BF_REG_T_VMEXIT_CTLS | 80 | defines the vmexit_ctls register |
| BF_REG_T_VMEXIT_MSR_STORE_COUNT | 81 | defines the vmexit_msr_store_count register |
| BF_REG_T_VMEXIT_MSR_LOAD_COUNT | 82 | defines the vmexit_msr_load_count register |
| BF_REG_T_VMENTRY_CTLS | 83 | defines the vmentry_ctls register |
| BF_REG_T_VMENTRY_MSR_LOAD_COUNT | 84 | defines the vmentry_msr_load_count register |
| BF_REG_T_VMENTRY_INTERRUPT_INFORMATION_FIELD | 85 | defines the vmentry_interrupt_information_field register |
| BF_REG_T_VMENTRY_EXCEPTION_ERROR_CODE | 86 | defines the vmentry_exception_error_code register |
| BF_REG_T_VMENTRY_INSTRUCTION_LENGTH | 87 | defines the vmentry_instruction_length register |
| BF_REG_T_TPR_THRESHOLD | 88 | defines the tpr_threshold register |
| BF_REG_T_SECONDARY_PROC_BASED_VM_EXECUTION_CTLS | 89 | defines the secondary_proc_based_vm_execution_ctls register |
| BF_REG_T_PLE_GAP | 90 | defines the ple_gap register |
| BF_REG_T_PLE_WINDOW | 91 | defines the ple_window register |
| BF_REG_T_VM_INSTRUCTION_ERROR | 92 | defines the vm_instruction_error register |
| BF_REG_T_EXIT_REASON | 93 | defines the exit_reason register |
| BF_REG_T_VMEXIT_INTERRUPTION_INFORMATION | 94 | defines the vmexit_interruption_information register |
| BF_REG_T_VMEXIT_INTERRUPTION_ERROR_CODE | 95 | defines the vmexit_interruption_error_code register |
| BF_REG_T_IDT_VECTORING_INFORMATION_FIELD | 96 | defines the idt_vectoring_information_field register |
| BF_REG_T_IDT_VECTORING_ERROR_CODE | 97 | defines the idt_vectoring_error_code register |
| BF_REG_T_VMEXIT_INSTRUCTION_LENGTH | 98 | defines the vmexit_instruction_length register |
| BF_REG_T_VMEXIT_INSTRUCTION_INFORMATION | 99 | defines the vmexit_instruction_information register |
| BF_REG_T_ES_LIMIT | 100 | defines the es_limit register |
| BF_REG_T_CS_LIMIT | 101 | defines the cs_limit register |
| BF_REG_T_SS_LIMIT | 102 | defines the ss_limit register |
| BF_REG_T_DS_LIMIT | 103 | defines the ds_limit register |
| BF_REG_T_FS_LIMIT | 104 | defines the fs_limit register |
| BF_REG_T_GS_LIMIT | 105 | defines the gs_limit register |
| BF_REG_T_LDTR_LIMIT | 106 | defines the ldtr_limit register |
| BF_REG_T_TR_LIMIT | 107 | defines the tr_limit register |
| BF_REG_T_GDTR_LIMIT | 108 | defines the gdtr_limit register |
| BF_REG_T_IDTR_LIMIT | 109 | defines the idtr_limit register |
| BF_REG_T_ES_ATTRIB | 110 | defines the es_attrib register |
| BF_REG_T_CS_ATTRIB | 111 | defines the cs_attrib register |
| BF_REG_T_SS_ATTRIB | 112 | defines the ss_attrib register |
| BF_REG_T_DS_ATTRIB | 113 | defines the ds_attrib register |
| BF_REG_T_FS_ATTRIB | 114 | defines the fs_attrib register |
| BF_REG_T_GS_ATTRIB | 115 | defines the gs_attrib register |
| BF_REG_T_LDTR_ATTRIB | 116 | defines the ldtr_attrib register |
| BF_REG_T_TR_ATTRIB | 117 | defines the tr_attrib register |
| BF_REG_T_INTERRUPTIBILITY_STATE | 118 | defines the interruptibility_state register |
| BF_REG_T_ACTIVITY_STATE | 119 | defines the activity_state register |
| BF_REG_T_SMBASE | 120 | defines the smbase register |
| BF_REG_T_SYSENTER_CS | 121 | defines the sysenter_cs register |
| BF_REG_T_VMX_PREEMPTION_TIMER_VALUE | 122 | defines the vmx_preemption_timer_value register |
| BF_REG_T_CR0_GUEST_HOST_MASK | 123 | defines the cr0_guest_host_mask register |
| BF_REG_T_CR4_GUEST_HOST_MASK | 124 | defines the cr4_guest_host_mask register |
| BF_REG_T_CR0_READ_SHADOW | 125 | defines the cr0_read_shadow register |
| BF_REG_T_CR4_READ_SHADOW | 126 | defines the cr4_read_shadow register |
| BF_REG_T_CR3_TARGET_VALUE0 | 127 | defines the cr3_target_value0 register |
| BF_REG_T_CR3_TARGET_VALUE1 | 128 | defines the cr3_target_value1 register |
| BF_REG_T_CR3_TARGET_VALUE2 | 129 | defines the cr3_target_value2 register |
| BF_REG_T_CR3_TARGET_VALUE3 | 130 | defines the cr3_target_value3 register |
| BF_REG_T_EXIT_QUALIFICATION | 131 | defines the exit_qualification register |
| BF_REG_T_IO_RCX | 132 | defines the io_rcx register |
| BF_REG_T_IO_RSI | 133 | defines the io_rsi register |
| BF_REG_T_IO_RDI | 134 | defines the io_rdi register |
| BF_REG_T_IO_RIP | 135 | defines the io_rip register |
| BF_REG_T_LINEAR_ADDRESS | 136 | defines the linear_address register |
| BF_REG_T_CR0 | 137 | defines the cr0 register |
| BF_REG_T_CR3 | 138 | defines the cr3 register |
| BF_REG_T_CR4 | 139 | defines the cr4 register |
| BF_REG_T_ES_BASE | 140 | defines the es_base register |
| BF_REG_T_CS_BASE | 141 | defines the cs_base register |
| BF_REG_T_SS_BASE | 142 | defines the ss_base register |
| BF_REG_T_DS_BASE | 143 | defines the ds_base register |
| BF_REG_T_FS_BASE | 144 | defines the fs_base register |
| BF_REG_T_GS_BASE | 145 | defines the gs_base register |
| BF_REG_T_LDTR_BASE | 146 | defines the ldtr_base register |
| BF_REG_T_TR_BASE | 147 | defines the tr_base register |
| BF_REG_T_GDTR_BASE | 148 | defines the gdtr_base register |
| BF_REG_T_IDTR_BASE | 149 | defines the idtr_base register |
| BF_REG_T_DR7 | 150 | defines the dr7 register |
| BF_REG_T_RSP | 151 | defines the rsp register |
| BF_REG_T_RIP | 152 | defines the rip register |
| BF_REG_T_RFLAGS | 153 | defines the rflags register |
| BF_REG_T_PENDING_DEBUG_EXCEPTIONS | 154 | defines the pending_debug_exceptions register |
| BF_REG_T_SYSENTER_ESP | 155 | defines the sysenter_esp register |
| BF_REG_T_SYSENTER_EIP | 156 | defines the sysenter_eip register |
| BF_REG_T_CR8 | 157 | defines the cr8 register |
| BF_REG_T_DR0 | 158 | defines the dr0 register |
| BF_REG_T_DR1 | 159 | defines the dr1 register |
| BF_REG_T_DR2 | 160 | defines the dr2 register |
| BF_REG_T_DR3 | 161 | defines the dr3 register |
| BF_REG_T_XCR0 | 162 | defines the xcr0 register |
| BF_REG_T_INVALID | 163 | defines the invalid register |

### 1.4.3. Exit Type

Defines the exit type used by bf_control_op_exit

**enum, uint64_t: bf_exit_status_t**
| Name | Value | Description |
| :--- | :---- | :---------- |
| bf_exit_status_t_success | 0 | Exit with a success code |
| bf_exit_status_t_failure | 1 | Exit with a failure code |

### 1.4.4. Bootstrap Callback Handler Type

Defines the signature of the bootstrap callback handler

**typedef, void(*bf_callback_handler_bootstrap_t)(uint16_t)**

### 1.4.5. VMExit Callback Handler Type

Defines the signature of the VM exit callback handler

**typedef, void(*bf_callback_handler_vmexit_t)(bsl::uint16_t, uint64_t)**

### 1.4.6. Fast Fail Callback Handler Type

Defines the signature of the fast fail callback handler

**typedef, void(*bf_callback_handler_fail_t)(uint64_t, uint64_t)**

## 1.5. ID Constants

The following defines some ID constants.

**const, uint16_t: BF_INVALID_ID**
| Value | Description |
| :---- | :---------- |
| 0xFFFF | Defines an invalid ID for an extension, VM, VP, VS and PP |

**const, uint16_t: BF_BS_PPID**
| Value | Description |
| :---- | :---------- |
| 0x0 | Defines the bootstrap physical processor ID |

**const, uint16_t: BF_ROOT_VMID**
| Value | Description |
| :---- | :---------- |
| 0x0 | Defines the root virtual machine ID |

## 1.6. Endianness

This document only applies to 64bit Intel and AMD systems conforming to the amd64 architecture. As such, this document is limited to little endian.

## 1.7. Host PAT (Intel/AMD Only)

The host PAT has the following layout. Indexes marked as XX are reserved for future use.

**const, uint64_t: BF_HOST_PAT**
| Value | Description |
| :---- | :---------- |
| 0xXXXXXXXX00XXXX06 | Defines the host PAT value |

# 2. Syscall Interface

The following section defines the syscall interface used by this specification, and therefore Bareflank.

## 2.1. Legal Syscall Environments

Userspace can execute syscalls from 64bit mode.

## 2.2. Alignment Requirements

This specification does not support structure based inputs/outputs and therefore there are not alignment requirements.

## 2.3. Syscall Status Codes

Every syscall returns a bf_status_t to indicate the success or failure of a syscall after execution. The following defines the layout of bf_status_t:

| Bits | Name | Description |
| :--- | :--- | :---------- |
| 63:48 | BF_STATUS_SIG | Contains 0x0000 on success, 0xDEAD on failure |
| 47:16 | BF_STATUS_FLAGS | Contains the flags associated with the bf_status_t |
| 15:0 | BF_STATUS_VALUE | Contains the value of the bf_status_t |

BF_STATUS_VALUE defines success or which type of error occurred. BF_STATUS_FLAGS provides additional information about why the error occurred.

### 2.3.1. BF_STATUS_SUCCESS, VALUE=0

**const, bf_status_t: BF_STATUS_SUCCESS**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000000 | Indicates the syscall returned successfully |

### 2.3.2. BF_STATUS_FAILURE, VALUE=1

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

### 2.3.3. BF_STATUS_INVALID_PERM, VALUE=2

**const, bf_status_t: BF_STATUS_INVALID_PERM_DENIED**
| Value | Description |
| :---- | :---------- |
| 0xDEAD000000010002 | Indicates the policy engine denied the syscall |

### 2.3.4. BF_STATUS_INVALID_PARAMS, VALUE=3

**const, mv_status_t: MV_STATUS_INVALID_INPUT_REG0**
| Value | Description |
| :---- | :---------- |
| 0xDEAD000000010003 | Indicates input reg0 is invalid |

**const, mv_status_t: MV_STATUS_INVALID_INPUT_REG1**
| Value | Description |
| :---- | :---------- |
| 0xDEAD000000020003 | Indicates input reg1 is invalid |

**const, mv_status_t: MV_STATUS_INVALID_INPUT_REG2**
| Value | Description |
| :---- | :---------- |
| 0xDEAD000000040003 | Indicates input reg2 is invalid |

**const, mv_status_t: MV_STATUS_INVALID_INPUT_REG3**
| Value | Description |
| :---- | :---------- |
| 0xDEAD000000080003 | Indicates input reg3 is invalid |

**const, mv_status_t: MV_STATUS_INVALID_INPUT_REG4**
| Value | Description |
| :---- | :---------- |
| 0xDEAD000000100003 | Indicates input reg4 is invalid |

**const, mv_status_t: MV_STATUS_INVALID_INPUT_REG5**
| Value | Description |
| :---- | :---------- |
| 0xDEAD000000200003 | Indicates input reg5 is invalid |

**const, mv_status_t: MV_STATUS_INVALID_OUTPUT_REG0**
| Value | Description |
| :---- | :---------- |
| 0xDEAD000000400003 | Indicates output reg0 is invalid |

**const, mv_status_t: MV_STATUS_INVALID_OUTPUT_REG1**
| Value | Description |
| :---- | :---------- |
| 0xDEAD000000800003 | Indicates output reg1 is invalid |

**const, mv_status_t: MV_STATUS_INVALID_OUTPUT_REG2**
| Value | Description |
| :---- | :---------- |
| 0xDEAD000001000003 | Indicates output reg2 is invalid |

**const, mv_status_t: MV_STATUS_INVALID_OUTPUT_REG3**
| Value | Description |
| :---- | :---------- |
| 0xDEAD000002000003 | Indicates output reg3 is invalid |

**const, mv_status_t: MV_STATUS_INVALID_OUTPUT_REG4**
| Value | Description |
| :---- | :---------- |
| 0xDEAD000004000003 | Indicates output reg4 is invalid |

**const, mv_status_t: MV_STATUS_INVALID_OUTPUT_REG5**
| Value | Description |
| :---- | :---------- |
| 0xDEAD000008000003 | Indicates output reg5 is invalid |

## 2.4. Syscall Inputs

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

**const, uint64_t: BF_SYSCALL_SIG_VAL**
| Value | Description |
| :---- | :---------- |
| 0x6642000000000000 | Defines the BF_SYSCALL_SIG field for RAX |

**const, uint64_t: BF_HYPERCALL_SIG_MASK**
| Value | Description |
| :---- | :---------- |
| 0xFFFF000000000000 | Defines a mask for BF_SYSCALL_SIG |

**const, uint64_t: BF_HYPERCALL_FLAGS_MASK**
| Value | Description |
| :---- | :---------- |
| 0x0000FFFF00000000 | Defines a mask for BF_SYSCALL_FLAGS |

**const, uint64_t: BF_HYPERCALL_OPCODE_MASK**
| Value | Description |
| :---- | :---------- |
| 0xFFFF0000FFFF0000 | Defines a mask for BF_SYSCALL_OP |

**const, uint64_t: BF_HYPERCALL_OPCODE_NOSIG_MASK**
| Value | Description |
| :---- | :---------- |
| 0x00000000FFFF0000 | Defines a mask for BF_SYSCALL_OP (with no signature added) |

**const, uint64_t: BF_HYPERCALL_INDEX_MASK**
| Value | Description |
| :---- | :---------- |
| 0x000000000000FFFF | Defines a mask for BF_SYSCALL_IDX |

BF_SYSCALL_SIG is used to ensure the syscall is, in fact, a Bareflank specific syscall. BF_SYSCALL_FLAGS is used to provide additional syscall options.

BF_SYSCALL_OP determines which opcode the syscall belongs to, logically grouping syscalls based on their function. BF_SYSCALL_OP is also used internally within the microkernel to dispatch the syscall to the proper handler. BF_SYSCALL_IDX, when combined with BF_SYSCALL_OP, uniquely identifies a specific syscall. This specification tightly packs the values assigned to both BF_SYSCALL_IDX and BF_SYSCALL_OP to ensure Bareflank (and variants) can use jump tables instead of branch logic.

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

## 2.5. Syscall Outputs

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

## 2.6. Syscall Opcodes

The following sections define the different opcodes that are supported by this specification. Note that each opcode includes the syscall signature making it easier to validate if the syscall is supported or not.

### 2.6.1. Control Support

**const, uint64_t: BF_CONTROL_OP_VAL**
| Value | Description |
| :---- | :---------- |
| 0x6642000000000000 | Defines the syscall opcode for bf_control_op |

**const, uint64_t: BF_CONTROL_OP_NOSIG_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000000 | Defines the syscall opcode for bf_control_op (nosig) |

### 2.6.2. Handle Support

**const, uint64_t: BF_HANDLE_OP_VAL**
| Value | Description |
| :---- | :---------- |
| 0x6642000000010000 | Defines the syscall opcode for bf_handle_op |

**const, uint64_t: BF_HANDLE_OP_NOSIG_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000010000 | Defines the syscall opcode for bf_handle_op (nosig) |

### 2.6.3. Debug Support

**const, uint64_t: BF_DEBUG_OP_VAL**
| Value | Description |
| :---- | :---------- |
| 0x6642000000020000 | Defines the syscall opcode for bf_debug_op |

**const, uint64_t: BF_DEBUG_OP_NOSIG_VAL**
| Value | Description |
| :---- | :---------- |
| 0x00000000000020000 | Defines the syscall opcode for bf_debug_op (nosig) |

### 2.6.4. Callback Support

**const, uint64_t: BF_CALLBACK_OP_VAL**
| Value | Description |
| :---- | :---------- |
| 0x6642000000030000 | Defines the syscall opcode for bf_callback_op |

**const, uint64_t: BF_CALLBACK_OP_NOSIG_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000030000 | Defines the syscall opcode for bf_callback_op (nosig) |

### 2.6.5. VM Support

**const, uint64_t: BF_VM_OP_VAL**
| Value | Description |
| :---- | :---------- |
| 0x6642000000040000 | Defines the syscall opcode for bf_vm_op |

**const, uint64_t: BF_VM_OP_NOSIG_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000040000 | Defines the syscall opcode for bf_vm_op (nosig) |

### 2.6.6. VP Support

**const, uint64_t: BF_VP_OP_VAL**
| Value | Description |
| :---- | :---------- |
| 0x6642000000050000 | Defines the syscall opcode for bf_vp_op |

**const, uint64_t: BF_VP_OP_NOSIG_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000050000 | Defines the syscall opcode for bf_vp_op (nosig) |

### 2.6.7. VS Support

**const, uint64_t: BF_VS_OP_VAL**
| Value | Description |
| :---- | :---------- |
| 0x6642000000060000 | Defines the syscall opcode for bf_vs_op |

**const, uint64_t: BF_VS_OP_NOSIG_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000060000 | Defines the syscall opcode for bf_vs_op (nosig) |

### 2.6.8. Intrinsic Support

**const, uint64_t: BF_INTRINSIC_OP_VAL**
| Value | Description |
| :---- | :---------- |
| 0x6642000000070000 | Defines the syscall opcode for bf_intrinsic_op |

**const, uint64_t: BF_INTRINSIC_OP_NOSIG_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000070000 | Defines the syscall opcode for bf_intrinsic_op (nosig) |

### 2.6.9. Mem Support

**const, uint64_t: BF_MEM_OP_VAL**
| Value | Description |
| :---- | :---------- |
| 0x6642000000080000 | Defines the syscall opcode for bf_mem_op |

**const, uint64_t: BF_MEM_OP_NOSIG_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000080000 | Defines the syscall opcode for bf_mem_op (nosig) |

## 2.7. Syscall Specification IDs

The following defines the specification IDs used when opening a handle. These provide software with a means to define which specification it implements. The version provided to the extension's entry point defines which version of this spec the microkernel supports. For example, if the provided version is 0x2, it means that it supports version #1 of this spec, in which case, an extension can open a handle with BF_SPEC_ID1_VAL. If the provided version is 0x6, it would mean that an extension could open a handle with BF_SPEC_ID1_VAL or BF_SPEC_ID2_VAL. Likewise, if the provided version is 0x4, it means that BF_SPEC_ID1_VAL is no longer supported, and the extension must open the handle with BF_SPEC_ID2_VAL.

**const, uint32_t: BF_SPEC_ID1_VAL**
| Value | Description |
| :---- | :---------- |
| 0x31236642 | Defines the ID for version #1 of this spec |

**const, uint32_t: BF_SPEC_ID1_MASK**
| Value | Description |
| :---- | :---------- |
| 0x2 | Defines the mask for checking support for version #1 of this spec |

**const, uint32_t: BF_ALL_SPECS_SUPPORTED_VAL**
| Value | Description |
| :---- | :---------- |
| 0x2 | Defines all versions supported |

**const, uint32_t: BF_INVALID_VERSION**
| Value | Description |
| :---- | :---------- |
| 0x80000000 | Defines an invalid version |

## 2.8. Thread Local Storage

The microkernel defines a "thread" the same way both Intel and AMD define a thread (i.e., a logical core). For example, some Intel CPUs have 4 cores and 8 threads when hyper-threading is enabled, or 4 cores and 4 threads when hyper-threading is disabled. Each logical core is given one "thread" and that thread always executes on that logical core. The microkernel defines these logical cores as physical processors (i.e., PP).

The layout of the TLS block provided to each extension uses a scheme similar to the ELF TLS specification, but with some modifications. Unlike the ELF TLS specification, each TLS block is limited to two pages. The lower half of the page is dedicated to "thread_local" storage. The upper half is defined by this specification, and provides access to registers shared between the microkernel and the extension to improve performance. For example, access to a VM's general purpose registers is available from the TLS block. Each TLS register defined by this specific is an offset into the upper half of the TLS block (which can be located using the fs segment register on Intel/AMD).

**IMPORTANT:**
The general purpose registers are always accessible to an extension to read and write, but it is up to the extension to ensure the correct VS state is being modified. Accesses to the TLS block modifies the active VS only. For example, while an extension is executing its bootstrap handler, there is no active VS, in which case any reads/writes to the general purpose registers from the TLS block will be lost. When an extension is executing from a VMExit handler, reads/writes to the general purpose registers from the TLS block are made to the VS that generated the VMExit. If an extension then creates a VS, the only way to modify the general purpose registers for the newly created VS is through the read/write ABIs. Attempting to use the TLS block will modify the registers for the active VS, not the newly created VS. The only way to set a VS to "active" is to use the run ABI, which on success does not return, meaning the extension has to wait for a VMExit before the newly create VS's general purpose registers can be accessed from the TLS block.

Although this seems overly complicated, this optimization works well for the majority of the VMExits an extension will have to handle, especially the VMExits that execute frequently as most of the time an extension will only be modifying the general purpose registers for the active VS.

### 2.8.1. TLS Offsets

**consts, void *: uint64_t**
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
| TLS_OFFSET_ACTIVE_VSID | 0xFF6U | stores the offset of the active vsid |
| TLS_OFFSET_ACTIVE_PPID | 0xFF8U | stores the offset of the active ppid |
| TLS_OFFSET_ONLINE_PPS | 0xFFAU | stores the number of PPs that are online |

## 2.9. Control Syscalls

### 2.9.1. bf_control_op_exit, OP=0x0, IDX=0x0

This syscall tells the microkernel to stop the execution of an extension, providing a means to fast fail.

**const, uint64_t: BF_CONTROL_OP_EXIT_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000000 | Defines the index for bf_control_op_exit |

### 2.9.2. bf_control_op_wait, OP=0x0, IDX=0x1

This syscall tells the microkernel that the extension would like to wait for a callback. This syscall is a blocking syscall that never returns and should be used to return from the _start function.

**const, uint64_t: BF_CONTROL_OP_WAIT_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000001 | Defines the index for bf_control_op_wait |

### 2.9.3. bf_control_op_again, OP=0x0, IDX=0x2

This syscall tells the microkernel that the extension would like to try again from a fast fail callback. This syscall is a blocking syscall that never returns and should be used to return from the fail_entry function.

**const, uint64_t: BF_CONTROL_OP_AGAIN_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000002 | Defines the index for bf_control_op_again |

## 2.10. Handle Syscalls

### 2.10.1. bf_handle_op_open_handle, OP=0x1, IDX=0x0

This syscall returns the handle that is required to execute the remaining syscalls.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 31:0 | The version of this spec that software supports |
| REG0 | 63:32 | REVI |

**Output:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | The value to set REG0 to for most other syscalls |

**const, uint64_t: BF_HANDLE_OP_OPEN_HANDLE_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000000 | Defines the index for bf_handle_op_open_handle |

**const, uint64_t: BF_INVALID_HANDLE**
| Value | Description |
| :---- | :---------- |
| 0xFFFFFFFFFFFFFFFF | Defines an invalid handle |

### 2.10.2. bf_handle_op_close_handle, OP=0x1, IDX=0x1

This syscall closes a previously opened handle.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of bf_handle_op_open_handle |

**const, uint64_t: BF_HANDLE_OP_CLOSE_HANDLE_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000001 | Defines the index for bf_handle_op_close_handle |

## 2.11. Debug Syscalls

### 2.11.1. bf_debug_op_out, OP=0x2, IDX=0x0

This syscall tells the microkernel to output RDI and RSI to the console device the microkernel is currently using for debugging.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | The first value to output to the microkernel's console |
| REG1 | 63:0 | The second value to output to the microkernel's console |

**const, uint64_t: BF_DEBUG_OP_OUT_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000000 | Defines the index for bf_debug_op_out |

### 2.11.2. bf_debug_op_dump_vm, OP=0x2, IDX=0x1

This syscall tells the microkernel to output a VM's state to the console device the microkernel is currently using for debugging.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | The ID of the VM's state to output |

**const, uint64_t: BF_DEBUG_OP_DUMP_VM_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000001 | Defines the index for bf_debug_op_dump_vm |

### 2.11.3. bf_debug_op_dump_vp, OP=0x2, IDX=0x2

This syscall tells the microkernel to output a VP's state to the console device the microkernel is currently using for debugging.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | The ID of the VP's state to output |

**const, uint64_t: BF_DEBUG_OP_DUMP_VP_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000002 | Defines the index for bf_debug_op_dump_vp |

### 2.11.4. bf_debug_op_dump_vs, OP=0x2, IDX=0x3

This syscall tells the microkernel to output a VS's state to the console device the microkernel is currently using for debugging.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | The ID of the VS's state to output |

**const, uint64_t: BF_DEBUG_OP_DUMP_VS_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000003 | Defines the index for bf_debug_op_dump_vs |

### 2.11.5. bf_debug_op_dump_vmexit_log, OP=0x2, IDX=0x4

This syscall tells the microkernel to output the VMExit log. The VMExit log is a chronological log of the "X" number of exits that have occurred on a specific physical processor.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | The PPID of the PP to dump the log from |

**const, uint64_t: BF_DEBUG_OP_DUMP_VMEXIT_LOG_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000003 | Defines the index for bf_debug_op_dump_vmexit_log |

### 2.11.6. bf_debug_op_write_c, OP=0x2, IDX=0x5

This syscall tells the microkernel to output a provided character to the microkernel's console.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 7:0 | The character to output |
| REG0 | 63:8 | REVI |

**const, uint64_t: BF_DEBUG_OP_WRITE_C_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000005 | Defines the index for bf_debug_op_write_c |

### 2.11.7. bf_debug_op_write_str, OP=0x2, IDX=0x6

This syscall tells the microkernel to output a provided string to the microkernel's console.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | The virtual address of a null terminated string to output |

**const, uint64_t: BF_DEBUG_OP_WRITE_STR_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000006 | Defines the index for bf_debug_op_write_str |

### 2.11.8. bf_debug_op_dump_ext, OP=0x2, IDX=0x7

This syscall tells the microkernel to output an extension's state to the console device the microkernel is currently using for debugging.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | The EXTID of the extensions's state to output |

**const, uint64_t: BF_DEBUG_OP_DUMP_EXT_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000007 | Defines the index for bf_debug_op_dump_ext |

### 2.11.9. bf_debug_op_dump_page_pool, OP=0x2, IDX=0x8

This syscall tells the microkernel to output the page pool's stats to the console device the microkernel is currently using for debugging.

**const, uint64_t: BF_DEBUG_OP_DUMP_PAGE_POOL_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000008 | Defines the index for bf_debug_op_dump_page_pool |

### 2.11.10. bf_debug_op_dump_huge_pool, OP=0x2, IDX=0x9

This syscall tells the microkernel to output the huge pool's stats to the console device the microkernel is currently using for debugging.

**const, uint64_t: BF_DEBUG_OP_DUMP_HUGE_POOL_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000009 | Defines the index for bf_debug_op_dump_huge_pool |

## 2.12. Callback Syscalls

### 2.12.1. bf_callback_op_register_bootstrap, OP=0x3, IDX=0x0

This syscall tells the microkernel that the extension would like to receive callbacks for bootstrap events.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of bf_handle_op_open_handle |
| REG1 | 63:0 | Set to the virtual address of the callback |

**const, uint64_t: BF_CALLBACK_OP_REGISTER_BOOTSTRAP_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000000 | Defines the index for bf_callback_op_register_bootstrap |

### 2.12.2. bf_callback_op_register_vmexit, OP=0x3, IDX=0x1

This syscall tells the microkernel that the extension would like to receive callbacks for VM exits.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of bf_handle_op_open_handle |
| REG1 | 63:0 | Set to the virtual address of the callback |

**const, uint64_t: BF_CALLBACK_OP_REGISTER_VMEXIT_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000001 | Defines the index for bf_callback_op_register_vmexit |

### 2.12.3. bf_callback_op_register_fail, OP=0x3, IDX=0x2

This syscall tells the microkernel that the extension would like to receive callbacks for fast fail events. If a fast fail event occurs, something terrible has happened, and the extension must take action, or the physical processor will halt.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of bf_handle_op_open_handle |
| REG1 | 63:0 | Set to the virtual address of the callback |

**const, uint64_t: BF_CALLBACK_OP_REGISTER_FAIL_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000002 | Defines the index for bf_callback_op_register_fail |

## 2.13. Virtual Machine Syscalls

A Virtual Machine or VM virtually represents a physical computer. Although the microkernel has an internal representation of a VM, it doesn't understand what a VM is outside of resource management, and it is up to the extension to define what a VM is and how it should operate.

One important resource within the microkernel that changes when a VM changes is the direct map each extension is given. When a VM changes, the direct map an extension uses to access physical memory also changes.

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

**const, uint64_t: BF_VM_OP_CREATE_VM_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000000 | Defines the index for bf_vm_op_create_vm |

### 2.13.2. bf_vm_op_destroy_vm, OP=0x4, IDX=0x1

This syscall tells the microkernel to destroy a VM given an ID.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of bf_handle_op_open_handle |
| REG1 | 15:0 | The ID of the VM to destroy |
| REG1 | 63:16 | REVI |

**const, uint64_t: BF_VM_OP_DESTROY_VM_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000001 | Defines the index for bf_vm_op_destroy_vm |

### 2.13.3. bf_vm_op_map_direct, OP=0x4, IDX=0x2

This syscall tells the microkernel to map a physical address into the VM's direct map. This is the same as directly accessing the direct map with the difference being that software can provide a physical address and receive the precalculated virtual address.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of bf_handle_op_open_handle |
| REG1 | 15:0 | The ID of the VM to map the physical address to |
| REG1 | 63:16 | REVI |
| REG2 | 12:0 | REV0 |
| REG2 | 63:12 | The physical address to map |

**Output:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 12:0 | REV0 |
| REG0 | 63:12 | The resulting virtual address of the map |

**const, uint64_t: BF_VM_OP_MAP_DIRECT_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000002 | Defines the index for bf_vm_op_map_direct |

### 2.13.4. bf_vm_op_unmap_direct, OP=0x4, IDX=0x3

This syscall tells the microkernel to unmap a previously mapped virtual address in the direct map. Unlike bf_vm_op_unmap_direct_broadcast, this syscall does not flush the TLB on any other PP, meaning this unmap is local to the PP the call is made on. Attempting to unmap a virtual address from the direct map that has been accessed on any other PP other than the PP this syscall is executed on will result in undefined behavior. This syscall is designed to support mapping and then immediately unmapping a physical address on a single PP during a single VMExit. It can also be used to map on a PP and then use unmap on the same PP during multiple VMExits, but special care must be taken to ensure no other PP can access the map, otherwise UB will occur.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of bf_handle_op_open_handle |
| REG1 | 15:0 | The ID of the VM to unmap the virtual address from |
| REG1 | 63:16 | REVI |
| REG2 | 12:0 | REV0 |
| REG2 | 63:12 | The virtual address to unmap |

**const, uint64_t: BF_VM_OP_UNMAP_DIRECT_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000003 | Defines the index for bf_vm_op_unmap_direct |

### 2.13.5. bf_vm_op_unmap_direct_broadcast, OP=0x4, IDX=0x4

This syscall tells the microkernel to unmap a previously mapped virtual address in the direct map. Unlike bf_vm_op_unmap_direct, this syscall performs a broadcast TLB flush which means it can be safely used on all direct mapped addresses. The downside of using this function is that it can be a lot slower than bf_vm_op_unmap_direct, especially on systems with a lot of PPs.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of bf_handle_op_open_handle |
| REG1 | 15:0 | The ID of the VM to unmap the virtual address from |
| REG1 | 63:16 | REVI |
| REG2 | 12:0 | REV0 |
| REG2 | 63:12 | The virtual address to unmap |

**const, uint64_t: BF_VM_OP_UNMAP_DIRECT_REMOTE_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000004 | Defines the index for bf_vm_op_unmap_direct_broadcast |

### 2.13.6. bf_vm_op_tlb_flush, OP=0x4, IDX=0x5

Given the ID of a VM, invalidates the VM's TLB on the PP that this is executed on.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of bf_handle_op_open_handle |
| REG1 | 15:0 | The ID of the VM to invalidate |
| REG1 | 63:16 | REVI |

**const, uint64_t: BF_VM_OP_TLB_FLUSH_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000005 | Defines the index for bf_vm_op_tlb_flush |

## 2.14. Virtual Processor Syscalls

A Virtual Processor or VP virtually represents a PP. Although the microkernel has an internal representation of a VP, it doesn't understand what a VP is outside of resource management, and it is up to the extension to define what a VP is and how it should operate.

### 2.14.1. bf_vp_op_create_vp, OP=0x5, IDX=0x0

This syscall tells the microkernel to create a VP given the ID of the VM the VP will be assigned to. Upon success, this syscall returns the ID of the newly created VP.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of bf_handle_op_open_handle |
| REG1 | 15:0 | The ID of the VM to assign the newly created VP to |
| REG1 | 63:16 | REVI |

**Output:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 15:0 | The resulting VPID of the newly created VP |
| REG0 | 63:16 | REVI |

**const, uint64_t: BF_VP_OP_CREATE_VP_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000000 | Defines the index for bf_vp_op_create_vp |

### 2.14.2. bf_vp_op_destroy_vp, OP=0x5, IDX=0x1

This syscall tells the microkernel to destroy a VP given an ID.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of bf_handle_op_open_handle |
| REG1 | 15:0 | The ID of the VP to destroy |
| REG1 | 63:16 | REVI |

**const, uint64_t: BF_VP_OP_DESTROY_VP_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000001 | Defines the index for bf_vp_op_destroy_vp |

## 2.15. Virtual Processor State Syscalls

A Virtual Processor State or VS virtually represents a PP's state. Most operations performed by an extension will be through a VS. When a VS is created, it is assigned to a VP and PP. To change the PP, a VS must be migrated.

### 2.15.1. bf_vs_op_create_vs, OP=0x6, IDX=0x0

This syscall tells the microkernel to create a VS given the IDs of the VP and PP the VS will be assigned to. Upon success, this syscall returns the ID of the newly created VS.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of bf_handle_op_open_handle |
| REG1 | 15:0 | The ID of the VP to assign the newly created VS to |
| REG1 | 63:16 | REVI |
| REG2 | 15:0 | The ID of the PP to assign the newly created VS to |
| REG2 | 63:16 | REVI |

**Output:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 15:0 | The resulting VSID of the newly created VS |
| REG0 | 63:16 | REVI |

**const, uint64_t: BF_VS_OP_CREATE_VS_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000000 | Defines the index for bf_vs_op_create_vs |

### 2.15.2. bf_vs_op_destroy_vs, OP=0x6, IDX=0x1

This syscall tells the microkernel to destroy a VS given an ID.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of bf_handle_op_open_handle |
| REG1 | 15:0 | The ID of the VS to destroy |
| REG1 | 63:16 | REVI |

**const, uint64_t: BF_VS_OP_DESTROY_VS_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000001 | Defines the index for bf_vs_op_destroy_vs |

### 2.15.3. bf_vs_op_init_as_root, OP=0x6, IDX=0x2

This syscall tells the microkernel to initialize a VS using the root VP state provided by the loader using the current PPID.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of bf_handle_op_open_handle |
| REG1 | 15:0 | The ID of the VS to initialize |
| REG1 | 63:16 | REVI |

**const, uint64_t: BF_VS_OP_INIT_AS_ROOT_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000002 | Defines the index for bf_vs_op_init_as_root |

### 2.15.4. bf_vs_op_read, OP=0x6, IDX=0x3

Reads a CPU register from the VS given a bf_reg_t. Note that the bf_reg_t is architecture-specific.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of bf_handle_op_open_handle |
| REG1 | 15:0 | The ID of the VS to read from |
| REG1 | 63:16 | REVI |
| REG2 | 63:0 | A bf_reg_t defining which register to read |

**Output:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | The resulting value |

**const, uint64_t: BF_VS_OP_READ_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000003 | Defines the index for bf_vs_op_read |

### 2.15.5. bf_vs_op_write, OP=0x6, IDX=0x4

Writes to a CPU register in the VS given a bf_reg_t and the value to write. Note that the bf_reg_t is architecture-specific.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of bf_handle_op_open_handle |
| REG1 | 15:0 | The ID of the VS to write to |
| REG1 | 63:16 | REVI |
| REG2 | 63:0 | A bf_reg_t defining which register to write to |
| REG3 | 63:0 | The value to write to the requested register |

**const, uint64_t: BF_VS_OP_WRITE_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000004 | Defines the index for bf_vs_op_write |

### 2.15.6. bf_vs_op_run, OP=0x6, IDX=0x5

Executes a VS given the ID of the VM, VP and VS to execute. The VS must be assigned to the provided VP and the provided VP must be assigned to the provided VM. The VP and VS must not be executing on any other PP, and the VS must be assigned to the PP this syscall is executed on. Upon success, this syscall will not return.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of bf_handle_op_open_handle |
| REG1 | 15:0 | The ID of the VM to run |
| REG1 | 63:16 | REVI |
| REG2 | 15:0 | The ID of the VP to run |
| REG2 | 63:16 | REVI |
| REG3 | 15:0 | The ID of the VS to run |
| REG3 | 63:16 | REVI |

**const, uint64_t: BF_VS_OP_RUN_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000005 | Defines the index for bf_vs_op_run |

### 2.15.7. bf_vs_op_run_current, OP=0x6, IDX=0x6

bf_vs_op_run_current tells the microkernel to execute the currently active VS, VP and VM.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of bf_handle_op_open_handle |

**const, uint64_t: BF_VS_OP_RUN_CURRENT_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000006 | Defines the index for bf_vs_op_run_current |

### 2.15.8. bf_vs_op_advance_ip_and_run_impl, OP=0x6, IDX=0x7

Advances the IP and executes a VS given the ID of the VM, VP and VS to execute. The VS must be assigned to the provided VP and the provided VP must be assigned to the provided VM. The VP and VS must not be executing on any other PP, and the VS must be assigned to the PP this syscall is executed on. Upon success, this syscall will not return.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of bf_handle_op_open_handle |
| REG1 | 15:0 | The ID of the VS advance the IP in |
| REG1 | 63:16 | REVI |

**const, uint64_t: BF_VS_OP_ADVANCE_IP_AND_RUN_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000007 | Defines the index for bf_vs_op_advance_ip_and_run_impl |

### 2.15.9. bf_vs_op_advance_ip_and_run_current, OP=0x6, IDX=0x8

bf_vs_op_advance_ip_and_run_current tells the microkernel to advance the IP of and execute the currently active VS, VP and VM.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of bf_handle_op_open_handle |

**const, uint64_t: BF_VS_OP_ADVANCE_IP_AND_RUN_CURRENT_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000008 | Defines the index for bf_vs_op_advance_ip_and_run_current |

### 2.15.10. bf_vs_op_promote, OP=0x6, IDX=0x9

bf_vs_op_promote tells the microkernel to promote the requested VS. bf_vs_op_promote will stop the hypervisor on the physical processor and replace its state with the state in the given VS. Note that this syscall only returns on error.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of bf_handle_op_open_handle |
| REG1 | 15:0 | The ID of the VS to promote |
| REG1 | 63:16 | REVI |

**const, uint64_t: BF_VS_OP_PROMOTE_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000009 | Defines the index for bf_vs_op_promote |

### 2.15.11. bf_vs_op_clear, OP=0x6, IDX=0xA

bf_vs_op_clear tells the microkernel to clear the VS's hardware cache, if one exists. How this is used depends entirely on the hardware and is associated with AMD's VMCB Clean Bits, and Intel's VMClear instruction. See the associated documentation for more details. On AMD, this ABI clears the entire VMCB. For more fine grained control, use the write ABIs to manually modify the VMCB.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of bf_handle_op_open_handle |
| REG1 | 15:0 | The ID of the VS to clear |
| REG1 | 63:16 | REVI |

**const, uint64_t: BF_VS_OP_CLEAR_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x000000000000000A | Defines the index for bf_vs_op_clear |

### 2.15.12. bf_vs_op_migrate, OP=0x6, IDX=0xB

Migrates a VS to the provided PP. The VS must not be active.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of bf_handle_op_open_handle |
| REG1 | 15:0 | The ID of the VS to migrate |
| REG1 | 63:16 | REVI |
| REG1 | 15:0 | The ID of the PP to migrate the VS to |
| REG1 | 63:16 | REVI |

**const, uint64_t: BF_VS_OP_MIGRATE_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x000000000000000B | Defines the index for bf_vs_op_migrate |

### 2.15.13. bf_vs_op_set_active, OP=0x6, IDX=0xC

Sets the active VM, VP and VS to the provided VM, VP and VS.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of bf_handle_op_open_handle |
| REG1 | 15:0 | The ID of the VM to set active |
| REG1 | 63:16 | REVI |
| REG2 | 15:0 | The ID of the VP to set active |
| REG2 | 63:16 | REVI |
| REG3 | 15:0 | The ID of the VS to set active |
| REG3 | 63:16 | REVI |

**const, uint64_t: BF_VS_OP_SET_ACTIVE_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x000000000000000C | Defines the index for bf_vs_op_set_active |

### 2.15.14. bf_vs_op_advance_ip_and_set_active, OP=0x6, IDX=0xD

Advances the IP of the current VS and then sets the active VM, VP and VS to the provided VM, VP and VS.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of bf_handle_op_open_handle |
| REG1 | 15:0 | The ID of the VM to set active |
| REG1 | 63:16 | REVI |
| REG2 | 15:0 | The ID of the VP to set active |
| REG2 | 63:16 | REVI |
| REG3 | 15:0 | The ID of the VS to set active |
| REG3 | 63:16 | REVI |

**const, uint64_t: BF_VS_OP_ADVANCE_IP_AND_SET_ACTIVE_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x000000000000000D | Defines the index for bf_vs_op_advance_ip_and_set_active |

### 2.15.15. bf_vs_op_tlb_flush, OP=0x6, IDX=0xE

Given the ID of a VS, invalidates a TLB entry for a given GLA on the PP that this is executed on.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of bf_handle_op_open_handle |
| REG1 | 15:0 | The ID of the VS to invalidate |
| REG1 | 63:16 | REVI |
| REG2 | 63:0 | The GLA to invalidate |

**const, uint64_t: BF_VS_OP_TLB_FLUSH_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x000000000000000E | Defines the index for bf_vs_op_tlb_flush |

## 2.16. Intrinsic Syscalls

### 2.16.1. bf_intrinsic_op_rdmsr, OP=0x7, IDX=0x0

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

**const, uint64_t: BF_INTRINSIC_OP_RDMSR_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000000 | Defines the index for bf_intrinsic_op_rdmsr |

### 2.16.2. bf_intrinsic_op_wrmsr, OP=0x7, IDX=0x1

Writes to an MSR directly from the CPU given the address of the MSR to write and the value to write. Note that this is specific to Intel/AMD only. Also note that not all MSRs can be written to, and which MSRs that can be written to is up to the microkernel's internal policy as well as which architecture the hypervisor is running on.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of bf_handle_op_open_handle |
| REG1 | 31:0 | The address of the MSR to write to |
| REG1 | 63:32 | REVI |
| REG2 | 63:0 | The value to write to the requested MSR |

**const, uint64_t: BF_INTRINSIC_OP_WRMSR_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000001 | Defines the index for bf_intrinsic_op_wrmsr |

## 2.17. Mem Syscalls

Each extension has access to several different memory pools:
- The page pool (used for allocating pages)
- The huge pool (used for allocating physically contiguous pages)
- TLS (used for thread-local storage)
- The direct map

The page pool provides a means to allocate a page.

The huge pool provides a method for allocating physically contiguous memory. This pool is small and platform-dependent (as in less than a megabyte total).
It should be noted that some microkernels may choose not to implement bf_mem_op_free_huge which is optional.

Thread-Local Storage (TLS) memory (typically allocated using `thread_local`) provides per-physical processor storage. The amount of TLS available to an extension is 1 page per physical processor.

The direct map provides an extension with a means to access any physical address by accessing the direct map region of the virtual address space (depends on the hypervisor's configuration). By default, on Intel/AMD with 4-level paging, this region starts at 0x0000600000000000, but it can be changed using CMake. An extension can access any physical address by simply adding 0x0000600000000000 to the physical address and dereferencing the resulting value. When a VM is destroyed, all physical memory maps associated with that VM will be removed. The direct map is also where page and huge page allocations are mapped, providing an extension with a simple means for performing a virtual address to physical address (and vice versa) translations.

### 2.17.1. bf_mem_op_alloc_page, OP=0x8, IDX=0x0

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

**const, uint64_t: BF_MEM_OP_ALLOC_PAGE_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000000 | Defines the index for bf_mem_op_alloc_page |

### 2.17.2. bf_mem_op_free_page, OP=0x8, IDX=0x1

Frees a page previously allocated by bf_mem_op_alloc_page. This operation is optional and not all microkernels may implement it.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of bf_handle_op_open_handle |
| REG1 | 63:0 | The virtual address of the page to free |

**Output:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |

**const, uint64_t: BF_MEM_OP_FREE_PAGE_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000001 | Defines the index for bf_mem_op_free_page |


### 2.17.3. bf_mem_op_alloc_huge, OP=0x8, IDX=0x2

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

**const, uint64_t: BF_MEM_OP_ALLOC_HUGE_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000002 | Defines the index for bf_mem_op_alloc_huge |

### 2.17.4. bf_mem_op_free_huge, OP=0x8, IDX=0x3

Frees memory previously allocated by bf_mem_op_alloc_huge. This operation is optional and not all microkernels may implement it.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of bf_handle_op_open_handle |
| REG1 | 63:0 | The virtual address of the memory to free |

**Output:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |

**const, uint64_t: BF_MEM_OP_FREE_HUGE_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000003 | Defines the index for bf_mem_op_free_huge |
