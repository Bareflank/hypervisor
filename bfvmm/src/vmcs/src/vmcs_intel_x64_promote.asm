;
; Bareflank Hypervisor
;
; Copyright (C) 2015 Assured Information Security, Inc.
; Author: Rian Quinn        <quinnr@ainfosec.com>
; Author: Brendan Kerrigan  <kerriganb@ainfosec.com>
;
; This library is free software; you can redistribute it and/or
; modify it under the terms of the GNU Lesser General Public
; License as published by the Free Software Foundation; either
; version 2.1 of the License, or (at your option) any later version.
;
; This library is distributed in the hope that it will be useful,
; but WITHOUT ANY WARRANTY; without even the implied warranty of
; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
; Lesser General Public License for more details.
;
; You should have received a copy of the GNU Lesser General Public
; License along with this library; if not, write to the Free Software
; Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA

bits 64
default rel

%define VMCS_GUEST_IA32_DEBUGCTL_FULL                             0x00002802
%define VMCS_GUEST_IA32_PAT_FULL                                  0x00002804
%define VMCS_GUEST_IA32_EFER_FULL                                 0x00002806
%define VMCS_GUEST_IA32_PERF_GLOBAL_CTRL_FULL                     0x00002808
%define VMCS_GUEST_IA32_SYSENTER_CS                               0x0000482A
%define VMCS_GUEST_IA32_SYSENTER_ESP                              0x00006824
%define VMCS_GUEST_IA32_SYSENTER_EIP                              0x00006826
%define VMCS_GUEST_FS_BASE                                        0x0000680E
%define VMCS_GUEST_GS_BASE                                        0x00006810

%define IA32_DEBUGCTL_MSR                                         0x000001D9
%define IA32_PAT_MSR                                              0x00000277
%define IA32_EFER_MSR                                             0xC0000080
%define IA32_PERF_GLOBAL_CTRL_MSR                                 0x0000038F
%define IA32_SYSENTER_CS_MSR                                      0x00000174
%define IA32_SYSENTER_ESP_MSR                                     0x00000175
%define IA32_SYSENTER_EIP_MSR                                     0x00000176
%define IA32_FS_BASE_MSR                                          0xC0000100
%define IA32_GS_BASE_MSR                                          0xC0000101

%define VMCS_GUEST_ES_SELECTOR                                    0x00000800
%define VMCS_GUEST_CS_SELECTOR                                    0x00000802
%define VMCS_GUEST_SS_SELECTOR                                    0x00000804
%define VMCS_GUEST_DS_SELECTOR                                    0x00000806
%define VMCS_GUEST_FS_SELECTOR                                    0x00000808
%define VMCS_GUEST_GS_SELECTOR                                    0x0000080A
%define VMCS_GUEST_LDTR_SELECTOR                                  0x0000080C
%define VMCS_GUEST_TR_SELECTOR                                    0x0000080E

%define VMCS_GUEST_GDTR_BASE                                      0x00006816
%define VMCS_GUEST_GDTR_LIMIT                                     0x00004810

%define VMCS_GUEST_IDTR_BASE                                      0x00006818
%define VMCS_GUEST_IDTR_LIMIT                                     0x00004812

%define VMCS_GUEST_CR0                                            0x00006800
%define VMCS_GUEST_CR3                                            0x00006802
%define VMCS_GUEST_CR4                                            0x00006804
%define VMCS_GUEST_DR7                                            0x0000681A

global vmcs_promote:function

extern __write_es
extern __write_cs
extern __write_ss
extern __write_ds
extern __write_gs
extern __write_fs
extern __write_ldtr
extern __write_tr
extern __write_msr
extern __write_msr
extern __write_gdt
extern __write_idt
extern __write_cr0;
extern __write_cr3;
extern __write_cr4;
extern __write_dr7;

section .text

; Promote VMCS
;
; Continues execution using the Guest state. Once this function execute,
; the host VMM will stop executing, and the guest will execute at the
; instruction that it exited on (likely the vmxoff instruction)
;
; NOTE: The order of these registers and their indexes depend on the
;       state save structure in the intrinsics code. If you change that
;       code, make sure you update this code to reflect the change.
;
vmcs_promote:

    mov r15, rdi

    ;
    ; Restore Control Registers
    ;

    mov rsi, VMCS_GUEST_CR0
    vmread rdi, rsi
    call __write_cr0 wrt ..plt

    mov rsi, VMCS_GUEST_CR3
    vmread rdi, rsi
    call __write_cr3 wrt ..plt

    mov rsi, VMCS_GUEST_CR4
    vmread rdi, rsi
    call __write_cr4 wrt ..plt

    mov rsi, VMCS_GUEST_DR7
    vmread rdi, rsi
    call __write_dr7 wrt ..plt

    ;
    ; Restore GDT
    ;

    mov rsi, VMCS_GUEST_GDTR_BASE
    vmread rdi, rsi
    push rdi

    mov rsi, VMCS_GUEST_GDTR_LIMIT
    vmread rdi, rsi
    push di

    mov rdi, rsp
    call __write_gdt wrt ..plt

    ;
    ; Restore IDT
    ;

    mov rsi, VMCS_GUEST_IDTR_BASE
    vmread rdi, rsi
    push rdi

    mov rsi, VMCS_GUEST_IDTR_LIMIT
    vmread rdi, rsi
    push di

    mov rdi, rsp
    call __write_idt wrt ..plt

    ;
    ; Clear TSS Busy
    ;

    mov rsi, VMCS_GUEST_GDTR_BASE
    vmread rdi, rsi
    mov rsi, VMCS_GUEST_TR_SELECTOR
    vmread rsi, rsi

    add rdi, rsi

    mov rax, 0xFFFFFDFFFFFFFFFF
    and [rdi], rax

    ;
    ; Restore Selectors
    ;

    mov rsi, VMCS_GUEST_ES_SELECTOR
    vmread rdi, rsi
    call __write_es wrt ..plt

    mov rsi, VMCS_GUEST_CS_SELECTOR
    vmread rdi, rsi
    call __write_cs wrt ..plt

    mov rsi, VMCS_GUEST_SS_SELECTOR
    vmread rdi, rsi
    call __write_ss wrt ..plt

    mov rsi, VMCS_GUEST_DS_SELECTOR
    vmread rdi, rsi
    call __write_ds wrt ..plt

    mov rsi, VMCS_GUEST_FS_SELECTOR
    vmread rdi, rsi
    call __write_fs wrt ..plt

    mov rsi, VMCS_GUEST_GS_SELECTOR
    vmread rdi, rsi
    call __write_gs wrt ..plt

    mov rsi, VMCS_GUEST_LDTR_SELECTOR
    vmread rdi, rsi
    call __write_ldtr wrt ..plt

    mov rsi, VMCS_GUEST_TR_SELECTOR
    vmread rdi, rsi
    call __write_tr wrt ..plt

    ;
    ; Restore MSRs
    ;

    mov rdi, IA32_DEBUGCTL_MSR
    mov rsi, VMCS_GUEST_IA32_DEBUGCTL_FULL
    vmread rsi, rsi
    call __write_msr wrt ..plt

    mov rdi, IA32_PAT_MSR
    mov rsi, VMCS_GUEST_IA32_PAT_FULL
    vmread rsi, rsi
    call __write_msr wrt ..plt

    mov rdi, IA32_EFER_MSR
    mov rsi, VMCS_GUEST_IA32_EFER_FULL
    vmread rsi, rsi
    call __write_msr wrt ..plt

    mov rdi, IA32_PERF_GLOBAL_CTRL_MSR
    mov rsi, VMCS_GUEST_IA32_PERF_GLOBAL_CTRL_FULL
    vmread rsi, rsi
    call __write_msr wrt ..plt

    mov rdi, IA32_SYSENTER_CS_MSR
    mov rsi, VMCS_GUEST_IA32_SYSENTER_CS
    vmread rsi, rsi
    call __write_msr wrt ..plt

    mov rdi, IA32_SYSENTER_ESP_MSR
    mov rsi, VMCS_GUEST_IA32_SYSENTER_ESP
    vmread rsi, rsi
    call __write_msr wrt ..plt

    mov rdi, IA32_SYSENTER_EIP_MSR
    mov rsi, VMCS_GUEST_IA32_SYSENTER_EIP
    vmread rsi, rsi
    call __write_msr wrt ..plt

    mov rdi, IA32_FS_BASE_MSR
    mov rsi, VMCS_GUEST_FS_BASE
    vmread rsi, rsi
    call __write_msr wrt ..plt

    mov rdi, IA32_GS_BASE_MSR
    mov rsi, VMCS_GUEST_GS_BASE
    vmread rsi, rsi
    call __write_msr wrt ..plt

    ;
    ; Restore Registers
    ;

    mov rdi, r15

%ifdef AVX_SUPPORTED
    vmovdqa ymm15, [rdi + 0x2A0]
    vmovdqa ymm14, [rdi + 0x280]
    vmovdqa ymm13, [rdi + 0x260]
    vmovdqa ymm12, [rdi + 0x240]
    vmovdqa ymm11, [rdi + 0x220]
    vmovdqa ymm10, [rdi + 0x200]
    vmovdqa ymm9,  [rdi + 0x1E0]
    vmovdqa ymm8,  [rdi + 0x1C0]
    vmovdqa ymm7,  [rdi + 0x1A0]
    vmovdqa ymm6,  [rdi + 0x180]
    vmovdqa ymm5,  [rdi + 0x160]
    vmovdqa ymm4,  [rdi + 0x140]
    vmovdqa ymm3,  [rdi + 0x120]
    vmovdqa ymm2,  [rdi + 0x100]
    vmovdqa ymm1,  [rdi + 0x0E0]
    vmovdqa ymm0,  [rdi + 0x0C0]
%else
    movdqa xmm7,  [rdi + 0x1A0]
    movdqa xmm6,  [rdi + 0x180]
    movdqa xmm5,  [rdi + 0x160]
    movdqa xmm4,  [rdi + 0x140]
    movdqa xmm3,  [rdi + 0x120]
    movdqa xmm2,  [rdi + 0x100]
    movdqa xmm1,  [rdi + 0x0E0]
    movdqa xmm0,  [rdi + 0x0C0]
%endif

    mov rsp,       [rdi + 0x080]
    mov rax,       [rdi + 0x078]
    push rax

    mov r15,       [rdi + 0x070]
    mov r14,       [rdi + 0x068]
    mov r13,       [rdi + 0x060]
    mov r12,       [rdi + 0x058]
    mov r11,       [rdi + 0x050]
    mov r10,       [rdi + 0x048]
    mov r9,        [rdi + 0x040]
    mov r8,        [rdi + 0x038]
    mov rsi,       [rdi + 0x028]
    mov rbp,       [rdi + 0x020]
    mov rdx,       [rdi + 0x018]
    mov rcx,       [rdi + 0x010]
    mov rbx,       [rdi + 0x008]
    mov rax,       [rdi + 0x000]

    mov rdi,       [rdi + 0x030]

    sti
    ret
