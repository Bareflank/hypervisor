;
; Copyright (C) 2019 Assured Information Security, Inc.
;
; Permission is hereby granted, free of charge, to any person obtaining a copy
; of this software and associated documentation files (the "Software"), to deal
; in the Software without restriction, including without limitation the rights
; to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
; copies of the Software, and to permit persons to whom the Software is
; furnished to do so, subject to the following conditions:
;
; The above copyright notice and this permission notice shall be included in all
; copies or substantial portions of the Software.
;
; THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
; IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
; FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
; AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
; LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
; OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
; SOFTWARE.

bits 64
default rel

%define CPUID_PERF_MONITORING                                     0x0000000A
%define CPUID_PERF_MONITORING_VERSION_ID                          0x00000002

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

extern _write_es
extern _write_cs
extern _write_ss
extern _write_ds
extern _write_gs
extern _write_fs
extern _write_ldtr
extern _write_tr
extern _write_msr
extern _write_msr
extern _write_gdt
extern _write_idt
extern _write_cr0
extern _write_cr3
extern _write_cr4
extern _write_dr7
extern _cpuid_eax

section .text

; Promote VMCS
;
; Continues execution using the Guest state. Once this function executes,
; the host VMM will stop executing, and the guest will execute at the
; instruction that it exited on (likely the vmxoff instruction)
;
; NOTE: The order of these registers and their indexes depend on the
;       state save structure in the intrinsics code. If you change that
;       code, make sure you update this code to reflect the change.
;
global vmcs_promote
vmcs_promote:

    mov r15, rdi

    ;
    ; Restore Control Registers
    ;

    mov rsi, VMCS_GUEST_CR0
    vmread rdi, rsi
    call _write_cr0 wrt ..plt

    mov rsi, VMCS_GUEST_CR3
    vmread rdi, rsi
    push rdi

    and rdi, 0xFFFFFFFFFFFFF000
    call _write_cr3 wrt ..plt

    mov rsi, VMCS_GUEST_CR4
    vmread rdi, rsi
    call _write_cr4 wrt ..plt

    pop rdi
    call _write_cr3 wrt ..plt

    mov rsi, VMCS_GUEST_DR7
    vmread rdi, rsi
    call _write_dr7 wrt ..plt

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
    call _write_gdt wrt ..plt

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
    call _write_idt wrt ..plt

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
    call _write_es wrt ..plt

    mov rsi, VMCS_GUEST_CS_SELECTOR
    vmread rdi, rsi
    call _write_cs wrt ..plt

    mov rsi, VMCS_GUEST_SS_SELECTOR
    vmread rdi, rsi
    call _write_ss wrt ..plt

    mov rsi, VMCS_GUEST_DS_SELECTOR
    vmread rdi, rsi
    call _write_ds wrt ..plt

    mov rsi, VMCS_GUEST_FS_SELECTOR
    vmread rdi, rsi
    call _write_fs wrt ..plt

    mov rsi, VMCS_GUEST_GS_SELECTOR
    vmread rdi, rsi
    call _write_gs wrt ..plt

    mov rsi, VMCS_GUEST_LDTR_SELECTOR
    vmread rdi, rsi
    call _write_ldtr wrt ..plt

    mov rsi, VMCS_GUEST_TR_SELECTOR
    vmread rdi, rsi
    call _write_tr wrt ..plt

    ;
    ; Restore MSRs
    ;

    mov rdi, IA32_DEBUGCTL_MSR
    mov rsi, VMCS_GUEST_IA32_DEBUGCTL_FULL
    vmread rsi, rsi
    call _write_msr wrt ..plt

    mov rdi, IA32_PAT_MSR
    mov rsi, VMCS_GUEST_IA32_PAT_FULL
    vmread rsi, rsi
    call _write_msr wrt ..plt

    mov rdi, IA32_EFER_MSR
    mov rsi, VMCS_GUEST_IA32_EFER_FULL
    vmread rsi, rsi
    call _write_msr wrt ..plt

    ;
    ; Check CPUID.0AH:EAX[7:0] for the existence of
    ; the IA32_PERF_GLOBAL_CTRL_MSR before writing
    ;

    mov edi, CPUID_PERF_MONITORING
    call _cpuid_eax wrt ..plt
    cmp al, CPUID_PERF_MONITORING_VERSION_ID
    jl .perf_not_supported

    mov rdi, IA32_PERF_GLOBAL_CTRL_MSR
    mov rsi, VMCS_GUEST_IA32_PERF_GLOBAL_CTRL_FULL
    vmread rsi, rsi
    call _write_msr wrt ..plt

.perf_not_supported:

    mov rdi, IA32_SYSENTER_CS_MSR
    mov rsi, VMCS_GUEST_IA32_SYSENTER_CS
    vmread rsi, rsi
    call _write_msr wrt ..plt

    mov rdi, IA32_SYSENTER_ESP_MSR
    mov rsi, VMCS_GUEST_IA32_SYSENTER_ESP
    vmread rsi, rsi
    call _write_msr wrt ..plt

    mov rdi, IA32_SYSENTER_EIP_MSR
    mov rsi, VMCS_GUEST_IA32_SYSENTER_EIP
    vmread rsi, rsi
    call _write_msr wrt ..plt

    mov rdi, IA32_FS_BASE_MSR
    mov rsi, VMCS_GUEST_FS_BASE
    vmread rsi, rsi
    call _write_msr wrt ..plt

    mov rdi, IA32_GS_BASE_MSR
    mov rsi, VMCS_GUEST_GS_BASE
    vmread rsi, rsi
    call _write_msr wrt ..plt

    mov rsi, 0x00006820
    vmread rdi, rsi
    and rdi, 0xFFFFFFFFFFFFFDFF
    push rdi
    popf
    
    ;
    ; Restore Registers
    ;

    mov rdi, r15

    movdqa xmm7,   [rdi + 0x1A0]
    movdqa xmm6,   [rdi + 0x180]
    movdqa xmm5,   [rdi + 0x160]
    movdqa xmm4,   [rdi + 0x140]
    movdqa xmm3,   [rdi + 0x120]
    movdqa xmm2,   [rdi + 0x100]
    movdqa xmm1,   [rdi + 0x0E0]
    movdqa xmm0,   [rdi + 0x0C0]

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
