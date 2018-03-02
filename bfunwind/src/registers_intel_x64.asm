;
; Bareflank Unwind Library
; Copyright (C) 2015 Assured Information Security, Inc.
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

global __store_registers_intel_x64:function
global __load_registers_intel_x64:function

section .text

; void __store_registers_intel_x64(registers_intel_x64_t *state)
;
; This function saves the current register state. Since this function is
; "naked", the state of the registers is identical to the state of the
; registers prior to the call to this function, except for rsp, which has
; been moved down by 8 bytes to accomidate the return address. For this reason
; we adjust rsp prior to storing it so that we have an accurate rsp
;
; Also note that we use the return address as rip. The DWARF code is going to
; give us a set of instructions on how to roll back the stack, and those
; instructions are relative to rip. So, we could have used rip just prior to
; the call to this function, but since this function is "naked" we can also use
; rip just after the call to this function (which is the return address) as
; the register state has not changed.
;
__store_registers_intel_x64:
    mov [rdi + 000], rax
    mov [rdi + 008], rbx
    mov [rdi + 016], rcx
    mov [rdi + 024], rdx
    mov [rdi + 032], rdi
    mov [rdi + 040], rsi
    mov [rdi + 048], rbp
    add rsp, 8
    mov [rdi + 056], rsp
    sub rsp, 8
    mov [rdi + 064], r8
    mov [rdi + 072], r9
    mov [rdi + 080], r10
    mov [rdi + 088], r11
    mov [rdi + 096], r12
    mov [rdi + 104], r13
    mov [rdi + 112], r14
    mov [rdi + 120], r15

    mov rax, [rsp]
    mov [rdi + 128], rax

    ret

; void __load_registers_intel_x64(registers_intel_x64_t *state)
;
; The goal of this function is to "resume" by setting the current state of the
; CPU to the state that was saved. This function is a little complicated
; because the order of each instruction needs to be just right.
;
; First we start by restoring all of the registers minus rsp, rip, rax and rdi.
; rdi is currently storing the location of the state fields, so attempting to
; change that would result in the rest of the state being corrupt, so that is
; the very last thing to change. rax is used to help restore rip, so that needs
; to be restored once we are done with it. rsp needs to be restored prior to
; restoring rip, and rip is restored by pushing it to the stack so that the
; ret instruction can call it.
;
__load_registers_intel_x64:
    mov rdx, [rdi + 008]
    mov rcx, [rdi + 016]
    mov rbx, [rdi + 024]
    mov rsi, [rdi + 040]
    mov rbp, [rdi + 048]
    mov r8,  [rdi + 064]
    mov r9,  [rdi + 072]
    mov r10, [rdi + 080]
    mov r11, [rdi + 088]
    mov r12, [rdi + 096]
    mov r13, [rdi + 104]
    mov r14, [rdi + 112]
    mov r15, [rdi + 120]

    mov rsp, [rdi + 056]

    mov rax, [rdi + 128]
    push rax

    mov rax, [rdi + 000]
    mov rdi, [rdi + 032]

    ret
