; @copyright
; Copyright (C) 2020 Assured Information Security, Inc.
;
; @copyright
; Permission is hereby granted, free of charge, to any person obtaining a copy
; of this software and associated documentation files (the "Software"), to deal
; in the Software without restriction, including without limitation the rights
; to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
; copies of the Software, and to permit persons to whom the Software is
; furnished to do so, subject to the following conditions:
;
; @copyright
; The above copyright notice and this permission notice shall be included in
; all copies or substantial portions of the Software.
;
; @copyright
; THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
; IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
; FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
; AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
; LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
; OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
; SOFTWARE.

    ; @brief defines the offset of state_save_t.debugctl
    SS_OFFSET_NMI EQU 318h

    esr_nmi_text SEGMENT ALIGN(1000h) 'CODE'
    esr_nmi PROC

    ; NOTE (IMPORTANT):
    ; - r15 is dedicated during the demotion process to the root_vp_state.
    ;   It cannot be changed from this until the kernel's actual ESRs are
    ;   loaded.

    push rax
    push rdx

    mov rax, 1h
    mov [r15 + SS_OFFSET_NMI], rax

    pop rdx
    pop rax

    iretq
    int 3

    esr_nmi ENDP
    esr_nmi_text ENDS
    end
