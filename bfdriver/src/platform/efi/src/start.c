/*
 * Bareflank Hypervisor
 * Copyright (C) 2018 Assured Information Security, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is furnished to do
 * so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

#include "bfefi.h"
#include "bflib.h"
#include "bfloader.h"
#include "common.h"
#include "x86_64.h"

VOID __attribute__((ms_abi)) bf_stop_hypervisor_on_core(VOID *data)
{
    (void)data;
    common_stop_core();
}

VOID __attribute__((ms_abi)) bf_cpuid_on_core(VOID *data)
{
    (void)data;
    __asm("cpuid");
}

VOID __attribute__((ms_abi)) bf_start_hypervisor_on_core(VOID *data)
{
    (void)data;

    _writerflags(_readrflags() & ~(1ULL << 18));

    KDESCRIPTOR old_gdt;
    _sgdt((void *)&old_gdt.Limit);

    PKGDTENTRY64 tss_entry, new_gdt;
    PKTSS64 tss;
    KDESCRIPTOR gdtr;
    _sgdt((void *)&gdtr.Limit);

    UINTN newsize = gdtr.Limit + 1;
    if (KGDT64_SYS_TSS + sizeof(*tss_entry) > newsize) {
        newsize = KGDT64_SYS_TSS + sizeof(*tss_entry);
    }

    new_gdt = (PKGDTENTRY64)bf_allocate_zero_pool(newsize);
    if (new_gdt == NULL) {
        Print(L"Error: bf_start_hypervisor_on_core: bf_allocate_zero_pool1\n");
        return;
    }

    gBS->CopyMem(new_gdt, gdtr.Base, gdtr.Limit + 1);

    tss = (PKTSS64)bf_allocate_zero_pool(sizeof(*tss) * 2);
    if (tss == NULL) {
        Print(L"Error: bf_start_hypervisor_on_core: bf_allocate_zero_pool2\n");
        return;
    }

    tss_entry = (PKGDTENTRY64)((uintptr_t)new_gdt + KGDT64_SYS_TSS);
    tss_entry->BaseLow = (uintptr_t)tss & 0xffff;
    tss_entry->Bits.BaseMiddle = ((uintptr_t)tss >> 16) & 0xff;
    tss_entry->Bits.BaseHigh = ((uintptr_t)tss >> 24) & 0xff;
    tss_entry->BaseUpper = (uintptr_t)tss >> 32;
    tss_entry->LimitLow = sizeof(KTSS64) - 1;
    tss_entry->Bits.Type = AMD64_TSS;
    tss_entry->Bits.Dpl = 0;
    tss_entry->Bits.Present = 1;
    tss_entry->Bits.System = 0;
    tss_entry->Bits.LongMode = 0;
    tss_entry->Bits.DefaultBig = 0;
    tss_entry->Bits.Granularity = 0;
    tss_entry->MustBeZero = 0;

    gdtr.Base = new_gdt;
    gdtr.Limit = KGDT64_SYS_TSS + sizeof(*tss_entry);
    _lgdt((void *)&gdtr.Limit);
    _ltr(KGDT64_SYS_TSS);

    _set_ne();
    int64_t ret = common_start_core();
    if (ret < 0) {
        Print(L"Error: bf_start_hypervisor_on_core: common_start_core %x\n", ret);
        return;
    }

    // Load previous gdt
    _lgdt((void *)&old_gdt.Limit);

    bf_free_pool((void *)new_gdt);
    bf_free_pool((void *)tss);

    Print(L"Core started.\n");

    return;
}

EFI_STATUS bf_start_by_startupallaps()
{
    EFI_STATUS status;
    UINTN cpus;
    EFI_MP_SERVICES_PROTOCOL *mp_services;

    EFI_GUID gEfiMpServiceProtocolGuid = EFI_MP_SERVICES_PROTOCOL_GUID;
    status = gBS->LocateProtocol(&gEfiMpServiceProtocolGuid,
                                 NULL,
                                 (VOID **)&mp_services);
    if (EFI_ERROR(status)) {
        PRINT_ERROR(status);
        goto fail;
    }

    cpus = bf_num_cpus();
    if (cpus == 0) {
        Print(L"Error: bf_start_by_startupallaps: bf_num_cpus\n");
        return EFI_NOT_FOUND;
    }
    Print(L"Detected %u CPUs.\n", cpus);

    if (cpus > 1) {
        status = mp_services->StartupAllAPs(mp_services,
                                            (EFI_AP_PROCEDURE)bf_start_hypervisor_on_core,
                                            TRUE,
                                            NULL,
                                            10000000,
                                            NULL,
                                            NULL);
        if (EFI_ERROR(status)) {
            PRINT_ERROR(status);
            goto fail;
        }
    }

    bf_start_hypervisor_on_core(NULL);

    return EFI_SUCCESS;

fail:

    return status;

}


EFI_STATUS bf_start_by_switchbsp()
{
    EFI_STATUS status;
    UINTN cpus;
    EFI_MP_SERVICES_PROTOCOL *mp_services;

    EFI_GUID gEfiMpServiceProtocolGuid = EFI_MP_SERVICES_PROTOCOL_GUID;
    status = gBS->LocateProtocol(&gEfiMpServiceProtocolGuid,
                                 NULL,
                                 (VOID **)&mp_services);
    if (EFI_ERROR(status)) {
        PRINT_ERROR(status);
        goto fail;
    }

    cpus = bf_num_cpus();
    if (cpus == 0) {
        Print(L"Error: bf_start_by_switchbsp: bf_num_cpus\n");
        return EFI_NOT_FOUND;
    }
    Print(L"Detected %u CPUs.\n", cpus);

    if (cpus > 1) {
        UINTN cur = cpus - 1;
        while (cur > 0) {
            status = mp_services->SwitchBSP(mp_services,
                                            cur,
                                            TRUE);
            if (EFI_ERROR(status)) {
                PRINT_ERROR(status);
                goto fail;
            }

            bf_start_hypervisor_on_core(NULL);
            cur--;
        }
    }

    status = mp_services->SwitchBSP(mp_services,
                                    0,
                                    TRUE);

    bf_start_hypervisor_on_core(NULL);

    return EFI_SUCCESS;

fail:

    return status;

}


EFI_STATUS bf_start_by_interactive()
{
    Print(L"Interactive start\n");
    EFI_STATUS status;

    EFI_MP_SERVICES_PROTOCOL *mp_services;

    EFI_GUID gEfiMpServiceProtocolGuid = EFI_MP_SERVICES_PROTOCOL_GUID;
    status = gBS->LocateProtocol(&gEfiMpServiceProtocolGuid,
                                 NULL,
                                 (VOID **)&mp_services);
    if (EFI_ERROR(status)) {
        PRINT_ERROR(status);
        goto fail;
    }

    UINTN ncpus = bf_num_cpus();
    if (ncpus == 0) {
        Print(L"bf_start_by_interactive: error bf_num_cpus returned zero\n");
        return EFI_NOT_FOUND;
    }

    UINTN started[16] = {0};

    EFI_INPUT_KEY pressed;
    while (1) {

        EFI_STATUS status = console_get_keystroke(&pressed);
        if (EFI_ERROR(status)) {
            PRINT_ERROR(status);
            goto fail;
        }

        if (pressed.ScanCode == 0) {
            if (pressed.UnicodeChar >= L'1' && pressed.UnicodeChar <= L'9') {
                UINTN core = (UINTN)(pressed.UnicodeChar - L'0');
                if (started[core] == 0) {
                    status = mp_services->StartupThisAP(mp_services,
                                                        (EFI_AP_PROCEDURE)bf_start_hypervisor_on_core,
                                                        core,
                                                        NULL,
                                                        50000000,
                                                        NULL,
                                                        NULL);
                    if (EFI_ERROR(status)) {
                        PRINT_ERROR(status);
                        goto fail;
                    }

                    started[core] = 1;
                }
                else {
                    status = mp_services->StartupThisAP(mp_services,
                                                        (EFI_AP_PROCEDURE)bf_cpuid_on_core,
                                                        core,
                                                        NULL,
                                                        50000000,
                                                        NULL,
                                                        NULL);
                    if (EFI_ERROR(status)) {
                        PRINT_ERROR(status);
                        goto fail;
                    }
                }
            }
            else if (pressed.UnicodeChar == L'0') {
                if (started[0] == 0) {
                    bf_start_hypervisor_on_core(NULL);
                    started[0] = 1;
                }
                else {
                    bf_cpuid_on_core(NULL);
                }
            }
        }
        else {
            break;
        }
    }

    Print(L"Leaving interactive mode\n");
    return EFI_SUCCESS;

fail:
    return status;

}
