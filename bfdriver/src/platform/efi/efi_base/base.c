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

#include "base.h"
#include "boot.h"
#include "mp_service.h"
#include "bfelf_loader.h"
#include "bftypes.h"
#include "common.h"


EFI_MP_SERVICES_PROTOCOL *g_mp_services;
extern char target_vmm_start[];
extern char target_vmm_end[];


VOID __attribute__((ms_abi))
bf_start_hypervisor_on_core(VOID *data)
{
    bfignored(data);
    _set_ne();
    platform_start_core();

    return;
}

static EFI_STATUS startup_ap(UINTN cpu)
{
    EFI_STATUS status = g_mp_services->StartupThisAP(
                            g_mp_services,
                            (EFI_AP_PROCEDURE)bf_start_hypervisor_on_core,
                            cpu,
                            NULL,
                            10000000,
                            NULL,
                            NULL
                        );
    if (EFI_ERROR(status)) {
        Print(L"base_start_fn StartupThisAP returned %r\n", status);
        return BOOT_ABORT;
    }
    return BOOT_CONTINUE;
}

boot_ret_t base_start_fn()
{
    EFI_STATUS status;

    uint64_t target_vmm_size = (uint64_t)(target_vmm_end - target_vmm_start);

    int64_t ret = common_add_module(
                      (const char *)target_vmm_start,
                      (uint64_t)target_vmm_size
                  );
    if (ret < 0) {
        Print(L"common_add_module returned %a\n", ec_to_str(ret));
        goto fail;
    }

    ret = common_load_vmm();
    if (ret < 0) {
        Print(L"common_load_vmm returned %a\n", ec_to_str(ret));
        goto fail;
    }

    uint64_t cpus = platform_num_cpus();
    if (cpus == 0) {
        Print(L"Error: bf_start_by_startupallaps: bf_num_cpus\n");
        goto fail;
    }

    Print(L"Starting hypervisor...\n");
    for (uint64_t i = 1; i < cpus; i++) {
        status = startup_ap(i);
        if (status != BOOT_CONTINUE) {
            return status;
        }
    }

    bf_start_hypervisor_on_core(NULL);
    return BOOT_CONTINUE;

fail:
    return BOOT_ABORT;
}

boot_ret_t base_prestart_fn()
{
    EFI_STATUS status;
    EFI_GUID gEfiMpServiceProtocolGuid = EFI_MP_SERVICES_PROTOCOL_GUID;
    status = gBS->LocateProtocol(
                 &gEfiMpServiceProtocolGuid,
                 NULL,
                 (VOID **)&g_mp_services
             );
    if (EFI_ERROR(status)) {
        Print(L"Locate mpservicesprotocol error %r\n", status);
        return BOOT_ABORT;
    }

    boot_platform_info.efi.enabled = 1;
    return BOOT_CONTINUE;
}

boot_ret_t register_module_base()
{
    boot_add_prestart_fn(base_prestart_fn);
    boot_set_start_fn(base_start_fn);
    return BOOT_SUCCESS;
}
