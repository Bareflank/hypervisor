
Bareflank EFI loader is an EFI executable that can launch bareflank from the EFI environment.

To build, ensure that ENABLE_BUILD_EFI=ON and BUILD_STATIC_LIBS=ON and make target efi_main_x86_64-vmm-elf.  Variable EFI_VMM_NAME can be specified to use an extended vmm with the loader (vmm should be located at ${VMM_PREFIX}/bin/${EFI_VMM_NAME})

The exit handlers necessary for booting an operating system afterwards are contained in extended_apis and enabled by setting platform_info_t.efi.enabled = 1

Use the API in bfdriver/include/boot.h to extend the EFI loader with your own functionality.  efi.h and efilib.h for the gnuefi library are available for use in EFI loader extensions.  Add EFI extensions in the same manner as VMM extensions (EXTENSION variable), possibly sharing a CMakeLists.txt file with other extension declarations.

Example that adds a print statement before launching bareflank:

hello/hello.c:
```
#include "boot.h"
#include "efi.h"
#include "efilib.h"

boot_ret_t my_prestart_fn()
{
    Print(L"hello from my_prestart_fn\n");
    return BOOT_CONTINUE;
}

boot_ret_t register_module_hello()
{
    boot_add_prestart_fn(my_prestart_fn);
    return BOOT_SUCCESS;
}
```

hello/CMakeLists.txt:
```
add_efi_module(
    NAME hello
    SOURCES hello.c
)
```

NOTE: add_efi_module NAME must match register_module_NAME to link correctly
