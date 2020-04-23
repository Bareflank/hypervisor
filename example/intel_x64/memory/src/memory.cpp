#include <vmm/x64.hpp>
#include <vmm/memory/vmm_memory.hpp>

namespace vmm
{

constexpr const uint32_t SIZE_4KB = 0x1000;
constexpr const uint32_t SIZE_16KB = 0x4000;
constexpr const uint32_t SIZE_4MB = 0x400000;
constexpr const uint32_t SIZE_1GB = 0x40000000;

bsl::errc_type vmm_init(x64_vm &root_vm, x64_platform &platform) noexcept
{
    // Allocate 1GB of memory
    void * bytes_1 = hva_alloc(SIZE_1GB);

    // Allocate a virtual address space of 16 KB that is mapped to the physical
    // address 0xF00D0000, using the default 4 KB page granularity.
    char * bytes_2 = hva_map_alloc<char>(0xF00D0000, SIZE_16KB);

    // Allocate a virtual address space of 4 MB that is mapped to the physical
    // address 0xBEEF0000, using 2 MB page granularity.
    uint32_t * bytes_3 = hva_map_alloc<uint32_t>(0xBEEF0000, SIZE_4MB,
                             page_size::page_2m);

    // Allocate a virtual address space of 4 KB that is mapped to uncacheable
    // (device) memory at the physical address 0xCAFE0000, using 4 KB page
    // granularity.
    uint32_t * bytes_4 = hva_map_alloc<uint32_t>(0xCAFE0000, SIZE_4KB,
                             page_size::page_4k, memory_type::uncacheable);

    // Resolve the host physical address that "bytes_2" is mapped to, which
    // will give 0xF00D0000
    uintptr_t bytes_2_host_phys_addr = hva_to_hpa(bytes_2);

    // Free the virtual address spaces defined by all mappings
    hva_free(bytes_1);
    hva_free(bytes_2);
    hva_free(bytes_3);
    hva_free(bytes_4);

    return 0;
}

}
