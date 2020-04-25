#ifndef VMM_PLATFORM_X64_MEMORY_HPP
#define VMM_PLATFORM_X64_MEMORY_HPP

#include <vmm/platform/x64/memory.hpp>

namespace vmm
{

class x64_memory:
    public memory
{
public:

    void * hva_map_alloc(uintptr_t hpa, uintmax_t size, page_size ps, memory_type mt)
    {
        // TODO: Implement Me!
        return static_cast<void *>(nullptr);
    }

    uintptr_t hva_to_hpa(void * hva)
    {
        // TODO: Implement Me!
        return 0;
    }

    x64_memory() noexcept = default;
};

}

#endif
