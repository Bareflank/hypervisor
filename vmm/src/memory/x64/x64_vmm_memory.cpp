#include <vmm/memory/vmm_memory.hpp>

namespace vmm
{

void * hva_alloc(uintmax_t size)
{
    // TODO: Implement Me!
    return static_cast<void *>(nullptr);
}

void * hva_map_alloc(uintptr_t hpa, uintmax_t size, page_size ps)
{
    // TODO: Implement Me!
    return static_cast<void *>(nullptr);
}

void hva_free(void * hva)
{
    // TODO: Implement Me!
    return;
}

uintptr_t hva_to_hpa(void * hva)
{
    // TODO: Implement Me!
    return 0;
}

}
