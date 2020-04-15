#ifndef VMM_VM_ID_NULL_HPP
#define VMM_VM_ID_NULL_HPP

#include <vmm/vm/vm_id.hpp>

namespace vmm
{

class vm_id_null:
    public vm_id
{
public:

    vm_id_null() noexcept = default;

    uint32_t
    id() noexcept final
    { return 0; }
};

}

#endif

