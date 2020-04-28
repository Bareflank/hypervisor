#ifndef VMM_VM_ID_NULL_HPP
#define VMM_VM_ID_NULL_HPP

#include <vmm/vm/vm_property.hpp>

namespace vmm
{

class common_vm_property:
    public vm_property
{
public:

    common_vm_property() noexcept = default;

    uint32_t get_id() noexcept final
    {
        // TODO: Implement Me!
        return 0;
    }

    void set_id(uint32_t id) noexcept
    {
        // TODO: Implement Me!
        return;
    }
};

}

#endif
