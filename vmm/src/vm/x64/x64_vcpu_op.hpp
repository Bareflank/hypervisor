#ifndef VMM_x64_VCPU_OPERATIONS_HPP
#define VMM_x64_VCPU_OPERATIONS_HPP

#include <vmm/vm/x64/x64_vcpu_op.hpp>

namespace vmm
{

class x64_vcpu_op:
    public vcpu_op
{
public:

    void vcpu_init_handler_set(x64_vcpu_delegate func) noexcept final
    {
        // TODO: Implement Me!
        return;
    }

    void
    vcpu_fini_handler_set(x64_vcpu_delegate func) noexcept final
    {
        // TODO: Implement Me!
        return;
    }

    x64_vcpu_op() noexcept = default;
};

}

#endif
