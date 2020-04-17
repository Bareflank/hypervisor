#ifndef VMM_VM_VCPU_OPERATIONS_HPP
#define VMM_VM_VCPU_OPERATIONS_HPP

#include <vmm/vcpu/x64/x64_vcpu.hpp>
#include <vmm/vcpu/x64/x64_vcpu_delegate.hpp>

namespace vmm
{

class vcpu_op
{
public:

    virtual void vcpu_init_handler_set(x64_vcpu_delegate func) noexcept = 0;
    virtual void vcpu_fini_handler_set(x64_vcpu_delegate func) noexcept = 0;

    virtual ~vcpu_op() noexcept = default;
protected:
    vcpu_op() noexcept = default;
    vcpu_op(vcpu_op &&) noexcept = default;
    vcpu_op &operator=(vcpu_op &&) noexcept = default;
    vcpu_op(vcpu_op const &) = delete;
    vcpu_op &operator=(vcpu_op const &) & = delete;
};

}

#endif
