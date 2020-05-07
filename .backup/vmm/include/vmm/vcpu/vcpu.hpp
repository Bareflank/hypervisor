#ifndef VMM_VCPU_HPP
#define VMM_VCPU_HPP

#include <vmm/vcpu/execute.hpp>
#include <vmm/vcpu/instruction_pointer.hpp>
#include <vmm/vcpu/vcpu_property.hpp>
#include <vmm/vcpu/virtual_register.hpp>

namespace vmm
{

class vcpu :
    public execute,
    public instruction_pointer,
    public vcpu_property,
    public virtual_register
{
public:
    ~vcpu() noexcept override = default;
protected:
    vcpu() noexcept = default;
    vcpu(vcpu &&) noexcept = default;
    vcpu &operator=(vcpu &&) noexcept = default;
    vcpu(vcpu const &) = delete;
    vcpu &operator=(vcpu const &) & = delete;
};

}

#endif
