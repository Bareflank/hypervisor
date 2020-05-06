#ifndef VMM_X64_VM_HPP
#define VMM_X64_VM_HPP

#include <vmm/vm/vm.hpp>
#include <vmm/vm/x64/x64_vcpu_op.hpp>

namespace vmm
{

class x64_vm :
    public vm,
    public vcpu_op
{
public:
    ~x64_vm() noexcept override = default;
protected:
    x64_vm() noexcept = default;
    x64_vm(x64_vm &&) noexcept = default;
    x64_vm &operator=(x64_vm &&) noexcept = default;
    x64_vm(x64_vm const &) = delete;
    x64_vm &operator=(x64_vm const &) & = delete;
};

}

#endif
