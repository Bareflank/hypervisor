#ifndef VMM_VM_HPP
#define VMM_VM_HPP

#include <vmm/vm/vm_id.hpp>
#include <bsl/errc_type.hpp>

namespace vmm
{

class vm :
    public vm_id
{
public:
    ~vm() noexcept override = default;
protected:
    vm() noexcept = default;
    vm(vm &&) noexcept = default;
    vm &operator=(vm &&) noexcept = default;
    vm(vm const &) = delete;
    vm &operator=(vm const &) & = delete;
};

}

#endif
