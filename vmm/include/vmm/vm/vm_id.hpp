#ifndef VMM_VM_VM_ID_HPP
#define VMM_VM_VM_ID_HPP

#include <bsl/cstdint.hpp>

namespace vmm
{

class vm_id
{
public:

    virtual uint32_t id() noexcept = 0;

    virtual ~vm_id() noexcept = default;
protected:
    vm_id() noexcept = default;
    vm_id(vm_id &&) noexcept = default;
    vm_id &operator=(vm_id &&) noexcept = default;
    vm_id(vm_id const &) = delete;
    vm_id &operator=(vm_id const &) & = delete;
};

}

#endif
