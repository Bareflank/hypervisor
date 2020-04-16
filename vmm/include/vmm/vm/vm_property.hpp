#ifndef VMM_VM_VM_ID_HPP
#define VMM_VM_VM_ID_HPP

#include <bsl/cstdint.hpp>

namespace vmm
{

class vm_property
{
public:

    virtual uint32_t id_get() noexcept = 0;

    virtual ~vm_property() noexcept = default;
protected:
    vm_property() noexcept = default;
    vm_property(vm_property &&) noexcept = default;
    vm_property &operator=(vm_property &&) noexcept = default;
    vm_property(vm_property const &) = delete;
    vm_property &operator=(vm_property const &) & = delete;
};

}

#endif
