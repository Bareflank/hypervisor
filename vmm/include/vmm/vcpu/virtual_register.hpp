#ifndef VMM_VCPU_VIRTUAL_REGISTER_HPP
#define VMM_VCPU_VIRTUAL_REGISTER_HPP

#include <bsl/errc_type.hpp>

namespace vmm
{

class virtual_register
{
public:

    // TODO: Define My Interface!

    virtual ~virtual_register() noexcept = default;
protected:
    virtual_register() noexcept = default;
    virtual_register(virtual_register &&) noexcept = default;
    virtual_register &operator=(virtual_register &&) noexcept = default;
    virtual_register(virtual_register const &) = delete;
    virtual_register &operator=(virtual_register const &) & = delete;
};

}

#endif
