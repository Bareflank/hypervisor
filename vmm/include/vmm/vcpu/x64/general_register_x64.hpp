#ifndef VMM_VCPU_X64_GENERAL_REGISTER_X64_HPP
#define VMM_VCPU_X64_GENERAL_REGISTER_X64_HPP

#include <bsl/errc_type.hpp>

namespace vmm
{

class general_register_x64
{
public:

    // TODO: Define My Interface!

    virtual ~general_register_x64() noexcept = default;
protected:
    general_register_x64() noexcept = default;
    general_register_x64(general_register_x64 &&) noexcept = default;
    general_register_x64 &operator=(general_register_x64 &&) noexcept = default;
    general_register_x64(general_register_x64 const &) = delete;
    general_register_x64 &operator=(general_register_x64 const &) & = delete;
};

}

#endif
