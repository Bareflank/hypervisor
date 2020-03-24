#ifndef VMMCTL_VMM_INFO_HPP
#define VMMCTL_VMM_INFO_HPP

#include <bsl/exit_code.hpp>

namespace vmmctl
{

class vmm_info
{
public:

    virtual bsl::exit_code dump() noexcept = 0;
    virtual bsl::exit_code status() noexcept = 0;

    virtual ~vmm_info() noexcept = default;
protected:
    vmm_info() noexcept = default;
    vmm_info(vmm_info &&) noexcept = default;
    vmm_info &operator=(vmm_info &&) noexcept = default;
    vmm_info(vmm_info const &) = delete;
    vmm_info &operator=(vmm_info const &) & = delete;
};

}

#endif
