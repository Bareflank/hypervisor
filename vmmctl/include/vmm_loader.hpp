#ifndef VMMCTL_VMM_LOADER_HPP
#define VMMCTL_VMM_LOADER_HPP

#include <bsl/exit_code.hpp>

namespace vmmctl
{

class vmm_loader
{
public:

    virtual bsl::exit_code load() noexcept = 0;
    virtual bsl::exit_code unload() noexcept = 0;
    virtual bsl::exit_code start() noexcept = 0;
    virtual bsl::exit_code stop() noexcept = 0;

    virtual ~vmm_loader() noexcept = default;
protected:
    vmm_loader() noexcept = default;
    vmm_loader(vmm_loader &&) noexcept = default;
    vmm_loader &operator=(vmm_loader &&) noexcept = default;
    vmm_loader(vmm_loader const &) = delete;
    vmm_loader &operator=(vmm_loader const &) & = delete;
};

}

#endif
