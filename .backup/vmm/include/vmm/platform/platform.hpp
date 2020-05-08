#ifndef VMM_PLATFORM_HPP
#define VMM_PLATFORM_HPP

#include <vmm/platform/acpi.hpp>
#include <vmm/platform/loader.hpp>

namespace vmm
{

class platform :
    public acpi,
    public loader
{
public:
    ~platform() noexcept override = default;
protected:
    platform() noexcept = default;
    platform(platform &&) noexcept = default;
    platform &operator=(platform &&) noexcept = default;
    platform(platform const &) = delete;
    platform &operator=(platform const &) & = delete;
};

}

#endif
