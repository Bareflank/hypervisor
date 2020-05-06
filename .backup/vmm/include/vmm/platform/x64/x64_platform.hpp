#ifndef VMM_X64_PLATFORM_HPP
#define VMM_X64_PLATFORM_HPP

#include <vmm/platform/platform.hpp>
#include <vmm/platform/x64/memory.hpp>

namespace vmm
{

class x64_platform :
    public platform,
    public memory
{
public:
    ~x64_platform() noexcept override = default;
protected:
    x64_platform() noexcept = default;
    x64_platform(x64_platform &&) noexcept = default;
    x64_platform &operator=(x64_platform &&) noexcept = default;
    x64_platform(x64_platform const &) = delete;
    x64_platform &operator=(x64_platform const &) & = delete;
};

}

#endif
