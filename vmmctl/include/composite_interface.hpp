#ifndef VMMCTRL_COMPOSITE_INTERFACE_HPP
#define VMMCTRL_COMPOSITE_INTERFACE_HPP

#include <vmm_info.hpp>
#include <vmm_loader.hpp>

namespace vmmctl
{

class composite_interface :
    public vmm_info,
    public vmm_loader
{
public:

    // Do not define parts of public interface here.
    // Rather, inherit many pure virtual interfaces to create a composite one!

    ~composite_interface() noexcept override = default;
protected:
    composite_interface() noexcept = default;
    composite_interface(composite_interface &&) noexcept = default;
    composite_interface &operator=(composite_interface &&) noexcept = default;
    composite_interface(composite_interface const &) = delete;
    composite_interface &operator=(composite_interface const &) & = delete;
};

}

#endif
