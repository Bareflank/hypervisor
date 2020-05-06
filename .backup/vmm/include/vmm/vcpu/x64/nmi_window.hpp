#ifndef VMM_VCPU_X64_NMI_WINDOW_HPP
#define VMM_VCPU_X64_NMI_WINDOW_HPP

#include <vmm/vcpu/x64/x64_vcpu_delegate.hpp>

namespace vmm
{

class nmi_window
{
public:

    /// @brief Enable vmexits for nmi windows that occur during
    ///     execution of a vcpu
    virtual void enable_nmi_window_vmexit() noexcept = 0;

    /// @brief Disable vmexits for nmi windows that occur during
    ///     execution of a vcpu
    virtual void disable_nmi_window_vmexit() noexcept = 0;

    /// @brief Set a vmexit handler that will be called for all vmexits caused
    ///     by an nmi window while a vcpu is executing.
    ///
    /// @param func The delegate function to be called
    virtual void set_nmi_window_vmexit_handler(x64_vcpu_delegate func) noexcept = 0;

    virtual ~nmi_window() noexcept = default;
protected:
    nmi_window() noexcept = default;
    nmi_window(nmi_window &&) noexcept = default;
    nmi_window &operator=(nmi_window &&) noexcept = default;
    nmi_window(nmi_window const &) = delete;
    nmi_window &operator=(nmi_window const &) & = delete;
};

}

#endif

