#ifndef VMM_VCPU_X64_NMI_HPP
#define VMM_VCPU_X64_NMI_HPP

#include <vmm/vcpu/x64/x64_vcpu_delegate.hpp>

namespace vmm
{

class nmi
{
public:

    /// @brief Enable vmexits for all non-maskable interrupts that arrive
    ///     during execution of a vcpu
    virtual void enable_nmi_vmexit() noexcept = 0;

    /// @brief Disable vmexits for all non-maskable interrupts that arrive
    ///     during execution of a vcpu
    virtual void disable_nmi_vmexit() noexcept = 0;

    /// @brief Set a vmexit handler that will be called for all vmexits caused
    ///     by arrival of a non-maskable interrupt while a vcpu is executing.
    ///
    /// @param func The delegate function to be called
    virtual void set_nmi_vmexit_handler(x64_vcpu_delegate func) noexcept = 0;

    /// @brief Inject a non-maskable interrupt into a vcpu
    virtual void inject_nmi() noexcept = 0;

    virtual ~nmi() noexcept = default;
protected:
    nmi() noexcept = default;
    nmi(nmi &&) noexcept = default;
    nmi &operator=(nmi &&) noexcept = default;
    nmi(nmi const &) = delete;
    nmi &operator=(nmi const &) & = delete;
};

}

#endif

