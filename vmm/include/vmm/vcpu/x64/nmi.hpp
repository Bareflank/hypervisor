#ifndef VMM_VCPU_X64_NMI_HPP
#define VMM_VCPU_X64_NMI_HPP

#include <bsl/errc_type.hpp>

namespace vmm
{

class nmi
{
public:

    /// @brief Enable vmexits for all non-maskable interrupts that arrive
    ///     during execution of a vcpu
    virtual void nmi_vmexit_enable() noexcept = 0;

    /// @brief Disable vmexits for all non-maskable interrupts that arrive
    ///     during execution of a vcpu
    virtual void nmi_vmexit_disable() noexcept = 0;

    /// @brief Set a vmexit handler that will be called for all vmexits caused
    ///     by arrival of a non-maskable interrupt while a vcpu is executing.
    ///
    /// @param func The delegate function to be called
    virtual void nmi_vmexit_handler_set(bsl::delegate<void (x64_vcpu &)> func) noexcept = 0;

    /// @brief Inject a non-maskable interrupt into a vcpu
    virtual void nmi_inject() noexcept = 0;

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

