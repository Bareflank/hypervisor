#ifndef VMM_VCPU_X64_SIPI_SIGNAL_HPP
#define VMM_VCPU_X64_SIPI_SIGNAL_HPP

#include <bsl/delegate.hpp>

namespace vmm
{

class sipi_signal
{
public:

    /// @brief Set a vmexit handler that will be called for all vmexits caused
    ///     by a sipi signal while a vcpu is executing.
    ///
    /// @param func The delegate function to be called
    virtual void sipi_signal_vmexit_handler_set(bsl::delegate<void (x64_vcpu &)> func) noexcept = 0;

    virtual ~sipi_signal() noexcept = default;
protected:
    sipi_signal() noexcept = default;
    sipi_signal(sipi_signal &&) noexcept = default;
    sipi_signal &operator=(sipi_signal &&) noexcept = default;
    sipi_signal(sipi_signal const &) = delete;
    sipi_signal &operator=(sipi_signal const &) & = delete;
};

}

#endif
