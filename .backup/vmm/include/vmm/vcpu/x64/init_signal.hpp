#ifndef VMM_VCPU_X64_INIT_SIGNAL_HPP
#define VMM_VCPU_X64_INIT_SIGNAL_HPP

#include <vmm/vcpu/x64/x64_vcpu_delegate.hpp>

namespace vmm
{

class init_signal
{
public:

    /// @brief Set a vmexit handler that will be called for all vmexits caused
    ///     by an init signal while a vcpu is executing.
    ///
    /// @param func The delegate function to be called
    virtual void set_init_signal_vmexit_handler(x64_vcpu_delegate func) noexcept = 0;

    virtual ~init_signal() noexcept = default;
protected:
    init_signal() noexcept = default;
    init_signal(init_signal &&) noexcept = default;
    init_signal &operator=(init_signal &&) noexcept = default;
    init_signal(init_signal const &) = delete;
    init_signal &operator=(init_signal const &) & = delete;
};

}

#endif
