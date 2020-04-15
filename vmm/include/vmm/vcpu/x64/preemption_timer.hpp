#ifndef VMM_VCPU_X64_PREEMPTION_TIMER_HPP
#define VMM_VCPU_X64_PREEMPTION_TIMER_HPP

#include <bsl/errc_type.hpp>

namespace vmm
{

class preemption_timer
{
public:

    /// @brief Enable vmexits from a preemption timer
    virtual void preemption_timer_vmexit_enable() noexcept = 0;

    /// @brief Disables vmexits from a preemption timer
    virtual void preemption_timer_vmexit_disable() noexcept = 0;

    /// @brief Set a vmexit handler that will be called for all vmexits caused
    ///     by the preemption timer while a vcpu is executing.
    ///
    /// @param func The delegate function to be called
    virtual void preemption_timer_vmexit_handler_set(bsl::delegate<void (x64_vcpu &)> func) noexcept = 0;

    /// @brief Set the preemption timer to the specified value
    ///
    /// @param value The value set the preemption timer to
    virtual void preemption_timer_set(uint64_t value) noexcept = 0;

    virtual ~preemption_timer() noexcept = default;
protected:
    preemption_timer() noexcept = default;
    preemption_timer(preemption_timer &&) noexcept = default;
    preemption_timer &operator=(preemption_timer &&) noexcept = default;
    preemption_timer(preemption_timer const &) = delete;
    preemption_timer &operator=(preemption_timer const &) & = delete;
};

}

#endif
