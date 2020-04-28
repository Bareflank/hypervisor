#ifndef VMM_VCPU_X64_WRMSR_HPP
#define VMM_VCPU_X64_WRMSR_HPP

#include <bsl/errc_type.hpp>

namespace vmm
{

class wrmsr
{
public:

    /// @brief Enable vmexits for a model specific register accesses via the
    ///     wrmsr instruction at the specified msr address during vcpu execution. 
    ///
    /// @param msr_address The msr address to enable wrmsr vmexits for
    virtual void enable_wrmsr_vmexit(uint32_t msr_address) noexcept = 0;

    /// @brief Enable vmexits for a range of model specific register accesses
    ///     via the wrmsr instruction with msr addresses in the range
    ///     @param begin to @param end (inclusive) during vcpu execution. 
    ///
    /// @expects begin <= end
    ///
    /// @param begin The lower bound of msr addresses to enable vmexits for
    /// @param end The upper bound of msr addresses to enable wrmsr vmexits for
    virtual void enable_wrmsr_vmexit_range(uint32_t begin, uint32_t end) noexcept = 0;

    /// @brief Disable vmexits for a model specific register accesses via the
    ///     wrmsr instruction at the specified msr address during vcpu execution. 
    ///
    /// @param msr_address The msr address to disable wrmsr vmexits for
    virtual void disable_wrmsr_vmexit(uint32_t msr_address) noexcept = 0;

    /// @brief Disable vmexits for a range of model specific register accesses
    ///     via the wrmsr instruction with msr addresses in the range
    ///     @param begin to @param end (inclusive) during vcpu execution. 
    ///
    /// @expects begin <= end
    ///
    /// @param begin The lower bound of msr addresses to disable vmexits for
    /// @param end The upper bound of msr addresses to disable wrmsr vmexits for
    virtual void disable_wrmsr_vmexit_range(uint32_t begin, uint32_t end) noexcept = 0;

    /// @brief Set a vmexit handler that will be called for all vmexits caused
    ///     by a wrmsr instruction while a vcpu is executing.
    ///
    /// @param func The delegate function to be called
    virtual void set_wrmsr_vmexit_handler(x64_vcpu_delegate func) noexcept = 0;

    /// @brief Returns the msr address of a wrmsr instruction that caused a
    ///     vmexit to occur while a vcpu was executing
    ///
    /// @return The msr address used in a wrmsr instruction that caused a
    ///     vmexit to occur
    virtual uint32_t get_wrmsr_vmexit_address() noexcept = 0;

    /// @brief Returns the value of a wrmsr instruction that caused a
    ///     vmexit to occur while a vcpu was executing
    ///
    /// @return The value used in a wrmsr instruction that caused a
    ///     vmexit to occur
    virtual uint64_t get_wrmsr_vmexit_value() noexcept = 0;

    /// @brief Execute (on the vcpu) a wrmsr instruction that caused a vmexit
    ///     to occur, using the vcpu's registers as the source registers for
    ///     the operation. This allows a user defined vm exit handler to pass
    ///     through a wrmsr instruction from a vcpu.
    virtual void execute_wrmsr() noexcept = 0;

    /// @brief Emulate a wrmsr instruction that caused a vmexit to occur
    ///     while a vcpu was executing. The given value is written to the
    ///     msr (at the vmexit wrmsr address) instead of the value
    ///     that caused the vmexit to occur. 
    ///
    /// @param value The value to be written to the msr
    virtual void emulate_wrmsr(uint64_t value) noexcept = 0;

    virtual ~wrmsr() noexcept = default;
protected:
    wrmsr() noexcept = default;
    wrmsr(wrmsr &&) noexcept = default;
    wrmsr &operator=(wrmsr &&) noexcept = default;
    wrmsr(wrmsr const &) = delete;
    wrmsr &operator=(wrmsr const &) & = delete;
};

}

#endif
