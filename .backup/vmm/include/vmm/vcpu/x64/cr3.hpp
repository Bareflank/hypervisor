#ifndef VMM_VCPU_X64_CR3_HPP
#define VMM_VCPU_X64_CR3_HPP

#include <vmm/vcpu/x64/x64_vcpu_delegate.hpp>

namespace vmm
{

class cr3
{
public:

    /// @brief Enable vmexits for all reads to control register cr3
    virtual void enable_cr3_read_vmexit() noexcept = 0;

    /// @brief Disable vmexits for all reads to control register cr3
    virtual void disable_cr3_read_vmexit() noexcept = 0;

    /// @brief Set a vmexit handler that will be called for all vmexits caused
    ///     by a read to control register cr3 while a vcpu is executing.
    ///
    /// @param func The delegate function to be called
    virtual void set_cr3_read_vmexit_handler(x64_vcpu_delegate func) noexcept = 0;

    /// @brief Execute (on the vcpu) a read from cr3 that caused a vmexit
    ///     to occur, using the vcpu's registers as the source and destination
    ///     registers for the operation. This allows a user defined vm exit
    ///     handler to pass through a read from a vcpu's cr3.
    virtual void execute_cr3_read() noexcept = 0;

    /// @brief Emulate a read from cr3 that caused a vmexit to occur while a
    ///     vcpu was executing. The given value is read into the vcpu's
    ///     destination register, instead of the vcpu's cr3. 
    ///
    /// @param cr3_value The value to be returned to a vcpu as a read from cr3
    virtual void emulate_cr3_read(uint64_t cr3_value) noexcept = 0;

    /// @brief Enable vmexits for all writes to control register cr3
    virtual void enable_cr3_write_vmexit() noexcept = 0;

    /// @brief Disable vmexits for all writes to control register cr3
    virtual void disable_cr3_write_vmexit() noexcept = 0;

    /// @brief Set a vmexit handler that will be called for all vmexits caused
    ///     by a write to control register cr3 while a vcpu is executing.
    ///
    /// @param func The delegate function to be called
    virtual void set_cr3_write_vmexit_handler(x64_vcpu_delegate func) noexcept = 0;

    /// @brief Returns the value being written to control register cr3 that
    ///     caused a vmexit to occur while a vcpu was executing
    ///
    /// @return The value written to cr3 that caused a vmexit
    virtual uint64_t get_cr3_write_vmexit_value() noexcept = 0;

    /// @brief Execute (on the vcpu) a write to cr3 that caused a vmexit
    ///     to occur, using the vcpu's registers as the source and destination
    ///     registers for the operation. This allows a user defined vm exit
    ///     handler to pass through a write to a vcpu's cr3.
    virtual void execute_cr3_write() noexcept = 0;

    /// @brief Emulate a write to cr3 that caused a vmexit to occur while a
    ///     vcpu was executing. The given value is written into the vcpu's
    ///     cr3, instead of the value that caused the vm exit to occur. 
    ///
    /// @param cr3_value The value to be written to a vcpu's cr3
    virtual void emulate_cr3_write(uint64_t cr3_value) noexcept = 0;

    virtual ~cr3() noexcept = default;
protected:
    cr3() noexcept = default;
    cr3(cr3 &&) noexcept = default;
    cr3 &operator=(cr3 &&) noexcept = default;
    cr3(cr3 const &) = delete;
    cr3 &operator=(cr3 const &) & = delete;
};

}

#endif
