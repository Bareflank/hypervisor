#ifndef VMM_VCPU_X64_GENERAL_REGISTER_X64_HPP
#define VMM_VCPU_X64_GENERAL_REGISTER_X64_HPP

namespace vmm
{

class general_register_x64
{
public:

    /// @brief Return the value of register rax
    ///
    /// @return The value of register rax
    virtual uint64_t rax_get() noexcept = 0;

    /// @brief Set the value of register rax
    ///
    /// @param value The value to set register rax to
    virtual void rax_set(uint64_t value) noexcept = 0;

    /// @brief Return the value of register rbx
    ///
    /// @return The value of register rbx
    virtual uint64_t rbx_get() noexcept = 0;

    /// @brief Set the value of register rbx
    ///
    /// @param value The value to set register rbx to
    virtual void rbx_set(uint64_t value) noexcept = 0;

    /// @brief Return the value of register rcx
    ///
    /// @return The value of register rcx
    virtual uint64_t rcx_get() noexcept = 0;

    /// @brief Set the value of register rcx
    ///
    /// @param value The value to set register rcx to
    virtual void rcx_set(uint64_t value) noexcept = 0;

    /// @brief Return the value of register rdx
    ///
    /// @return The value of register rdx
    virtual uint64_t rdx_get() noexcept = 0;

    /// @brief Set the value of register rdx
    ///
    /// @param value The value to set register rdx to
    virtual void rdx_set(uint64_t value) noexcept = 0;

    /// @brief Return the value of register rbp
    ///
    /// @return The value of register rbp
    virtual uint64_t rbp_get() noexcept = 0;

    /// @brief Set the value of register rbp
    ///
    /// @param value The value to set register rbp to
    virtual void rbp_set(uint64_t value) noexcept = 0;

    /// @brief Return the value of register rsi
    ///
    /// @return The value of register rsi
    virtual uint64_t rsi_get() noexcept = 0;

    /// @brief Set the value of register rsi
    ///
    /// @param value The value to set register rsi to
    virtual void rsi_set(uint64_t value) noexcept = 0;

    /// @brief Return the value of register rdi
    ///
    /// @return The value of register rdi
    virtual uint64_t rdi_get() noexcept = 0;

    /// @brief Set the value of register rdi
    ///
    /// @param value The value to set register rdi to
    virtual void rdi_set(uint64_t value) noexcept = 0;

    /// @brief Return the value of register r8
    ///
    /// @return The value of register r8
    virtual uint64_t r8_get() noexcept = 0;

    /// @brief Set the value of register r8
    ///
    /// @param value The value to set register r8 to
    virtual void r8_set(uint64_t value) noexcept = 0;

    /// @brief Return the value of register r9
    ///
    /// @return The value of register r9
    virtual uint64_t r9_get() noexcept = 0;

    /// @brief Set the value of register r9
    ///
    /// @param value The value to set register r9 to
    virtual void r9_set(uint64_t value) noexcept = 0;

    /// @brief Return the value of register r10
    ///
    /// @return The value of register r10
    virtual uint64_t r10_get() noexcept = 0;

    /// @brief Set the value of register r10
    ///
    /// @param value The value to set register r10 to
    virtual void r10_set(uint64_t value) noexcept = 0;

    /// @brief Return the value of register r11
    ///
    /// @return The value of register r11
    virtual uint64_t r11_get() noexcept = 0;

    /// @brief Set the value of register r11
    ///
    /// @param value The value to set register r11 to
    virtual void r11_set(uint64_t value) noexcept = 0;

    /// @brief Return the value of register r12
    ///
    /// @return The value of register r12
    virtual uint64_t r12_get() noexcept = 0;

    /// @brief Set the value of register r12
    ///
    /// @param value The value to set register r12 to
    virtual void r12_set(uint64_t value) noexcept = 0;

    /// @brief Return the value of register r13
    ///
    /// @return The value of register r13
    virtual uint64_t r13_get() noexcept = 0;

    /// @brief Set the value of register r13
    ///
    /// @param value The value to set register r13 to
    virtual void r13_set(uint64_t value) noexcept = 0;

    /// @brief Return the value of register r14
    ///
    /// @return The value of register r14
    virtual uint64_t r14_get() noexcept = 0;

    /// @brief Set the value of register r14
    ///
    /// @param value The value to set register r14 to
    virtual void r14_set(uint64_t value) noexcept = 0;

    /// @brief Return the value of register r15
    ///
    /// @return The value of register r15
    virtual uint64_t r15_get() noexcept = 0;

    /// @brief Set the value of register r15
    ///
    /// @param value The value to set register r15 to
    virtual void r15_set(uint64_t value) noexcept = 0;

    /// @brief Return the value of register rip
    ///
    /// @return The value of register rip
    virtual uint64_t rip_get() noexcept = 0;

    /// @brief Set the value of register rip
    ///
    /// @param value The value to set register rip to
    virtual void rip_set(uint64_t value) noexcept = 0;

    /// @brief Return the value of register rsp
    ///
    /// @return The value of register rsp
    virtual uint64_t rsp_get() noexcept = 0;

    /// @brief Set the value of register rsp
    ///
    /// @param value The value to set register rsp to
    virtual void rsp_set(uint64_t value) noexcept = 0;

    virtual ~general_register_x64() noexcept = default;
protected:
    general_register_x64() noexcept = default;
    general_register_x64(general_register_x64 &&) noexcept = default;
    general_register_x64 &operator=(general_register_x64 &&) noexcept = default;
    general_register_x64(general_register_x64 const &) = delete;
    general_register_x64 &operator=(general_register_x64 const &) & = delete;
};

}

#endif
