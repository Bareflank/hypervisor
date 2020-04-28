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
    virtual uint64_t get_rax() noexcept = 0;

    /// @brief Set the value of register rax
    ///
    /// @param value The value to set register rax to
    virtual void set_rax(uint64_t value) noexcept = 0;

    /// @brief Return the value of register rbx
    ///
    /// @return The value of register rbx
    virtual uint64_t get_rbx() noexcept = 0;

    /// @brief Set the value of register rbx
    ///
    /// @param value The value to set register rbx to
    virtual void set_rbx(uint64_t value) noexcept = 0;

    /// @brief Return the value of register rcx
    ///
    /// @return The value of register rcx
    virtual uint64_t get_rcx() noexcept = 0;

    /// @brief Set the value of register rcx
    ///
    /// @param value The value to set register rcx to
    virtual void set_rcx(uint64_t value) noexcept = 0;

    /// @brief Return the value of register rdx
    ///
    /// @return The value of register rdx
    virtual uint64_t get_rdx() noexcept = 0;

    /// @brief Set the value of register rdx
    ///
    /// @param value The value to set register rdx to
    virtual void set_rdx(uint64_t value) noexcept = 0;

    /// @brief Return the value of register rbp
    ///
    /// @return The value of register rbp
    virtual uint64_t get_rbp() noexcept = 0;

    /// @brief Set the value of register rbp
    ///
    /// @param value The value to set register rbp to
    virtual void set_rbp(uint64_t value) noexcept = 0;

    /// @brief Return the value of register rsi
    ///
    /// @return The value of register rsi
    virtual uint64_t get_rsi() noexcept = 0;

    /// @brief Set the value of register rsi
    ///
    /// @param value The value to set register rsi to
    virtual void set_rsi(uint64_t value) noexcept = 0;

    /// @brief Return the value of register rdi
    ///
    /// @return The value of register rdi
    virtual uint64_t get_rdi() noexcept = 0;

    /// @brief Set the value of register rdi
    ///
    /// @param value The value to set register rdi to
    virtual void set_rdi(uint64_t value) noexcept = 0;

    /// @brief Return the value of register r8
    ///
    /// @return The value of register r8
    virtual uint64_t get_r8() noexcept = 0;

    /// @brief Set the value of register r8
    ///
    /// @param value The value to set register r8 to
    virtual void set_r8(uint64_t value) noexcept = 0;

    /// @brief Return the value of register r9
    ///
    /// @return The value of register r9
    virtual uint64_t get_r9() noexcept = 0;

    /// @brief Set the value of register r9
    ///
    /// @param value The value to set register r9 to
    virtual void set_r9(uint64_t value) noexcept = 0;

    /// @brief Return the value of register r10
    ///
    /// @return The value of register r10
    virtual uint64_t get_r10() noexcept = 0;

    /// @brief Set the value of register r10
    ///
    /// @param value The value to set register r10 to
    virtual void set_r10(uint64_t value) noexcept = 0;

    /// @brief Return the value of register r11
    ///
    /// @return The value of register r11
    virtual uint64_t get_r11() noexcept = 0;

    /// @brief Set the value of register r11
    ///
    /// @param value The value to set register r11 to
    virtual void set_r11(uint64_t value) noexcept = 0;

    /// @brief Return the value of register r12
    ///
    /// @return The value of register r12
    virtual uint64_t get_r12() noexcept = 0;

    /// @brief Set the value of register r12
    ///
    /// @param value The value to set register r12 to
    virtual void set_r12(uint64_t value) noexcept = 0;

    /// @brief Return the value of register r13
    ///
    /// @return The value of register r13
    virtual uint64_t get_r13() noexcept = 0;

    /// @brief Set the value of register r13
    ///
    /// @param value The value to set register r13 to
    virtual void set_r13(uint64_t value) noexcept = 0;

    /// @brief Return the value of register r14
    ///
    /// @return The value of register r14
    virtual uint64_t get_r14() noexcept = 0;

    /// @brief Set the value of register r14
    ///
    /// @param value The value to set register r14 to
    virtual void set_r14(uint64_t value) noexcept = 0;

    /// @brief Return the value of register r15
    ///
    /// @return The value of register r15
    virtual uint64_t get_r15() noexcept = 0;

    /// @brief Set the value of register r15
    ///
    /// @param value The value to set register r15 to
    virtual void set_r15(uint64_t value) noexcept = 0;

    /// @brief Return the value of register rip
    ///
    /// @return The value of register rip
    virtual uint64_t get_rip() noexcept = 0;

    /// @brief Set the value of register rip
    ///
    /// @param value The value to set register rip to
    virtual void set_rip(uint64_t value) noexcept = 0;

    /// @brief Return the value of register rsp
    ///
    /// @return The value of register rsp
    virtual uint64_t get_rsp() noexcept = 0;

    /// @brief Set the value of register rsp
    ///
    /// @param value The value to set register rsp to
    virtual void set_rsp(uint64_t value) noexcept = 0;

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
