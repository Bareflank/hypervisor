/// @copyright
/// Copyright (C) 2020 Assured Information Security, Inc.
///
/// @copyright
/// Permission is hereby granted, free of charge, to any person obtaining a copy
/// of this software and associated documentation files (the "Software"), to deal
/// in the Software without restriction, including without limitation the rights
/// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
/// copies of the Software, and to permit persons to whom the Software is
/// furnished to do so, subject to the following conditions:
///
/// @copyright
/// The above copyright notice and this permission notice shall be included in
/// all copies or substantial portions of the Software.
///
/// @copyright
/// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
/// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
/// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
/// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
/// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
/// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
/// SOFTWARE.

#ifndef MK_INTERFACE_H
#define MK_INTERFACE_H

#include <bsl/char_type.hpp>
#include <bsl/convert.hpp>
#include <bsl/cstdint.hpp>
#include <bsl/cstr_type.hpp>
#include <bsl/discard.hpp>
#include <bsl/safe_integral.hpp>

namespace syscall
{
    // -------------------------------------------------------------------------
    // Scalar Types
    // -------------------------------------------------------------------------

    /// @brief Defines the type used for returning status from a function
    using bf_status_t = bsl::safe_uint64;
    /// @brief Defines an unsigned 8bit integer
    using bf_uint8_t = bsl::uint8;
    /// @brief Defines an unsigned 16bit integer
    using bf_uint16_t = bsl::uint16;
    /// @brief Defines an unsigned 32bit integer
    using bf_uint32_t = bsl::uint32;
    /// @brief Defines an unsigned 64bit integer
    using bf_uint64_t = bsl::uint64;
    /// @brief Defines a raw pointer type
    using bf_ptr_t = void const *;

    // -------------------------------------------------------------------------
    // Handle Type
    // -------------------------------------------------------------------------

    /// @class syscall::bf_handle_t
    ///
    /// <!-- description -->
    ///   @brief The bf_handle_t structure is an opaque structure containing
    ///     the handle that is used by most of the syscalls in this
    ///     specification. The opaque structure is used internally by the C
    ///     wrapper interface for storing state as needed and should not be
    ///     accessed directly. The C wrapper is allowed to redefine the
    ///     internal layout of this structure at any time (e.g., the C wrapper
    ///     might provide an alternative layout for unit testing).
    ///
    // IWYU is more important here, and this rule would make this interface
    // needlessly overcomplicated.
    // NOLINTNEXTLINE(bsl-user-defined-type-names-match-header-name)
    struct bf_handle_t final
    {
        /// @brief The handle returned by bf_handle_op_open_handle
        bf_uint64_t hndl;
    };

    // -------------------------------------------------------------------------
    // Register Type
    // -------------------------------------------------------------------------

    /// @brief Defines which register is being requested by certain syscalls
    // IWYU is more important here, and this rule would make this interface
    // needlessly overcomplicated.
    // NOLINTNEXTLINE(bsl-user-defined-type-names-match-header-name)
    enum class bf_reg_t : bsl::uint64
    {
        /// @brief defines the rax register
        bf_reg_t_rax = static_cast<bsl::uint64>(0),
        /// @brief defines the rbx register
        bf_reg_t_rbx = static_cast<bsl::uint64>(1),
        /// @brief defines the rcx register
        bf_reg_t_rcx = static_cast<bsl::uint64>(2),
        /// @brief defines the rdx register
        bf_reg_t_rdx = static_cast<bsl::uint64>(3),
        /// @brief defines the rbp register
        bf_reg_t_rbp = static_cast<bsl::uint64>(4),
        /// @brief defines the rsi register
        bf_reg_t_rsi = static_cast<bsl::uint64>(5),
        /// @brief defines the rdi register
        bf_reg_t_rdi = static_cast<bsl::uint64>(6),
        /// @brief defines the r8 register
        bf_reg_t_r8 = static_cast<bsl::uint64>(7),
        /// @brief defines the r9 register
        bf_reg_t_r9 = static_cast<bsl::uint64>(8),
        /// @brief defines the r10 register
        bf_reg_t_r10 = static_cast<bsl::uint64>(9),
        /// @brief defines the r11 register
        bf_reg_t_r11 = static_cast<bsl::uint64>(10),
        /// @brief defines the r12 register
        bf_reg_t_r12 = static_cast<bsl::uint64>(11),
        /// @brief defines the r13 register
        bf_reg_t_r13 = static_cast<bsl::uint64>(12),
        /// @brief defines the r14 register
        bf_reg_t_r14 = static_cast<bsl::uint64>(13),
        /// @brief defines the r15 register
        bf_reg_t_r15 = static_cast<bsl::uint64>(14),
        /// @brief defines the rip register
        bf_reg_t_rip = static_cast<bsl::uint64>(15),
        /// @brief defines the rsp register
        bf_reg_t_rsp = static_cast<bsl::uint64>(16),
        /// @brief defines the rflags register
        bf_reg_t_rflags = static_cast<bsl::uint64>(17),
        /// @brief defines the gdtr_base_addr register
        bf_reg_t_gdtr_base_addr = static_cast<bsl::uint64>(18),
        /// @brief defines the gdtr_limit register
        bf_reg_t_gdtr_limit = static_cast<bsl::uint64>(19),
        /// @brief defines the idtr_base_addr register
        bf_reg_t_idtr_base_addr = static_cast<bsl::uint64>(20),
        /// @brief defines the idtr_limit register
        bf_reg_t_idtr_limit = static_cast<bsl::uint64>(21),
        /// @brief defines the es register
        bf_reg_t_es = static_cast<bsl::uint64>(22),
        /// @brief defines the es_base_addr register
        bf_reg_t_es_base_addr = static_cast<bsl::uint64>(23),
        /// @brief defines the es_limit register
        bf_reg_t_es_limit = static_cast<bsl::uint64>(24),
        /// @brief defines the es_attributes register
        bf_reg_t_es_attributes = static_cast<bsl::uint64>(25),
        /// @brief defines the cs register
        bf_reg_t_cs = static_cast<bsl::uint64>(26),
        /// @brief defines the cs_base_addr register
        bf_reg_t_cs_base_addr = static_cast<bsl::uint64>(27),
        /// @brief defines the cs_limit register
        bf_reg_t_cs_limit = static_cast<bsl::uint64>(28),
        /// @brief defines the cs_attributes register
        bf_reg_t_cs_attributes = static_cast<bsl::uint64>(29),
        /// @brief defines the ss register
        bf_reg_t_ss = static_cast<bsl::uint64>(30),
        /// @brief defines the ss_base_addr register
        bf_reg_t_ss_base_addr = static_cast<bsl::uint64>(31),
        /// @brief defines the ss_limit register
        bf_reg_t_ss_limit = static_cast<bsl::uint64>(32),
        /// @brief defines the ss_attributes register
        bf_reg_t_ss_attributes = static_cast<bsl::uint64>(33),
        /// @brief defines the ds register
        bf_reg_t_ds = static_cast<bsl::uint64>(34),
        /// @brief defines the ds_base_addr register
        bf_reg_t_ds_base_addr = static_cast<bsl::uint64>(35),
        /// @brief defines the ds_limit register
        bf_reg_t_ds_limit = static_cast<bsl::uint64>(36),
        /// @brief defines the ds_attributes register
        bf_reg_t_ds_attributes = static_cast<bsl::uint64>(37),
        /// @brief defines the fs register
        bf_reg_t_fs = static_cast<bsl::uint64>(38),
        /// @brief defines the fs_base_addr register
        bf_reg_t_fs_base_addr = static_cast<bsl::uint64>(39),
        /// @brief defines the fs_limit register
        bf_reg_t_fs_limit = static_cast<bsl::uint64>(40),
        /// @brief defines the fs_attributes register
        bf_reg_t_fs_attributes = static_cast<bsl::uint64>(41),
        /// @brief defines the gs register
        bf_reg_t_gs = static_cast<bsl::uint64>(42),
        /// @brief defines the gs_base_addr register
        bf_reg_t_gs_base_addr = static_cast<bsl::uint64>(43),
        /// @brief defines the gs_limit register
        bf_reg_t_gs_limit = static_cast<bsl::uint64>(44),
        /// @brief defines the gs_attributes register
        bf_reg_t_gs_attributes = static_cast<bsl::uint64>(45),
        /// @brief defines the ldtr register
        bf_reg_t_ldtr = static_cast<bsl::uint64>(46),
        /// @brief defines the ldtr_base_addr register
        // We don't have a choice in the naming here
        // NOLINTNEXTLINE(bsl-identifier-typographically-unambiguous)
        bf_reg_t_ldtr_base_addr = static_cast<bsl::uint64>(47),
        /// @brief defines the ldtr_limit register
        // We don't have a choice in the naming here
        // NOLINTNEXTLINE(bsl-identifier-typographically-unambiguous)
        bf_reg_t_ldtr_limit = static_cast<bsl::uint64>(48),
        /// @brief defines the ldtr_attributes register
        bf_reg_t_ldtr_attributes = static_cast<bsl::uint64>(49),
        /// @brief defines the tr register
        bf_reg_t_tr = static_cast<bsl::uint64>(50),
        /// @brief defines the tr_base_addr register
        bf_reg_t_tr_base_addr = static_cast<bsl::uint64>(51),
        /// @brief defines the tr_limit register
        bf_reg_t_tr_limit = static_cast<bsl::uint64>(52),
        /// @brief defines the tr_attributes register
        bf_reg_t_tr_attributes = static_cast<bsl::uint64>(53),
        /// @brief defines the cr0 register
        bf_reg_t_cr0 = static_cast<bsl::uint64>(54),
        /// @brief defines the cr2 register
        bf_reg_t_cr2 = static_cast<bsl::uint64>(55),
        /// @brief defines the cr3 register
        bf_reg_t_cr3 = static_cast<bsl::uint64>(56),
        /// @brief defines the cr4 register
        bf_reg_t_cr4 = static_cast<bsl::uint64>(57),
        /// @brief defines the dr6 register
        bf_reg_t_dr6 = static_cast<bsl::uint64>(58),
        /// @brief defines the dr7 register
        bf_reg_t_dr7 = static_cast<bsl::uint64>(59),
        /// @brief defines the ia32_efer register
        bf_reg_t_ia32_efer = static_cast<bsl::uint64>(60),
        /// @brief defines the ia32_star register
        bf_reg_t_ia32_star = static_cast<bsl::uint64>(61),
        /// @brief defines the ia32_lstar register
        bf_reg_t_ia32_lstar = static_cast<bsl::uint64>(62),
        /// @brief defines the ia32_cstar register
        bf_reg_t_ia32_cstar = static_cast<bsl::uint64>(63),
        /// @brief defines the ia32_fmask register
        bf_reg_t_ia32_fmask = static_cast<bsl::uint64>(64),
        /// @brief defines the ia32_fs_base register
        bf_reg_t_ia32_fs_base = static_cast<bsl::uint64>(65),
        /// @brief defines the ia32_gs_base register
        bf_reg_t_ia32_gs_base = static_cast<bsl::uint64>(66),
        /// @brief defines the ia32_kernel_gs_base register
        bf_reg_t_ia32_kernel_gs_base = static_cast<bsl::uint64>(67),
        /// @brief defines the ia32_sysenter_cs register
        bf_reg_t_ia32_sysenter_cs = static_cast<bsl::uint64>(68),
        /// @brief defines the ia32_sysenter_esp register
        bf_reg_t_ia32_sysenter_esp = static_cast<bsl::uint64>(69),
        /// @brief defines the ia32_sysenter_eip register
        bf_reg_t_ia32_sysenter_eip = static_cast<bsl::uint64>(70),
        /// @brief defines the ia32_pat register
        bf_reg_t_ia32_pat = static_cast<bsl::uint64>(71),
        /// @brief defines the ia32_debugctl register
        bf_reg_t_ia32_debugctl = static_cast<bsl::uint64>(72),
    };

    // -------------------------------------------------------------------------
    // TLS Page Offsets
    // -------------------------------------------------------------------------

    /// @brief stores the offset in the TLS block for rax
    constexpr bsl::safe_uintmax TLS_OFFSET_RAX{bsl::to_umax(0x800U)};
    /// @brief stores the offset in the TLS block for rbx
    constexpr bsl::safe_uintmax TLS_OFFSET_RBX{bsl::to_umax(0x808U)};
    /// @brief stores the offset in the TLS block for rcx
    constexpr bsl::safe_uintmax TLS_OFFSET_RCX{bsl::to_umax(0x810U)};
    /// @brief stores the offset in the TLS block for rdx
    constexpr bsl::safe_uintmax TLS_OFFSET_RDX{bsl::to_umax(0x818U)};
    /// @brief stores the offset in the TLS block for rbp
    constexpr bsl::safe_uintmax TLS_OFFSET_RBP{bsl::to_umax(0x820U)};
    /// @brief stores the offset in the TLS block for rsi
    constexpr bsl::safe_uintmax TLS_OFFSET_RSI{bsl::to_umax(0x828U)};
    /// @brief stores the offset in the TLS block for rdi
    constexpr bsl::safe_uintmax TLS_OFFSET_RDI{bsl::to_umax(0x830U)};
    /// @brief stores the offset in the TLS block for r8
    constexpr bsl::safe_uintmax TLS_OFFSET_R8{bsl::to_umax(0x838U)};
    /// @brief stores the offset in the TLS block for r9
    constexpr bsl::safe_uintmax TLS_OFFSET_R9{bsl::to_umax(0x840U)};
    /// @brief stores the offset in the TLS block for r10
    constexpr bsl::safe_uintmax TLS_OFFSET_R10{bsl::to_umax(0x848U)};
    /// @brief stores the offset in the TLS block for r11
    constexpr bsl::safe_uintmax TLS_OFFSET_R11{bsl::to_umax(0x850U)};
    /// @brief stores the offset in the TLS block for r12
    constexpr bsl::safe_uintmax TLS_OFFSET_R12{bsl::to_umax(0x858U)};
    /// @brief stores the offset in the TLS block for r13
    constexpr bsl::safe_uintmax TLS_OFFSET_R13{bsl::to_umax(0x860U)};
    /// @brief stores the offset in the TLS block for r14
    constexpr bsl::safe_uintmax TLS_OFFSET_R14{bsl::to_umax(0x868U)};
    /// @brief stores the offset in the TLS block for r15
    constexpr bsl::safe_uintmax TLS_OFFSET_R15{bsl::to_umax(0x870U)};
    /// @brief stores the offset in the TLS block for the thread id
    constexpr bsl::safe_uintmax TLS_OFFSET_THREAD_ID{bsl::to_umax(0xFF8U)};

    // -------------------------------------------------------------------------
    // Exit Type
    // -------------------------------------------------------------------------

    /// @brief Defines the exit type used by bf_control_op_exit
    // IWYU is more important here, and this rule would make this interface
    // needlessly overcomplicated.
    // NOLINTNEXTLINE(bsl-user-defined-type-names-match-header-name)
    enum class bf_exit_status_t : bsl::uint64
    {
        /// @brief Exit with a success code
        success = static_cast<bsl::uint64>(0),
        /// @brief Exit with a failure code
        failure = static_cast<bsl::uint64>(1)
    };

    // -------------------------------------------------------------------------
    // Bootstrap Callback Handler Type
    // -------------------------------------------------------------------------

    /// @brief Defines the signature of the bootstrap callback handler
    // Entry points cannot use safe integral types
    // NOLINTNEXTLINE(bsl-non-safe-integral-types-are-forbidden)
    using bf_callback_handler_bootstrap_t = void (*)(bsl::uint16);

    // -------------------------------------------------------------------------
    // VMExit Callback Handler Type
    // -------------------------------------------------------------------------

    /// @brief Defines the signature of the VM exit callback handler
    // Entry points cannot use safe integral types
    // NOLINTNEXTLINE(bsl-non-safe-integral-types-are-forbidden)
    using bf_callback_handler_vmexit_t = void (*)(bsl::uint16, bsl::uint64);

    // -------------------------------------------------------------------------
    // Fast Fail Callback Handler Type
    // -------------------------------------------------------------------------

    /// @brief Defines the signature of the fast fail callback handler
    // Entry points cannot use safe integral types
    // NOLINTNEXTLINE(bsl-non-safe-integral-types-are-forbidden)
    using bf_callback_handler_fail_t = void (*)(bf_status_t::value_type);

    // -------------------------------------------------------------------------
    // Prototypes
    // -------------------------------------------------------------------------

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_control_op_exit.
    ///
    extern "C" void bf_control_op_exit_impl() noexcept;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_handle_op_open_handle.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///   @param reg0_out n/a
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] auto bf_handle_op_open_handle_impl(    // --
        bf_uint32_t const reg0_in,                                  // --
        bf_uint64_t *const reg0_out) noexcept -> bf_status_t::value_type;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_handle_op_close_handle.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///
    extern "C" void bf_handle_op_close_handle_impl(    // --
        bf_uint64_t const reg0_in) noexcept;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_debug_op_out.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///   @param reg1_in n/a
    ///
    extern "C" void bf_debug_op_out_impl(    // --
        bf_uint64_t const reg0_in,           // --
        bf_uint64_t const reg1_in) noexcept;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_debug_op_dump_vm.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///
    extern "C" void bf_debug_op_dump_vm_impl(    // --
        bf_uint16_t const reg0_in) noexcept;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_debug_op_dump_vp.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///
    extern "C" void bf_debug_op_dump_vp_impl(    // --
        bf_uint16_t const reg0_in) noexcept;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_debug_op_dump_vps.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///
    extern "C" void bf_debug_op_dump_vps_impl(    // --
        bf_uint16_t const reg0_in) noexcept;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_debug_op_dump_vmexit_log.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///
    extern "C" void bf_debug_op_dump_vmexit_log_impl(    // --
        bf_uint16_t const reg0_in) noexcept;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_debug_op_write_c.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///
    extern "C" void bf_debug_op_write_c_impl(    // --
        bsl::char_type const reg0_in) noexcept;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_debug_op_write_str.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///
    extern "C" void bf_debug_op_write_str_impl(    // --
        bsl::char_type const *const reg0_in) noexcept;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_callback_op_wait.
    ///
    extern "C" void bf_callback_op_wait_impl() noexcept;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_callback_op_register_bootstrap.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///   @param reg1_in n/a
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] auto bf_callback_op_register_bootstrap_impl(    // --
        bf_uint64_t const reg0_in,                                           // --
        bf_callback_handler_bootstrap_t const reg1_in) noexcept -> bf_status_t::value_type;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_callback_op_register_vmexit.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///   @param reg1_in n/a
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] auto bf_callback_op_register_vmexit_impl(    // --
        bf_uint64_t const reg0_in,                                        // --
        bf_callback_handler_vmexit_t const reg1_in) noexcept -> bf_status_t::value_type;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_callback_op_register_fail.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///   @param reg1_in n/a
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] auto bf_callback_op_register_fail_impl(    // --
        bf_uint64_t const reg0_in,                                      // --
        bf_callback_handler_fail_t const reg1_in) noexcept -> bf_status_t::value_type;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_vm_op_create_vm.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///   @param reg0_out n/a
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] auto bf_vm_op_create_vm_impl(    // --
        bf_uint64_t const reg0_in,                            // --
        bf_uint16_t *const reg0_out) noexcept -> bf_status_t::value_type;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_vm_op_destroy_vm.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///   @param reg1_in n/a
    ///
    extern "C" void bf_vm_op_destroy_vm_impl(    // --
        bf_uint64_t const reg0_in,               // --
        bf_uint16_t const reg1_in) noexcept;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_vp_op_create_vp.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///   @param reg0_out n/a
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] auto bf_vp_op_create_vp_impl(    // --
        bf_uint64_t const reg0_in,                            // --
        bf_uint16_t *const reg0_out) noexcept -> bf_status_t::value_type;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_vp_op_destroy_vp.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///   @param reg1_in n/a
    ///
    extern "C" void bf_vp_op_destroy_vp_impl(    // --
        bf_uint64_t const reg0_in,               // --
        bf_uint16_t const reg1_in) noexcept;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_vps_op_create_vps.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///   @param reg0_out n/a
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] auto bf_vps_op_create_vps_impl(    // --
        bf_uint64_t const reg0_in,                              // --
        bf_uint16_t *const reg0_out) noexcept -> bf_status_t::value_type;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_vps_op_destroy_vps.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///   @param reg1_in n/a
    ///
    extern "C" void bf_vps_op_destroy_vps_impl(    // --
        bf_uint64_t const reg0_in,                 // --
        bf_uint16_t const reg1_in) noexcept;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_vps_op_init_as_root.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///   @param reg1_in n/a
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] auto bf_vps_op_init_as_root_impl(    // --
        bf_uint64_t const reg0_in,                                // --
        bf_uint16_t const reg1_in) noexcept -> bf_status_t::value_type;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_vps_op_read8.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///   @param reg1_in n/a
    ///   @param reg2_in n/a
    ///   @param reg0_out n/a
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] auto bf_vps_op_read8_impl(    // --
        bf_uint64_t const reg0_in,                         // --
        bf_uint16_t const reg1_in,                         // --
        bf_uint64_t const reg2_in,                         // --
        bf_uint8_t *const reg0_out) noexcept -> bf_status_t::value_type;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_vps_op_read16.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///   @param reg1_in n/a
    ///   @param reg2_in n/a
    ///   @param reg0_out n/a
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] auto bf_vps_op_read16_impl(    // --
        bf_uint64_t const reg0_in,                          // --
        bf_uint16_t const reg1_in,                          // --
        bf_uint64_t const reg2_in,                          // --
        bf_uint16_t *const reg0_out) noexcept -> bf_status_t::value_type;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_vps_op_read32.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///   @param reg1_in n/a
    ///   @param reg2_in n/a
    ///   @param reg0_out n/a
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] auto bf_vps_op_read32_impl(    // --
        bf_uint64_t const reg0_in,                          // --
        bf_uint16_t const reg1_in,                          // --
        bf_uint64_t const reg2_in,                          // --
        bf_uint32_t *const reg0_out) noexcept -> bf_status_t::value_type;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_vps_op_read64.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///   @param reg1_in n/a
    ///   @param reg2_in n/a
    ///   @param reg0_out n/a
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] auto bf_vps_op_read64_impl(    // --
        bf_uint64_t const reg0_in,                          // --
        bf_uint16_t const reg1_in,                          // --
        bf_uint64_t const reg2_in,                          // --
        bf_uint64_t *const reg0_out) noexcept -> bf_status_t::value_type;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_vps_op_write8.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///   @param reg1_in n/a
    ///   @param reg2_in n/a
    ///   @param reg3_in n/a
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] auto bf_vps_op_write8_impl(    // --
        bf_uint64_t const reg0_in,                          // --
        bf_uint16_t const reg1_in,                          // --
        bf_uint64_t const reg2_in,                          // --
        bf_uint8_t const reg3_in) noexcept -> bf_status_t::value_type;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_vps_op_write16.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///   @param reg1_in n/a
    ///   @param reg2_in n/a
    ///   @param reg3_in n/a
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] auto bf_vps_op_write16_impl(    // --
        bf_uint64_t const reg0_in,                           // --
        bf_uint16_t const reg1_in,                           // --
        bf_uint64_t const reg2_in,                           // --
        bf_uint16_t const reg3_in) noexcept -> bf_status_t::value_type;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_vps_op_write32.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///   @param reg1_in n/a
    ///   @param reg2_in n/a
    ///   @param reg3_in n/a
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] auto bf_vps_op_write32_impl(    // --
        bf_uint64_t const reg0_in,                           // --
        bf_uint16_t const reg1_in,                           // --
        bf_uint64_t const reg2_in,                           // --
        bf_uint32_t const reg3_in) noexcept -> bf_status_t::value_type;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_vps_op_write64.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///   @param reg1_in n/a
    ///   @param reg2_in n/a
    ///   @param reg3_in n/a
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] auto bf_vps_op_write64_impl(    // --
        bf_uint64_t const reg0_in,                           // --
        bf_uint16_t const reg1_in,                           // --
        bf_uint64_t const reg2_in,                           // --
        bf_uint64_t const reg3_in) noexcept -> bf_status_t::value_type;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_vps_op_read_reg_impl.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///   @param reg1_in n/a
    ///   @param reg2_in n/a
    ///   @param reg0_out n/a
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] auto bf_vps_op_read_reg_impl(    // --
        bf_uint64_t const reg0_in,                            // --
        bf_uint16_t const reg1_in,                            // --
        bf_reg_t const reg2_in,                               // --
        bf_uint64_t *const reg0_out) noexcept -> bf_status_t::value_type;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_vps_op_write_reg.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///   @param reg1_in n/a
    ///   @param reg2_in n/a
    ///   @param reg3_in n/a
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] auto bf_vps_op_write_reg_impl(    // --
        bf_uint64_t const reg0_in,                             // --
        bf_uint16_t const reg1_in,                             // --
        bf_reg_t const reg2_in,                                // --
        bf_uint64_t const reg3_in) noexcept -> bf_status_t::value_type;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_vps_op_run.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///   @param reg1_in n/a
    ///   @param reg2_in n/a
    ///   @param reg3_in n/a
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] auto bf_vps_op_run_impl(    // --
        bf_uint64_t const reg0_in,                       // --
        bf_uint16_t const reg1_in,                       // --
        bf_uint16_t const reg2_in,                       // --
        bf_uint16_t const reg3_in) noexcept -> bf_status_t::value_type;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_vps_op_run_current.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] auto bf_vps_op_run_current_impl(    // --
        bf_uint64_t const reg0_in) noexcept -> bf_status_t::value_type;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_vps_op_advance_ip.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///   @param reg1_in n/a
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] auto bf_vps_op_advance_ip_impl(    // --
        bf_uint64_t const reg0_in,                              // --
        bf_uint16_t const reg1_in) noexcept -> bf_status_t::value_type;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_vps_op_advance_ip_and_run_current.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] auto bf_vps_op_advance_ip_and_run_current_impl(    // --
        bf_uint64_t const reg0_in) noexcept -> bf_status_t::value_type;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_vps_op_promote.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///   @param reg1_in n/a
    ///
    extern "C" void bf_vps_op_promote_impl(    // --
        bf_uint64_t const reg0_in,             // --
        bf_uint16_t const reg1_in) noexcept;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_intrinsic_op_read_msr.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///   @param reg1_in n/a
    ///   @param reg0_out n/a
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] auto bf_intrinsic_op_read_msr_impl(    // --
        bf_uint64_t const reg0_in,                                  // --
        bf_uint32_t const reg1_in,                                  // --
        bf_uint64_t *const reg0_out) noexcept -> bf_status_t::value_type;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_intrinsic_op_write_msr.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///   @param reg1_in n/a
    ///   @param reg2_in n/a
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] auto bf_intrinsic_op_write_msr_impl(    // --
        bf_uint64_t const reg0_in,                                   // --
        bf_uint32_t const reg1_in,                                   // --
        bf_uint64_t const reg2_in) noexcept -> bf_status_t::value_type;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_mem_op_alloc_page.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///   @param reg0_out n/a
    ///   @param reg1_out n/a
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] auto bf_mem_op_alloc_page_impl(    // --
        bf_uint64_t const reg0_in,                              // --
        bf_ptr_t *const reg0_out,
        bf_uint64_t *const reg1_out) noexcept -> bf_status_t::value_type;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_mem_op_virt_to_phys.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///   @param reg1_in n/a
    ///   @param reg0_out n/a
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] auto bf_mem_op_virt_to_phys_impl(    // --
        bf_uint64_t const reg0_in,                                // --
        bf_ptr_t const reg1_in,                                   // --
        bf_uint64_t *const reg0_out) noexcept -> bf_status_t::value_type;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_tls_rax.
    ///
    /// <!-- inputs/outputs -->
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] auto bf_tls_rax_impl() noexcept -> bf_uint64_t;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_tls_set_rax.
    ///
    /// <!-- inputs/outputs -->
    ///   @param val n/a
    ///
    extern "C" void bf_tls_set_rax_impl(bf_uint64_t const val) noexcept;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_tls_rbx.
    ///
    /// <!-- inputs/outputs -->
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] auto bf_tls_rbx_impl() noexcept -> bf_uint64_t;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_tls_set_rbx.
    ///
    /// <!-- inputs/outputs -->
    ///   @param val n/a
    ///
    extern "C" void bf_tls_set_rbx_impl(bf_uint64_t const val) noexcept;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_tls_rcx.
    ///
    /// <!-- inputs/outputs -->
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] auto bf_tls_rcx_impl() noexcept -> bf_uint64_t;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_tls_set_rcx.
    ///
    /// <!-- inputs/outputs -->
    ///   @param val n/a
    ///
    extern "C" void bf_tls_set_rcx_impl(bf_uint64_t const val) noexcept;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_tls_rdx.
    ///
    /// <!-- inputs/outputs -->
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] auto bf_tls_rdx_impl() noexcept -> bf_uint64_t;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_tls_set_rdx.
    ///
    /// <!-- inputs/outputs -->
    ///   @param val n/a
    ///
    extern "C" void bf_tls_set_rdx_impl(bf_uint64_t const val) noexcept;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_tls_rbp.
    ///
    /// <!-- inputs/outputs -->
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] auto bf_tls_rbp_impl() noexcept -> bf_uint64_t;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_tls_set_rbp.
    ///
    /// <!-- inputs/outputs -->
    ///   @param val n/a
    ///
    extern "C" void bf_tls_set_rbp_impl(bf_uint64_t const val) noexcept;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_tls_rsi.
    ///
    /// <!-- inputs/outputs -->
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] auto bf_tls_rsi_impl() noexcept -> bf_uint64_t;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_tls_set_rsi.
    ///
    /// <!-- inputs/outputs -->
    ///   @param val n/a
    ///
    extern "C" void bf_tls_set_rsi_impl(bf_uint64_t const val) noexcept;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_tls_rdi.
    ///
    /// <!-- inputs/outputs -->
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] auto bf_tls_rdi_impl() noexcept -> bf_uint64_t;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_tls_set_rdi.
    ///
    /// <!-- inputs/outputs -->
    ///   @param val n/a
    ///
    extern "C" void bf_tls_set_rdi_impl(bf_uint64_t const val) noexcept;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_tls_r8.
    ///
    /// <!-- inputs/outputs -->
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] auto bf_tls_r8_impl() noexcept -> bf_uint64_t;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_tls_set_r8.
    ///
    /// <!-- inputs/outputs -->
    ///   @param val n/a
    ///
    extern "C" void bf_tls_set_r8_impl(bf_uint64_t const val) noexcept;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_tls_r9.
    ///
    /// <!-- inputs/outputs -->
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] auto bf_tls_r9_impl() noexcept -> bf_uint64_t;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_tls_set_r9.
    ///
    /// <!-- inputs/outputs -->
    ///   @param val n/a
    ///
    extern "C" void bf_tls_set_r9_impl(bf_uint64_t const val) noexcept;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_tls_r10.
    ///
    /// <!-- inputs/outputs -->
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] auto bf_tls_r10_impl() noexcept -> bf_uint64_t;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_tls_set_r10.
    ///
    /// <!-- inputs/outputs -->
    ///   @param val n/a
    ///
    extern "C" void bf_tls_set_r10_impl(bf_uint64_t const val) noexcept;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_tls_r11.
    ///
    /// <!-- inputs/outputs -->
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] auto bf_tls_r11_impl() noexcept -> bf_uint64_t;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_tls_set_r11.
    ///
    /// <!-- inputs/outputs -->
    ///   @param val n/a
    ///
    extern "C" void bf_tls_set_r11_impl(bf_uint64_t const val) noexcept;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_tls_r12.
    ///
    /// <!-- inputs/outputs -->
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] auto bf_tls_r12_impl() noexcept -> bf_uint64_t;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_tls_set_r12.
    ///
    /// <!-- inputs/outputs -->
    ///   @param val n/a
    ///
    extern "C" void bf_tls_set_r12_impl(bf_uint64_t const val) noexcept;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_tls_r13.
    ///
    /// <!-- inputs/outputs -->
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] auto bf_tls_r13_impl() noexcept -> bf_uint64_t;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_tls_set_r13.
    ///
    /// <!-- inputs/outputs -->
    ///   @param val n/a
    ///
    extern "C" void bf_tls_set_r13_impl(bf_uint64_t const val) noexcept;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_tls_r14.
    ///
    /// <!-- inputs/outputs -->
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] auto bf_tls_r14_impl() noexcept -> bf_uint64_t;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_tls_set_r14.
    ///
    /// <!-- inputs/outputs -->
    ///   @param val n/a
    ///
    extern "C" void bf_tls_set_r14_impl(bf_uint64_t const val) noexcept;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_tls_r15.
    ///
    /// <!-- inputs/outputs -->
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] auto bf_tls_r15_impl() noexcept -> bf_uint64_t;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_tls_set_r15.
    ///
    /// <!-- inputs/outputs -->
    ///   @param val n/a
    ///
    extern "C" void bf_tls_set_r15_impl(bf_uint64_t const val) noexcept;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_tls_thread_id.
    ///
    /// <!-- inputs/outputs -->
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] auto bf_tls_thread_id_impl() noexcept -> bf_uint64_t;

    // -------------------------------------------------------------------------
    // TLS
    // -------------------------------------------------------------------------

    /// <!-- description -->
    ///   @brief Returns the value of tls.rax
    ///
    /// <!-- inputs/outputs -->
    ///   @param handle reserved for uint testing
    ///   @return Returns the value of tls.rax
    ///
    [[nodiscard]] inline auto
    bf_tls_rax(bf_handle_t const &handle) noexcept -> bsl::safe_uintmax
    {
        bsl::discard(handle);
        return {bf_tls_rax_impl()};
    }

    /// <!-- description -->
    ///   @brief Sets the value of tls.rax
    ///
    /// <!-- inputs/outputs -->
    ///   @param handle reserved for uint testing
    ///   @param val The value to set tls.rax to
    ///
    inline void
    bf_tls_set_rax(bf_handle_t const &handle, bsl::safe_uintmax const &val) noexcept
    {
        bsl::discard(handle);
        bf_tls_set_rax_impl(val.get());
    }

    /// <!-- description -->
    ///   @brief Returns the value of tls.rbx
    ///
    /// <!-- inputs/outputs -->
    ///   @param handle reserved for uint testing
    ///   @return Returns the value of tls.rbx
    ///
    [[nodiscard]] inline auto
    bf_tls_rbx(bf_handle_t const &handle) noexcept -> bsl::safe_uintmax
    {
        bsl::discard(handle);
        return {bf_tls_rbx_impl()};
    }

    /// <!-- description -->
    ///   @brief Sets the value of tls.rbx
    ///
    /// <!-- inputs/outputs -->
    ///   @param handle reserved for uint testing
    ///   @param val The value to set tls.rbx to
    ///
    inline void
    bf_tls_set_rbx(bf_handle_t const &handle, bsl::safe_uintmax const &val) noexcept
    {
        bsl::discard(handle);
        bf_tls_set_rbx_impl(val.get());
    }

    /// <!-- description -->
    ///   @brief Returns the value of tls.rcx
    ///
    /// <!-- inputs/outputs -->
    ///   @param handle reserved for uint testing
    ///   @return Returns the value of tls.rcx
    ///
    [[nodiscard]] inline auto
    bf_tls_rcx(bf_handle_t const &handle) noexcept -> bsl::safe_uintmax
    {
        bsl::discard(handle);
        return {bf_tls_rcx_impl()};
    }

    /// <!-- description -->
    ///   @brief Sets the value of tls.rcx
    ///
    /// <!-- inputs/outputs -->
    ///   @param handle reserved for uint testing
    ///   @param val The value to set tls.rcx to
    ///
    inline void
    bf_tls_set_rcx(bf_handle_t const &handle, bsl::safe_uintmax const &val) noexcept
    {
        bsl::discard(handle);
        bf_tls_set_rcx_impl(val.get());
    }

    /// <!-- description -->
    ///   @brief Returns the value of tls.rdx
    ///
    /// <!-- inputs/outputs -->
    ///   @param handle reserved for uint testing
    ///   @return Returns the value of tls.rdx
    ///
    [[nodiscard]] inline auto
    bf_tls_rdx(bf_handle_t const &handle) noexcept -> bsl::safe_uintmax
    {
        bsl::discard(handle);
        return {bf_tls_rdx_impl()};
    }

    /// <!-- description -->
    ///   @brief Sets the value of tls.rdx
    ///
    /// <!-- inputs/outputs -->
    ///   @param handle reserved for uint testing
    ///   @param val The value to set tls.rdx to
    ///
    inline void
    bf_tls_set_rdx(bf_handle_t const &handle, bsl::safe_uintmax const &val) noexcept
    {
        bsl::discard(handle);
        bf_tls_set_rdx_impl(val.get());
    }

    /// <!-- description -->
    ///   @brief Returns the value of tls.rbp
    ///
    /// <!-- inputs/outputs -->
    ///   @param handle reserved for uint testing
    ///   @return Returns the value of tls.rbp
    ///
    [[nodiscard]] inline auto
    bf_tls_rbp(bf_handle_t const &handle) noexcept -> bsl::safe_uintmax
    {
        bsl::discard(handle);
        return {bf_tls_rbp_impl()};
    }

    /// <!-- description -->
    ///   @brief Sets the value of tls.rbp
    ///
    /// <!-- inputs/outputs -->
    ///   @param handle reserved for uint testing
    ///   @param val The value to set tls.rbp to
    ///
    inline void
    bf_tls_set_rbp(bf_handle_t const &handle, bsl::safe_uintmax const &val) noexcept
    {
        bsl::discard(handle);
        bf_tls_set_rbp_impl(val.get());
    }

    /// <!-- description -->
    ///   @brief Returns the value of tls.rsi
    ///
    /// <!-- inputs/outputs -->
    ///   @param handle reserved for uint testing
    ///   @return Returns the value of tls.rsi
    ///
    [[nodiscard]] inline auto
    bf_tls_rsi(bf_handle_t const &handle) noexcept -> bsl::safe_uintmax
    {
        bsl::discard(handle);
        return {bf_tls_rsi_impl()};
    }

    /// <!-- description -->
    ///   @brief Sets the value of tls.rsi
    ///
    /// <!-- inputs/outputs -->
    ///   @param handle reserved for uint testing
    ///   @param val The value to set tls.rsi to
    ///
    inline void
    bf_tls_set_rsi(bf_handle_t const &handle, bsl::safe_uintmax const &val) noexcept
    {
        bsl::discard(handle);
        bf_tls_set_rsi_impl(val.get());
    }

    /// <!-- description -->
    ///   @brief Returns the value of tls.rdi
    ///
    /// <!-- inputs/outputs -->
    ///   @param handle reserved for uint testing
    ///   @return Returns the value of tls.rdi
    ///
    [[nodiscard]] inline auto
    bf_tls_rdi(bf_handle_t const &handle) noexcept -> bsl::safe_uintmax
    {
        bsl::discard(handle);
        return {bf_tls_rdi_impl()};
    }

    /// <!-- description -->
    ///   @brief Sets the value of tls.rdi
    ///
    /// <!-- inputs/outputs -->
    ///   @param handle reserved for uint testing
    ///   @param val The value to set tls.rdi to
    ///
    inline void
    bf_tls_set_rdi(bf_handle_t const &handle, bsl::safe_uintmax const &val) noexcept
    {
        bsl::discard(handle);
        bf_tls_set_rdi_impl(val.get());
    }

    /// <!-- description -->
    ///   @brief Returns the value of tls.r8
    ///
    /// <!-- inputs/outputs -->
    ///   @param handle reserved for uint testing
    ///   @return Returns the value of tls.r8
    ///
    [[nodiscard]] inline auto
    bf_tls_r8(bf_handle_t const &handle) noexcept -> bsl::safe_uintmax
    {
        bsl::discard(handle);
        return {bf_tls_r8_impl()};
    }

    /// <!-- description -->
    ///   @brief Sets the value of tls.r8
    ///
    /// <!-- inputs/outputs -->
    ///   @param handle reserved for uint testing
    ///   @param val The value to set tls.r8 to
    ///
    inline void
    bf_tls_set_r8(bf_handle_t const &handle, bsl::safe_uintmax const &val) noexcept
    {
        bsl::discard(handle);
        bf_tls_set_r8_impl(val.get());
    }

    /// <!-- description -->
    ///   @brief Returns the value of tls.r9
    ///
    /// <!-- inputs/outputs -->
    ///   @param handle reserved for uint testing
    ///   @return Returns the value of tls.r9
    ///
    [[nodiscard]] inline auto
    bf_tls_r9(bf_handle_t const &handle) noexcept -> bsl::safe_uintmax
    {
        bsl::discard(handle);
        return {bf_tls_r9_impl()};
    }

    /// <!-- description -->
    ///   @brief Sets the value of tls.r9
    ///
    /// <!-- inputs/outputs -->
    ///   @param handle reserved for uint testing
    ///   @param val The value to set tls.r9 to
    ///
    inline void
    bf_tls_set_r9(bf_handle_t const &handle, bsl::safe_uintmax const &val) noexcept
    {
        bsl::discard(handle);
        bf_tls_set_r9_impl(val.get());
    }

    /// <!-- description -->
    ///   @brief Returns the value of tls.r10
    ///
    /// <!-- inputs/outputs -->
    ///   @param handle reserved for uint testing
    ///   @return Returns the value of tls.r10
    ///
    [[nodiscard]] inline auto
    bf_tls_r10(bf_handle_t const &handle) noexcept -> bsl::safe_uintmax
    {
        bsl::discard(handle);
        return {bf_tls_r10_impl()};
    }

    /// <!-- description -->
    ///   @brief Sets the value of tls.r10
    ///
    /// <!-- inputs/outputs -->
    ///   @param handle reserved for uint testing
    ///   @param val The value to set tls.r10 to
    ///
    inline void
    bf_tls_set_r10(bf_handle_t const &handle, bsl::safe_uintmax const &val) noexcept
    {
        bsl::discard(handle);
        bf_tls_set_r10_impl(val.get());
    }

    /// <!-- description -->
    ///   @brief Returns the value of tls.r11
    ///
    /// <!-- inputs/outputs -->
    ///   @param handle reserved for uint testing
    ///   @return Returns the value of tls.r11
    ///
    [[nodiscard]] inline auto
    bf_tls_r11(bf_handle_t const &handle) noexcept -> bsl::safe_uintmax
    {
        bsl::discard(handle);
        return {bf_tls_r11_impl()};
    }

    /// <!-- description -->
    ///   @brief Sets the value of tls.r11
    ///
    /// <!-- inputs/outputs -->
    ///   @param handle reserved for uint testing
    ///   @param val The value to set tls.r11 to
    ///
    inline void
    bf_tls_set_r11(bf_handle_t const &handle, bsl::safe_uintmax const &val) noexcept
    {
        bsl::discard(handle);
        bf_tls_set_r11_impl(val.get());
    }

    /// <!-- description -->
    ///   @brief Returns the value of tls.r12
    ///
    /// <!-- inputs/outputs -->
    ///   @param handle reserved for uint testing
    ///   @return Returns the value of tls.r12
    ///
    [[nodiscard]] inline auto
    bf_tls_r12(bf_handle_t const &handle) noexcept -> bsl::safe_uintmax
    {
        bsl::discard(handle);
        return {bf_tls_r12_impl()};
    }

    /// <!-- description -->
    ///   @brief Sets the value of tls.r12
    ///
    /// <!-- inputs/outputs -->
    ///   @param handle reserved for uint testing
    ///   @param val The value to set tls.r12 to
    ///
    inline void
    bf_tls_set_r12(bf_handle_t const &handle, bsl::safe_uintmax const &val) noexcept
    {
        bsl::discard(handle);
        bf_tls_set_r12_impl(val.get());
    }

    /// <!-- description -->
    ///   @brief Returns the value of tls.r13
    ///
    /// <!-- inputs/outputs -->
    ///   @param handle reserved for uint testing
    ///   @return Returns the value of tls.r13
    ///
    [[nodiscard]] inline auto
    bf_tls_r13(bf_handle_t const &handle) noexcept -> bsl::safe_uintmax
    {
        bsl::discard(handle);
        return {bf_tls_r13_impl()};
    }

    /// <!-- description -->
    ///   @brief Sets the value of tls.r13
    ///
    /// <!-- inputs/outputs -->
    ///   @param handle reserved for uint testing
    ///   @param val The value to set tls.r13 to
    ///
    inline void
    bf_tls_set_r13(bf_handle_t const &handle, bsl::safe_uintmax const &val) noexcept
    {
        bsl::discard(handle);
        bf_tls_set_r13_impl(val.get());
    }

    /// <!-- description -->
    ///   @brief Returns the value of tls.r14
    ///
    /// <!-- inputs/outputs -->
    ///   @param handle reserved for uint testing
    ///   @return Returns the value of tls.r14
    ///
    [[nodiscard]] inline auto
    bf_tls_r14(bf_handle_t const &handle) noexcept -> bsl::safe_uintmax
    {
        bsl::discard(handle);
        return {bf_tls_r14_impl()};
    }

    /// <!-- description -->
    ///   @brief Sets the value of tls.r14
    ///
    /// <!-- inputs/outputs -->
    ///   @param handle reserved for uint testing
    ///   @param val The value to set tls.r14 to
    ///
    inline void
    bf_tls_set_r14(bf_handle_t const &handle, bsl::safe_uintmax const &val) noexcept
    {
        bsl::discard(handle);
        bf_tls_set_r14_impl(val.get());
    }

    /// <!-- description -->
    ///   @brief Returns the value of tls.r15
    ///
    /// <!-- inputs/outputs -->
    ///   @param handle reserved for uint testing
    ///   @return Returns the value of tls.r15
    ///
    [[nodiscard]] inline auto
    bf_tls_r15(bf_handle_t const &handle) noexcept -> bsl::safe_uintmax
    {
        bsl::discard(handle);
        return {bf_tls_r15_impl()};
    }

    /// <!-- description -->
    ///   @brief Sets the value of tls.r15
    ///
    /// <!-- inputs/outputs -->
    ///   @param handle reserved for uint testing
    ///   @param val The value to set tls.r15 to
    ///
    inline void
    bf_tls_set_r15(bf_handle_t const &handle, bsl::safe_uintmax const &val) noexcept
    {
        bsl::discard(handle);
        bf_tls_set_r15_impl(val.get());
    }

    /// <!-- description -->
    ///   @brief Returns the value of tls.thread_id
    ///
    /// <!-- inputs/outputs -->
    ///   @return Returns the value of tls.thread_id
    ///
    [[nodiscard]] inline auto
    bf_tls_thread_id() noexcept -> bsl::safe_uintmax
    {
        return {bf_tls_thread_id_impl()};
    }

    // -------------------------------------------------------------------------
    // Syscall Status Codes
    // -------------------------------------------------------------------------

    /// @brief Defines a mask for BF_STATUS_SIG
    constexpr bf_status_t BF_STATUS_SIG_MASK{bsl::to_u64(0xFFFF000000000000U)};
    /// @brief Defines a mask for BF_STATUS_FLAGS
    constexpr bf_status_t BF_STATUS_FLAGS_MASK{bsl::to_u64(0x0000FFFFFFFF0000U)};
    /// @brief Defines a mask for BF_STATUS_VALUE
    constexpr bf_status_t BF_STATUS_VALUE_MASK{bsl::to_u64(0x000000000000FFFFU)};

    /// <!-- description -->
    ///   @brief n/a
    ///
    /// <!-- inputs/outputs -->
    ///   @param status n/a
    ///   @return n/a
    ///
    [[nodiscard]] inline auto
    bf_status_sig(bf_status_t const &status) noexcept -> bf_status_t
    {
        return status & BF_STATUS_SIG_MASK;
    }

    /// <!-- description -->
    ///   @brief n/a
    ///
    /// <!-- inputs/outputs -->
    ///   @param status n/a
    ///   @return n/a
    ///
    [[nodiscard]] inline auto
    bf_status_flags(bf_status_t const &status) noexcept -> bf_status_t
    {
        return status & BF_STATUS_FLAGS_MASK;
    }

    /// <!-- description -->
    ///   @brief n/a
    ///
    /// <!-- inputs/outputs -->
    ///   @param status n/a
    ///   @return n/a
    ///
    [[nodiscard]] inline auto
    bf_status_value(bf_status_t const &status) noexcept -> bf_status_t
    {
        return status & BF_STATUS_VALUE_MASK;
    }

    /// @brief Used to indicated that the syscall returned successfully
    constexpr bf_status_t BF_STATUS_SUCCESS{bsl::to_u64(0x0000000000000000U)};
    /// @brief Indicates an unknown error occurred
    constexpr bf_status_t BF_STATUS_FAILURE_UNKNOWN{bsl::to_u64(0xDEAD000000010001U)};
    /// @brief Indicates the syscall is unsupported
    constexpr bf_status_t BF_STATUS_FAILURE_INVALID_HANDLE{bsl::to_u64(0xDEAD000000020001U)};
    /// @brief Indicates the provided handle is invalid
    constexpr bf_status_t BF_STATUS_FAILURE_UNSUPPORTED{bsl::to_u64(0xDEAD000000040001U)};
    /// @brief Indicates the extension is not allowed to execute this syscall
    constexpr bf_status_t BF_STATUS_INVALID_PERM_EXT{bsl::to_u64(0xDEAD000000010002U)};
    /// @brief Indicates the policy engine denied the syscall
    constexpr bf_status_t BF_STATUS_INVALID_PERM_DENIED{bsl::to_u64(0xDEAD000000020002U)};
    /// @brief Indicates param 0 is invalid
    constexpr bf_status_t BF_STATUS_INVALID_PARAMS0{bsl::to_u64(0xDEAD000000010003U)};
    /// @brief Indicates param 1 is invalid
    constexpr bf_status_t BF_STATUS_INVALID_PARAMS1{bsl::to_u64(0xDEAD000000020003U)};
    /// @brief Indicates param 2 is invalid
    constexpr bf_status_t BF_STATUS_INVALID_PARAMS2{bsl::to_u64(0xDEAD000000040003U)};
    /// @brief Indicates param 3 is invalid
    constexpr bf_status_t BF_STATUS_INVALID_PARAMS3{bsl::to_u64(0xDEAD000000080003U)};
    /// @brief Indicates param 4 is invalid
    constexpr bf_status_t BF_STATUS_INVALID_PARAMS4{bsl::to_u64(0xDEAD000000100003U)};
    /// @brief Indicates param 5 is invalid
    constexpr bf_status_t BF_STATUS_INVALID_PARAMS5{bsl::to_u64(0xDEAD000000200003U)};

    // -------------------------------------------------------------------------
    // Syscall Inputs
    // -------------------------------------------------------------------------

    /// @brief Defines the BF_SYSCALL_SIG field for RAX
    constexpr bsl::safe_uint64 BF_HYPERCALL_SIG_VAL{bsl::to_u64(0x6642000000000000U)};
    /// @brief Defines a mask for BF_SYSCALL_SIG
    constexpr bsl::safe_uint64 BF_HYPERCALL_SIG_MASK{bsl::to_u64(0xFFFF000000000000U)};
    /// @brief Defines a mask for BF_SYSCALL_FLAGS
    constexpr bsl::safe_uint64 BF_HYPERCALL_FLAGS_MASK{bsl::to_u64(0x0000FFFF00000000U)};
    /// @brief Defines a mask for BF_SYSCALL_OP
    constexpr bsl::safe_uint64 BF_HYPERCALL_OPCODE_MASK{bsl::to_u64(0xFFFF0000FFFF0000U)};
    /// @brief Defines a mask for BF_SYSCALL_OP (with no signature added)
    constexpr bsl::safe_uint64 BF_HYPERCALL_OPCODE_NOSIG_MASK{bsl::to_u64(0x00000000FFFF0000U)};
    /// @brief Defines a mask for BF_SYSCALL_IDX
    constexpr bsl::safe_uint64 BF_HYPERCALL_INDEX_MASK{bsl::to_u64(0x000000000000FFFFU)};

    /// <!-- description -->
    ///   @brief n/a
    ///
    /// <!-- inputs/outputs -->
    ///   @param rax n/a
    ///   @return n/a
    ///
    [[nodiscard]] constexpr auto
    bf_syscall_sig(bsl::safe_uint64 const &rax) noexcept -> bsl::safe_uint64
    {
        return rax & BF_HYPERCALL_SIG_MASK;
    }

    /// <!-- description -->
    ///   @brief n/a
    ///
    /// <!-- inputs/outputs -->
    ///   @param rax n/a
    ///   @return n/a
    ///
    [[nodiscard]] constexpr auto
    bf_syscall_flags(bsl::safe_uint64 const &rax) noexcept -> bsl::safe_uint64
    {
        return rax & BF_HYPERCALL_FLAGS_MASK;
    }

    /// <!-- description -->
    ///   @brief n/a
    ///
    /// <!-- inputs/outputs -->
    ///   @param rax n/a
    ///   @return n/a
    ///
    [[nodiscard]] constexpr auto
    bf_syscall_opcode(bsl::safe_uint64 const &rax) noexcept -> bsl::safe_uint64
    {
        return rax & BF_HYPERCALL_OPCODE_MASK;
    }

    /// <!-- description -->
    ///   @brief n/a
    ///
    /// <!-- inputs/outputs -->
    ///   @param rax n/a
    ///   @return n/a
    ///
    [[nodiscard]] constexpr auto
    bf_syscall_opcode_nosig(bsl::safe_uint64 const &rax) noexcept -> bsl::safe_uint64
    {
        return rax & BF_HYPERCALL_OPCODE_NOSIG_MASK;
    }

    /// <!-- description -->
    ///   @brief n/a
    ///
    /// <!-- inputs/outputs -->
    ///   @param rax n/a
    ///   @return n/a
    ///
    [[nodiscard]] constexpr auto
    bf_syscall_index(bsl::safe_uint64 const &rax) noexcept -> bsl::safe_uint64
    {
        return rax & BF_HYPERCALL_INDEX_MASK;
    }

    // -------------------------------------------------------------------------
    // Specification IDs
    // -------------------------------------------------------------------------

    /// @brief Defines the ID for version #1 of this spec
    constexpr bsl::safe_uint32 BF_SPEC_ID1_VAL{bsl::to_u32(0x31236642)};

    /// @brief Defines the mask for checking support for version #1 of this spec
    constexpr bsl::safe_uint32 BF_SPEC_ID1_MASK{bsl::to_u32(0x2)};

    /// @brief Defines the value likely returned by bf_handle_op_version
    constexpr bsl::safe_uint32 BF_ALL_SPECS_SUPPORTED_VAL{bsl::to_u32(0x2)};

    // -------------------------------------------------------------------------
    // Syscall Opcodes - Control Support
    // -------------------------------------------------------------------------

    /// @brief Defines the syscall opcode for bf_control_op
    constexpr bsl::safe_uint64 BF_CONTROL_OP_VAL{bsl::to_u64(0x6642000000000000U)};
    /// @brief Defines the syscall opcode for bf_control_op (nosig)
    constexpr bsl::safe_uint64 BF_CONTROL_OP_NOSIG_VAL{bsl::to_u64(0x0000000000000000U)};

    // -------------------------------------------------------------------------
    // Syscall Opcodes - Handle Support
    // -------------------------------------------------------------------------

    /// @brief Defines the syscall opcode for bf_handle_op
    constexpr bsl::safe_uint64 BF_HANDLE_OP_VAL{bsl::to_u64(0x6642000000010000U)};
    /// @brief Defines the syscall opcode for bf_handle_op (nosig)
    constexpr bsl::safe_uint64 BF_HANDLE_OP_NOSIG_VAL{bsl::to_u64(0x0000000000010000U)};

    // -------------------------------------------------------------------------
    // Syscall Opcodes - Debug Support
    // -------------------------------------------------------------------------

    /// @brief Defines the syscall opcode for bf_debug_op
    constexpr bsl::safe_uint64 BF_DEBUG_OP_VAL{bsl::to_u64(0x6642000000020000U)};
    /// @brief Defines the syscall opcode for bf_debug_op (nosig)
    constexpr bsl::safe_uint64 BF_DEBUG_OP_NOSIG_VAL{bsl::to_u64(0x00000000000020000U)};

    // -------------------------------------------------------------------------
    // Syscall Opcodes - Callback Support
    // -------------------------------------------------------------------------

    /// @brief Defines the syscall opcode for bf_callback_op
    constexpr bsl::safe_uint64 BF_CALLBACK_OP_VAL{bsl::to_u64(0x6642000000030000U)};
    /// @brief Defines the syscall opcode for bf_callback_op (nosig)
    constexpr bsl::safe_uint64 BF_CALLBACK_OP_NOSIG_VAL{bsl::to_u64(0x0000000000030000U)};

    // -------------------------------------------------------------------------
    // Syscall Opcodes - VM Support
    // -------------------------------------------------------------------------

    /// @brief Defines the syscall opcode for bf_vm_op
    constexpr bsl::safe_uint64 BF_VM_OP_VAL{bsl::to_u64(0x6642000000040000U)};
    /// @brief Defines the syscall opcode for bf_vm_op (nosig)
    constexpr bsl::safe_uint64 BF_VM_OP_NOSIG_VAL{bsl::to_u64(0x0000000000040000U)};

    // -------------------------------------------------------------------------
    // Syscall Opcodes - VP Support
    // -------------------------------------------------------------------------

    /// @brief Defines the syscall opcode for bf_vp_op
    constexpr bsl::safe_uint64 BF_VP_OP_VAL{bsl::to_u64(0x6642000000050000U)};
    /// @brief Defines the syscall opcode for bf_vp_op (nosig)
    constexpr bsl::safe_uint64 BF_VP_OP_NOSIG_VAL{bsl::to_u64(0x0000000000050000U)};

    // -------------------------------------------------------------------------
    // Syscall Opcodes - VPS Support
    // -------------------------------------------------------------------------

    /// @brief Defines the syscall opcode for bf_vps_op
    constexpr bsl::safe_uint64 BF_VPS_OP_VAL{bsl::to_u64(0x6642000000060000U)};
    /// @brief Defines the syscall opcode for bf_vps_op (nosig)
    constexpr bsl::safe_uint64 BF_VPS_OP_NOSIG_VAL{bsl::to_u64(0x0000000000060000U)};

    // -------------------------------------------------------------------------
    // Syscall Opcodes - Intrinsic Support
    // -------------------------------------------------------------------------

    /// @brief Defines the syscall opcode for bf_intrinsic_op
    constexpr bsl::safe_uint64 BF_INTRINSIC_OP_VAL{bsl::to_u64(0x6642000000070000U)};
    /// @brief Defines the syscall opcode for bf_intrinsic_op (nosig)
    constexpr bsl::safe_uint64 BF_INTRINSIC_OP_NOSIG_VAL{bsl::to_u64(0x0000000000070000U)};

    // -------------------------------------------------------------------------
    // Syscall Opcodes - Mem Support
    // -------------------------------------------------------------------------

    /// @brief Defines the syscall opcode for bf_mem_op
    constexpr bsl::safe_uint64 BF_MEM_OP_VAL{bsl::to_u64(0x6642000000080000U)};
    /// @brief Defines the syscall opcode for bf_mem_op (nosig)
    constexpr bsl::safe_uint64 BF_MEM_OP_NOSIG_VAL{bsl::to_u64(0x0000000000080000U)};

    // -------------------------------------------------------------------------
    // bf_control_op_exit
    // -------------------------------------------------------------------------

    /// @brief Defines the syscall index for bf_control_op_exit
    constexpr bsl::safe_uint64 BF_CONTROL_OP_EXIT_IDX_VAL{bsl::to_u64(0x0000000000000000U)};

    /// <!-- description -->
    ///   @brief This syscall tells the microkernel to exit the execution
    ///     of an extension, providing a means to fast fail.
    ///
    inline void
    bf_control_op_exit() noexcept
    {
        bf_control_op_exit_impl();
    }

    // -------------------------------------------------------------------------
    // bf_handle_op_open_handle
    // -------------------------------------------------------------------------

    /// @brief Defines the syscall index for bf_handle_op_open_handle
    constexpr bsl::safe_uint64 BF_HANDLE_OP_OPEN_HANDLE_IDX_VAL{bsl::to_u64(0x0000000000000000U)};

    /// <!-- description -->
    ///   @brief This syscall returns a handle which is required to execute
    ///     the remaining syscalls. Some versions of Bareflank might provide
    ///     a certain degree of backwards compatibility which can be queried
    ///     using bf_handle_op_version. The version argument of this syscall
    ///     provides software with means to tell the microkernel which version
    ///     of this spec it is trying to use. If software provides a version
    ///     that Bareflank doesn't support (i.e., a version that is not listed
    ///     by bf_handle_op_version), this syscall will fail.
    ///
    /// <!-- inputs/outputs -->
    ///   @param version The version of this spec that software supports
    ///   @param handle The value to set REG0 to for most other syscalls
    ///   @return Returns the bf_status_t result of the syscall. See the
    ///     specification for more information about error codes.
    ///
    [[nodiscard]] inline auto
    bf_handle_op_open_handle(               // --
        bsl::safe_uint32 const &version,    // --
        bf_handle_t &handle) noexcept -> bf_status_t
    {
        return {bf_handle_op_open_handle_impl(version.get(), &handle.hndl)};
    }

    // -------------------------------------------------------------------------
    // bf_handle_op_close_handle
    // -------------------------------------------------------------------------

    /// @brief Defines the syscall index for bf_handle_op_close_handle
    constexpr bsl::safe_uint64 BF_HANDLE_OP_CLOSE_HANDLE_IDX_VAL{bsl::to_u64(0x0000000000000001U)};

    /// <!-- description -->
    ///   @brief This syscall closes a previously opened handle.
    ///
    /// <!-- inputs/outputs -->
    ///   @param handle Set to the result of bf_handle_op_open_handle
    ///
    inline void
    bf_handle_op_close_handle(    // --
        bf_handle_t &handle) noexcept
    {
        bf_handle_op_close_handle_impl(handle.hndl);
        handle = {};
    }

    // -------------------------------------------------------------------------
    // bf_is_spec1_supported
    // -------------------------------------------------------------------------

    /// <!-- description -->
    ///   @brief n/a
    ///
    /// <!-- inputs/outputs -->
    ///   @param version n/a
    ///   @return n/a
    ///
    [[nodiscard]] constexpr auto
    bf_is_spec1_supported(bsl::safe_uint32 const &version) noexcept -> bool
    {
        return ((version & BF_SPEC_ID1_MASK) != bsl::ZERO_U32);
    }

    // -------------------------------------------------------------------------
    // bf_debug_op_out
    // -------------------------------------------------------------------------

    /// @brief Defines the syscall index for bf_debug_op_out
    constexpr bsl::safe_uint64 BF_DEBUG_OP_OUT_IDX_VAL{bsl::to_u64(0x0000000000000000U)};

    /// <!-- description -->
    ///   @brief This syscall tells the microkernel to output RDI and RSI to
    ///     the console device the microkernel is currently using for
    ///     debugging. The purpose of this syscall is to provide a simple
    ///     means for debugging issues with the extension and can be used
    ///     even when the extension is not fully bootstrapped or is in a
    ///     failure state. Also note that this syscall is designed to execute
    ///     as quickly as possible (although it is still constrained by the
    ///     speed at which it can dump debug text to the console).
    ///
    /// <!-- inputs/outputs -->
    ///   @param val1 The first value to output to the microkernel's console
    ///   @param val2 The second value to output to the microkernel's console
    ///
    inline void
    bf_debug_op_out(                     // --
        bsl::safe_uint64 const &val1,    // --
        bsl::safe_uint64 const &val2) noexcept
    {
        bf_debug_op_out_impl(val1.get(), val2.get());
    }

    // -------------------------------------------------------------------------
    // bf_debug_op_dump_vm
    // -------------------------------------------------------------------------

    /// @brief Defines the syscall index for bf_debug_op_dump_vm
    constexpr bsl::safe_uint64 BF_DEBUG_OP_DUMP_VM_IDX_VAL{bsl::to_u64(0x0000000000000001U)};

    /// <!-- description -->
    ///   @brief This syscall tells the microkernel to output the state of a
    ///     VM to the console device the microkernel is currently using for
    ///     debugging. The report that is generated is implementation defined,
    ///     and in some cases could take a while to complete. In other words,
    ///     this syscall should only be used when debugging, and only in
    ///     scenarios where you can afford the time needed to output a lot of
    ///     VM state to the microkernel's console.
    ///
    /// <!-- inputs/outputs -->
    ///   @param vmid The VMID of the VM whose state is to be outputted
    ///
    inline void
    bf_debug_op_dump_vm(    // --
        bsl::safe_uint16 const &vmid) noexcept
    {
        bf_debug_op_dump_vm_impl(vmid.get());
    }

    // -------------------------------------------------------------------------
    // bf_debug_op_dump_vp
    // -------------------------------------------------------------------------

    /// @brief Defines the syscall index for bf_debug_op_dump_vp
    constexpr bsl::safe_uint64 BF_DEBUG_OP_DUMP_VP_IDX_VAL{bsl::to_u64(0x0000000000000002U)};

    /// <!-- description -->
    ///   @brief This syscall tells the microkernel to output the state of a
    ///     VP to the console device the microkernel is currently using for
    ///     debugging. The report that is generated is implementation defined,
    ///     and in some cases could take a while to complete. In other words,
    ///     this syscall should only be used when debugging, and only in
    ///     scenarios where you can afford the time needed to output a lot of
    ///     VP state to the microkernel's console.
    ///
    /// <!-- inputs/outputs -->
    ///   @param vpid The VPID of the VP whose state is to be outputted
    ///
    inline void
    bf_debug_op_dump_vp(    // --
        bsl::safe_uint16 const &vpid) noexcept
    {
        bf_debug_op_dump_vp_impl(vpid.get());
    }

    // -------------------------------------------------------------------------
    // bf_debug_op_dump_vps
    // -------------------------------------------------------------------------

    /// @brief Defines the syscall index for bf_debug_op_dump_vps
    constexpr bsl::safe_uint64 BF_DEBUG_OP_DUMP_VPS_IDX_VAL{bsl::to_u64(0x0000000000000003U)};

    /// <!-- description -->
    ///   @brief This syscall tells the microkernel to output the state of a
    ///     VPS to the console device the microkernel is currently using for
    ///     debugging. The report that is generated is implementation defined,
    ///     and in some cases could take a while to complete. In other words,
    ///     this syscall should only be used when debugging, and only in
    ///     scenarios where you can afford the time needed to output a lot of
    ///     VPS state to the microkernel's console.
    ///
    /// <!-- inputs/outputs -->
    ///   @param vpsid The VPSID of the VPS whose state is to be outputted
    ///
    inline void
    bf_debug_op_dump_vps(    // --
        bsl::safe_uint16 const &vpsid) noexcept
    {
        bf_debug_op_dump_vps_impl(vpsid.get());
    }

    // -------------------------------------------------------------------------
    // bf_debug_op_dump_vmexit_log
    // -------------------------------------------------------------------------

    /// @brief Defines the syscall index for bf_debug_op_dump_vmexit_log
    constexpr bsl::safe_uint64 BF_DEBUG_OP_DUMP_VMEXIT_LOG_IDX_VAL{
        bsl::to_u64(0x0000000000000004U)};

    /// <!-- description -->
    ///   @brief This syscall tells the microkernel to output the vmexit log.
    ///     The vmexit log is a chronological log of the "X" number of exits
    ///     that have occurred from the time the call to
    ///     bf_debug_op_dump_vmexit_log is made. The total number of "X" logs
    ///     is implementation defined and not under the control of software
    ///     (i.e., this value is usually compiled into Bareflank cannot be
    ///     changed at runtime). In addition, the format of this log is also
    ///     implementation defined. If the microkernel has to kill a VP for
    ///     VM for any reason it will output this log by default for debugging
    ///     purposes, but sometimes, software is aware of odd condition, or is
    ///     even aware that something bad has happened, and this syscall
    ///     provides software with an opportunity to dump this log on demand.
    ///
    /// <!-- inputs/outputs -->
    ///   @param vpid The VPID of the VP to dump the log from
    ///
    inline void
    bf_debug_op_dump_vmexit_log(    // --
        bsl::safe_uint16 const &vpid) noexcept
    {
        bf_debug_op_dump_vmexit_log_impl(vpid.get());
    }

    // -------------------------------------------------------------------------
    // bf_debug_op_write_c
    // -------------------------------------------------------------------------

    /// @brief Defines the syscall index for bf_debug_op_write_c
    constexpr bsl::safe_uint64 BF_DEBUG_OP_WRITE_C_IDX_VAL{bsl::to_u64(0x0000000000000005U)};

    /// <!-- description -->
    ///   @brief This syscall tells the microkernel to output a provided
    ///     character to the microkernel's console.
    ///
    /// <!-- inputs/outputs -->
    ///   @param c The character to output
    ///
    inline void
    bf_debug_op_write_c(    // --
        bsl::char_type const c) noexcept
    {
        bf_debug_op_write_c_impl(c);
    }

    // -------------------------------------------------------------------------
    // bf_debug_op_write_str
    // -------------------------------------------------------------------------

    /// @brief Defines the syscall index for bf_debug_op_write_str
    constexpr bsl::safe_uint64 BF_DEBUG_OP_WRITE_STR_IDX_VAL{bsl::to_u64(0x0000000000000006U)};

    /// <!-- description -->
    ///   @brief This syscall tells the microkernel to output a provided
    ///     string to the microkernel's console.
    ///
    /// <!-- inputs/outputs -->
    ///   @param str The virtual address of a null terminated string to output
    ///
    inline void
    bf_debug_op_write_str(    // --
        bsl::cstr_type const str) noexcept
    {
        bf_debug_op_write_str_impl(str);
    }

    // -------------------------------------------------------------------------
    // bf_callback_op_wait
    // -------------------------------------------------------------------------

    /// @brief Defines the syscall index for bf_callback_op_wait
    constexpr bsl::safe_uint64 BF_CALLBACK_OP_WAIT_IDX_VAL{bsl::to_u64(0x0000000000000000U)};

    /// <!-- description -->
    ///   @brief This syscall tells the microkernel that the extension would
    ///     like to wait for a callback. This is a blocking syscall that never
    ///     returns and should be used to return from the successful execution
    ///     of the _start function.
    ///
    inline void
    bf_callback_op_wait() noexcept
    {
        bf_callback_op_wait_impl();
    }

    // -------------------------------------------------------------------------
    // bf_callback_op_register_bootstrap
    // -------------------------------------------------------------------------

    /// @brief Defines the syscall index for bf_callback_op_register_bootstrap
    constexpr bsl::safe_uint64 BF_CALLBACK_OP_REGISTER_BOOTSTRAP_IDX_VAL{
        bsl::to_u64(0x0000000000000002U)};

    /// <!-- description -->
    ///   @brief This syscall tells the microkernel that the extension would
    ///     like to receive callbacks for bootstrap events
    ///
    /// <!-- inputs/outputs -->
    ///   @param handle Set to the result of bf_handle_op_open_handle
    ///   @param handler Set to the virtual address of the callback
    ///   @return Returns the bf_status_t result of the syscall. See the
    ///     specification for more information about error codes.
    ///
    [[nodiscard]] inline auto
    bf_callback_op_register_bootstrap(    // --
        bf_handle_t const &handle,        // --
        bf_callback_handler_bootstrap_t const handler) noexcept -> bf_status_t
    {
        return {bf_callback_op_register_bootstrap_impl(handle.hndl, handler)};
    }

    // -------------------------------------------------------------------------
    // bf_callback_op_register_vmexit
    // -------------------------------------------------------------------------

    /// @brief Defines the syscall index for bf_callback_op_register_vmexit
    constexpr bsl::safe_uint64 BF_CALLBACK_OP_REGISTER_VMEXIT_IDX_VAL{
        bsl::to_u64(0x0000000000000003U)};

    /// <!-- description -->
    ///   @brief This syscall tells the microkernel that the extension would
    ///     like to receive callbacks for VM exits
    ///
    /// <!-- inputs/outputs -->
    ///   @param handle Set to the result of bf_handle_op_open_handle
    ///   @param handler Set to the virtual address of the callback
    ///   @return Returns the bf_status_t result of the syscall. See the
    ///     specification for more information about error codes.
    ///
    [[nodiscard]] inline auto
    bf_callback_op_register_vmexit(    // --
        bf_handle_t const &handle,     // --
        bf_callback_handler_vmexit_t const handler) noexcept -> bf_status_t
    {
        return {bf_callback_op_register_vmexit_impl(handle.hndl, handler)};
    }

    // -------------------------------------------------------------------------
    // bf_callback_op_register_fail
    // -------------------------------------------------------------------------

    /// @brief Defines the syscall index for bf_callback_op_register_fail
    constexpr bsl::safe_uint64 BF_CALLBACK_OP_REGISTER_FAIL_IDX_VAL{
        bsl::to_u64(0x0000000000000004U)};

    /// <!-- description -->
    ///   @brief This syscall tells the microkernel that the extension would
    ///     like to receive callbacks for fast fail events. If a fast fail
    ///     event occurs, something really bad has happened, and action must
    ///     be taken, or the physical processor will halt.
    ///
    /// <!-- inputs/outputs -->
    ///   @param handle Set to the result of bf_handle_op_open_handle
    ///   @param handler Set to the virtual address of the callback
    ///   @return Returns the bf_status_t result of the syscall. See the
    ///     specification for more information about error codes.
    ///
    [[nodiscard]] inline auto
    bf_callback_op_register_fail(     // --
        bf_handle_t const &handle,    // --
        bf_callback_handler_fail_t const handler) noexcept -> bf_status_t
    {
        return {bf_callback_op_register_fail_impl(handle.hndl, handler)};
    }

    // -------------------------------------------------------------------------
    // bf_vm_op_create_vm
    // -------------------------------------------------------------------------

    /// @brief Defines the syscall index for bf_vm_op_create_vm
    constexpr bsl::safe_uint64 BF_VM_OP_CREATE_VM_IDX_VAL{bsl::to_u64(0x0000000000000000U)};

    /// <!-- description -->
    ///   @brief This syscall tells the microkernel to create a VM
    ///     and return it's ID.
    ///
    /// <!-- inputs/outputs -->
    ///   @param handle Set to the result of bf_handle_op_open_handle
    ///   @param vmid The resulting VMID of the newly created VM
    ///   @return Returns the bf_status_t result of the syscall. See the
    ///     specification for more information about error codes.
    ///
    [[nodiscard]] inline auto
    bf_vm_op_create_vm(               // --
        bf_handle_t const &handle,    // --
        bsl::safe_uint16 &vmid) noexcept -> bf_status_t
    {
        return {bf_vm_op_create_vm_impl(handle.hndl, vmid.data())};
    }

    // -------------------------------------------------------------------------
    // bf_vm_op_destroy_vm
    // -------------------------------------------------------------------------

    /// @brief Defines the syscall index for bf_vm_op_destroy_vm
    constexpr bsl::safe_uint64 BF_VM_OP_DESTROY_VM_IDX_VAL{bsl::to_u64(0x0000000000000001U)};

    /// <!-- description -->
    ///   @brief This syscall tells the microkernel to destroy a VM
    ///     given an ID.
    ///
    /// <!-- inputs/outputs -->
    ///   @param handle Set to the result of bf_handle_op_open_handle
    ///   @param vmid The VMID of the VM to destroy
    ///
    inline void
    bf_vm_op_destroy_vm(              // --
        bf_handle_t const &handle,    // --
        bsl::safe_uint16 const &vmid) noexcept
    {
        bf_vm_op_destroy_vm_impl(handle.hndl, vmid.get());
    }

    // -------------------------------------------------------------------------
    // bf_vp_op_create_vp
    // -------------------------------------------------------------------------

    /// @brief Defines the syscall index for bf_vp_op_create_vp
    constexpr bsl::safe_uint64 BF_VP_OP_CREATE_VP_IDX_VAL{bsl::to_u64(0x0000000000000000U)};

    /// <!-- description -->
    ///   @brief This syscall tells the microkernel to create a VP
    ///     and return it's ID.
    ///
    /// <!-- inputs/outputs -->
    ///   @param handle Set to the result of bf_handle_op_open_handle
    ///   @param vpid The resulting VPID of the newly created VP
    ///   @return Returns the bf_status_t result of the syscall. See the
    ///     specification for more information about error codes.
    ///
    [[nodiscard]] inline auto
    bf_vp_op_create_vp(               // --
        bf_handle_t const &handle,    // --
        bsl::safe_uint16 &vpid) noexcept -> bf_status_t
    {
        return {bf_vp_op_create_vp_impl(handle.hndl, vpid.data())};
    }

    // -------------------------------------------------------------------------
    // bf_vp_op_destroy_vp
    // -------------------------------------------------------------------------

    /// @brief Defines the syscall index for bf_vp_op_destroy_vp
    constexpr bsl::safe_uint64 BF_VP_OP_DESTROY_VP_IDX_VAL{bsl::to_u64(0x0000000000000001U)};

    /// <!-- description -->
    ///   @brief This syscall tells the microkernel to destroy a VP
    ///     given an ID.
    ///
    /// <!-- inputs/outputs -->
    ///   @param handle Set to the result of bf_handle_op_open_handle
    ///   @param vpid The VPID of the VP to destroy
    ///
    inline void
    bf_vp_op_destroy_vp(              // --
        bf_handle_t const &handle,    // --
        bsl::safe_uint16 const &vpid) noexcept
    {
        bf_vp_op_destroy_vp_impl(handle.hndl, vpid.get());
    }

    // -------------------------------------------------------------------------
    // bf_vps_op_create_vps
    // -------------------------------------------------------------------------

    /// @brief Defines the syscall index for bf_vps_op_create_vps
    constexpr bsl::safe_uint64 BF_VPS_OP_CREATE_VPS_IDX_VAL{bsl::to_u64(0x0000000000000000U)};

    /// <!-- description -->
    ///   @brief This syscall tells the microkernel to create a VPS
    ///     and return it's ID.
    ///
    /// <!-- inputs/outputs -->
    ///   @param handle Set to the result of bf_handle_op_open_handle
    ///   @param vpsid The resulting VPSID of the newly created VPS
    ///   @return Returns the bf_status_t result of the syscall. See the
    ///     specification for more information about error codes.
    ///
    [[nodiscard]] inline auto
    bf_vps_op_create_vps(             // --
        bf_handle_t const &handle,    // --
        bsl::safe_uint16 &vpsid) noexcept -> bf_status_t
    {
        return {bf_vps_op_create_vps_impl(handle.hndl, vpsid.data())};
    }

    // -------------------------------------------------------------------------
    // bf_vps_op_destroy_vps
    // -------------------------------------------------------------------------

    /// @brief Defines the syscall index for bf_vps_op_destroy_vps
    constexpr bsl::safe_uint64 BF_VPS_OP_DESTROY_VPS_IDX_VAL{bsl::to_u64(0x0000000000000001U)};

    /// <!-- description -->
    ///   @brief This syscall tells the microkernel to destroy a VPS
    ///     given an ID.
    ///
    /// <!-- inputs/outputs -->
    ///   @param handle Set to the result of bf_handle_op_open_handle
    ///   @param vpsid The VPSID of the VPS to destroy
    ///
    inline void
    bf_vps_op_destroy_vps(            // --
        bf_handle_t const &handle,    // --
        bsl::safe_uint16 const &vpsid) noexcept
    {
        bf_vps_op_destroy_vps_impl(handle.hndl, vpsid.get());
    }

    // -------------------------------------------------------------------------
    // bf_vps_op_init_as_root
    // -------------------------------------------------------------------------

    /// @brief Defines the syscall index for bf_vps_op_init_as_root
    constexpr bsl::safe_uint64 BF_VPS_OP_INIT_AS_ROOT_IDX_VAL{bsl::to_u64(0x0000000000000002U)};

    /// <!-- description -->
    ///   @brief This syscall tells the microkernel to initialize a VPS using
    ///     the root VP state that was provided by the loader given the VPSID
    ///     to initialize as well as the PPID of the physical processor to
    ///     get the root VP state from.
    ///
    /// <!-- inputs/outputs -->
    ///   @param handle Set to the result of bf_handle_op_open_handle
    ///   @param vpsid The VPSID of the VPS to initialize
    ///   @return Returns the bf_status_t result of the syscall. See the
    ///     specification for more information about error codes.
    ///
    [[nodiscard]] inline auto
    bf_vps_op_init_as_root(           // --
        bf_handle_t const &handle,    // --
        bsl::safe_uint16 const &vpsid) noexcept -> bf_status_t
    {
        return {bf_vps_op_init_as_root_impl(handle.hndl, vpsid.get())};
    }

    // -------------------------------------------------------------------------
    // bf_vps_op_read8
    // -------------------------------------------------------------------------

    /// @brief Defines the syscall index for bf_vps_op_read8
    constexpr bsl::safe_uint64 BF_VPS_OP_READ8_IDX_VAL{bsl::to_u64(0x0000000000000003U)};

    /// <!-- description -->
    ///   @brief Reads an 8bit field from the VPS. The "index" is architecture
    ///     specific. For Intel, the index (or encoding) is the defined in
    ///     Appendix B "Field Encoding in VMCS". For AMD, the index (or offset)
    ///     is defined in Appendix B "Layout of VMCB".
    ///
    /// <!-- inputs/outputs -->
    ///   @param handle Set to the result of bf_handle_op_open_handle
    ///   @param vpsid The VPSID of the VPS to read from
    ///   @param index The HVE specific index defining which field to read
    ///   @param value The resulting value
    ///   @return Returns the bf_status_t result of the syscall. See the
    ///     specification for more information about error codes.
    ///
    [[nodiscard]] inline auto
    bf_vps_op_read8(                      // --
        bf_handle_t const &handle,        // --
        bsl::safe_uint16 const &vpsid,    // --
        bsl::safe_uint64 const &index,    // --
        bsl::safe_uint8 &value) noexcept -> bf_status_t
    {
        return {bf_vps_op_read8_impl(handle.hndl, vpsid.get(), index.get(), value.data())};
    }

    // -------------------------------------------------------------------------
    // bf_vps_op_read16
    // -------------------------------------------------------------------------

    /// @brief Defines the syscall index for bf_vps_op_read16
    constexpr bsl::safe_uint64 BF_VPS_OP_READ16_IDX_VAL{bsl::to_u64(0x0000000000000004U)};

    /// <!-- description -->
    ///   @brief Reads a 16bit field from the VPS. The "index" is architecture
    ///     specific. For Intel, the index (or encoding) is the defined in
    ///     Appendix B "Field Encoding in VMCS". For AMD, the index (or offset)
    ///     is defined in Appendix B "Layout of VMCB".
    ///
    /// <!-- inputs/outputs -->
    ///   @param handle Set to the result of bf_handle_op_open_handle
    ///   @param vpsid The VPSID of the VPS to read from
    ///   @param index The HVE specific index defining which field to read
    ///   @param value The resulting value
    ///   @return Returns the bf_status_t result of the syscall. See the
    ///     specification for more information about error codes.
    ///
    [[nodiscard]] inline auto
    bf_vps_op_read16(                     // --
        bf_handle_t const &handle,        // --
        bsl::safe_uint16 const &vpsid,    // --
        bsl::safe_uint64 const &index,    // --
        bsl::safe_uint16 &value) noexcept -> bf_status_t
    {
        return {bf_vps_op_read16_impl(handle.hndl, vpsid.get(), index.get(), value.data())};
    }

    // -------------------------------------------------------------------------
    // bf_vps_op_read32
    // -------------------------------------------------------------------------

    /// @brief Defines the syscall index for bf_vps_op_read32
    constexpr bsl::safe_uint64 BF_VPS_OP_READ32_IDX_VAL{bsl::to_u64(0x0000000000000005U)};

    /// <!-- description -->
    ///   @brief Reads a 32bit field from the VPS. The "index" is architecture
    ///     specific. For Intel, the index (or encoding) is the defined in
    ///     Appendix B "Field Encoding in VMCS". For AMD, the index (or offset)
    ///     is defined in Appendix B "Layout of VMCB".
    ///
    /// <!-- inputs/outputs -->
    ///   @param handle Set to the result of bf_handle_op_open_handle
    ///   @param vpsid The VPSID of the VPS to read from
    ///   @param index The HVE specific index defining which field to read
    ///   @param value The resulting value
    ///   @return Returns the bf_status_t result of the syscall. See the
    ///     specification for more information about error codes.
    ///
    [[nodiscard]] inline auto
    bf_vps_op_read32(                     // --
        bf_handle_t const &handle,        // --
        bsl::safe_uint16 const &vpsid,    // --
        bsl::safe_uint64 const &index,    // --
        bsl::safe_uint32 &value) noexcept -> bf_status_t
    {
        return {bf_vps_op_read32_impl(handle.hndl, vpsid.get(), index.get(), value.data())};
    }

    // -------------------------------------------------------------------------
    // bf_vps_op_read64
    // -------------------------------------------------------------------------

    /// @brief Defines the syscall index for bf_vps_op_read64
    constexpr bsl::safe_uint64 BF_VPS_OP_READ64_IDX_VAL{bsl::to_u64(0x0000000000000006U)};

    /// <!-- description -->
    ///   @brief Reads an 64bit field from the VPS. The "index" is architecture
    ///     specific. For Intel, the index (or encoding) is the defined in
    ///     Appendix B "Field Encoding in VMCS". For AMD, the index (or offset)
    ///     is defined in Appendix B "Layout of VMCB".
    ///
    /// <!-- inputs/outputs -->
    ///   @param handle Set to the result of bf_handle_op_open_handle
    ///   @param vpsid The VPSID of the VPS to read from
    ///   @param index The HVE specific index defining which field to read
    ///   @param value The resulting value
    ///   @return Returns the bf_status_t result of the syscall. See the
    ///     specification for more information about error codes.
    ///
    [[nodiscard]] inline auto
    bf_vps_op_read64(                     // --
        bf_handle_t const &handle,        // --
        bsl::safe_uint16 const &vpsid,    // --
        bsl::safe_uint64 const &index,    // --
        bsl::safe_uint64 &value) noexcept -> bf_status_t
    {
        return {bf_vps_op_read64_impl(handle.hndl, vpsid.get(), index.get(), value.data())};
    }

    // -------------------------------------------------------------------------
    // bf_vps_op_write8
    // -------------------------------------------------------------------------

    /// @brief Defines the syscall index for bf_vps_op_write
    constexpr bsl::safe_uint64 BF_VPS_OP_WRITE8_IDX_VAL{bsl::to_u64(0x0000000000000007U)};

    /// <!-- description -->
    ///   @brief Writes to an 8bit field in the VPS. The "index" is architecture
    ///     specific. For Intel, the index (or encoding) is the defined in
    ///     Appendix B "Field Encoding in VMCS". For AMD, the index (or offset)
    ///     is defined in Appendix B "Layout of VMCB".
    ///
    /// <!-- inputs/outputs -->
    ///   @param handle Set to the result of bf_handle_op_open_handle
    ///   @param vpsid The VPSID of the VPS to write to
    ///   @param index The HVE specific index defining which field to write to
    ///   @param value The value to write to the requested field
    ///   @return Returns the bf_status_t result of the syscall. See the
    ///     specification for more information about error codes.
    ///
    [[nodiscard]] inline auto
    bf_vps_op_write8(                     // --
        bf_handle_t const &handle,        // --
        bsl::safe_uint16 const &vpsid,    // --
        bsl::safe_uint64 const &index,    // --
        bsl::safe_uint8 const &value) noexcept -> bf_status_t
    {
        return {bf_vps_op_write8_impl(handle.hndl, vpsid.get(), index.get(), value.get())};
    }

    // -------------------------------------------------------------------------
    // bf_vps_op_write16
    // -------------------------------------------------------------------------

    /// @brief Defines the syscall index for bf_vps_op_write
    constexpr bsl::safe_uint64 BF_VPS_OP_WRITE16_IDX_VAL{bsl::to_u64(0x0000000000000008U)};

    /// <!-- description -->
    ///   @brief Writes to a 16bit field in the VPS. The "index" is architecture
    ///     specific. For Intel, the index (or encoding) is the defined in
    ///     Appendix B "Field Encoding in VMCS". For AMD, the index (or offset)
    ///     is defined in Appendix B "Layout of VMCB".
    ///
    /// <!-- inputs/outputs -->
    ///   @param handle Set to the result of bf_handle_op_open_handle
    ///   @param vpsid The VPSID of the VPS to write to
    ///   @param index The HVE specific index defining which field to write to
    ///   @param value The value to write to the requested field
    ///   @return Returns the bf_status_t result of the syscall. See the
    ///     specification for more information about error codes.
    ///
    [[nodiscard]] inline auto
    bf_vps_op_write16(                    // --
        bf_handle_t const &handle,        // --
        bsl::safe_uint16 const &vpsid,    // --
        bsl::safe_uint64 const &index,    // --
        bsl::safe_uint16 const &value) noexcept -> bf_status_t
    {
        return {bf_vps_op_write16_impl(handle.hndl, vpsid.get(), index.get(), value.get())};
    }

    // -------------------------------------------------------------------------
    // bf_vps_op_write32
    // -------------------------------------------------------------------------

    /// @brief Defines the syscall index for bf_vps_op_write
    constexpr bsl::safe_uint64 BF_VPS_OP_WRITE32_IDX_VAL{bsl::to_u64(0x0000000000000009U)};

    /// <!-- description -->
    ///   @brief Writes to a 32bit field in the VPS. The "index" is architecture
    ///     specific. For Intel, the index (or encoding) is the defined in
    ///     Appendix B "Field Encoding in VMCS". For AMD, the index (or offset)
    ///     is defined in Appendix B "Layout of VMCB".
    ///
    /// <!-- inputs/outputs -->
    ///   @param handle Set to the result of bf_handle_op_open_handle
    ///   @param vpsid The VPSID of the VPS to write to
    ///   @param index The HVE specific index defining which field to write to
    ///   @param value The value to write to the requested field
    ///   @return Returns the bf_status_t result of the syscall. See the
    ///     specification for more information about error codes.
    ///
    [[nodiscard]] inline auto
    bf_vps_op_write32(                    // --
        bf_handle_t const &handle,        // --
        bsl::safe_uint16 const &vpsid,    // --
        bsl::safe_uint64 const &index,    // --
        bsl::safe_uint32 const &value) noexcept -> bf_status_t
    {
        return {bf_vps_op_write32_impl(handle.hndl, vpsid.get(), index.get(), value.get())};
    }

    // -------------------------------------------------------------------------
    // bf_vps_op_write64
    // -------------------------------------------------------------------------

    /// @brief Defines the syscall index for bf_vps_op_write
    constexpr bsl::safe_uint64 BF_VPS_OP_WRITE64_IDX_VAL{bsl::to_u64(0x000000000000000AU)};

    /// <!-- description -->
    ///   @brief Writes to a 64bit field in the VPS. The "index" is architecture
    ///     specific. For Intel, the index (or encoding) is the defined in
    ///     Appendix B "Field Encoding in VMCS". For AMD, the index (or offset)
    ///     is defined in Appendix B "Layout of VMCB".
    ///
    /// <!-- inputs/outputs -->
    ///   @param handle Set to the result of bf_handle_op_open_handle
    ///   @param vpsid The VPSID of the VPS to write to
    ///   @param index The HVE specific index defining which field to write to
    ///   @param value The value to write to the requested field
    ///   @return Returns the bf_status_t result of the syscall. See the
    ///     specification for more information about error codes.
    ///
    [[nodiscard]] inline auto
    bf_vps_op_write64(                    // --
        bf_handle_t const &handle,        // --
        bsl::safe_uint16 const &vpsid,    // --
        bsl::safe_uint64 const &index,    // --
        bsl::safe_uint64 const &value) noexcept -> bf_status_t
    {
        return {bf_vps_op_write64_impl(handle.hndl, vpsid.get(), index.get(), value.get())};
    }

    // -------------------------------------------------------------------------
    // bf_vps_op_read_reg
    // -------------------------------------------------------------------------

    /// @brief Defines the syscall index for bf_vps_op_read_reg
    constexpr bsl::safe_uint64 BF_VPS_OP_READ_REG_IDX_VAL{bsl::to_u64(0x000000000000000BU)};

    /// <!-- description -->
    ///   @brief Reads a CPU register from the VPS given a bf_reg_t. Note
    ///     that the bf_reg_t is architecture specific.
    ///
    /// <!-- inputs/outputs -->
    ///   @param handle Set to the result of bf_handle_op_open_handle
    ///   @param vpsid The VPSID of the VPS to read from
    ///   @param reg A bf_reg_t defining which register to read
    ///   @param value The resulting value
    ///   @return Returns the bf_status_t result of the syscall. See the
    ///     specification for more information about error codes.
    ///
    [[nodiscard]] inline auto
    bf_vps_op_read_reg(                   // --
        bf_handle_t const &handle,        // --
        bsl::safe_uint16 const &vpsid,    // --
        bf_reg_t const reg,               // --
        bsl::safe_uint64 &value) noexcept -> bf_status_t
    {
        return {bf_vps_op_read_reg_impl(handle.hndl, vpsid.get(), reg, value.data())};
    }

    // -------------------------------------------------------------------------
    // bf_vps_op_write_reg
    // -------------------------------------------------------------------------

    /// @brief Defines the syscall index for bf_vps_op_write_reg
    constexpr bsl::safe_uint64 BF_VPS_OP_WRITE_REG_IDX_VAL{bsl::to_u64(0x000000000000000CU)};

    /// <!-- description -->
    ///   @brief Writes to a CPU register in the VPS given a bf_reg_t and the
    ///     value to write. Note that the bf_reg_t is architecture specific.
    ///
    /// <!-- inputs/outputs -->
    ///   @param handle Set to the result of bf_handle_op_open_handle
    ///   @param vpsid The VPSID of the VPS to write to
    ///   @param reg A bf_reg_t defining which register to write to
    ///   @param value The value to write to the requested register
    ///   @return Returns the bf_status_t result of the syscall. See the
    ///     specification for more information about error codes.
    ///
    [[nodiscard]] inline auto
    bf_vps_op_write_reg(                  // --
        bf_handle_t const &handle,        // --
        bsl::safe_uint16 const &vpsid,    // --
        bf_reg_t const reg,               // --
        bsl::safe_uint64 const &value) noexcept -> bf_status_t
    {
        return {bf_vps_op_write_reg_impl(handle.hndl, vpsid.get(), reg, value.get())};
    }

    // -------------------------------------------------------------------------
    // bf_vps_op_run
    // -------------------------------------------------------------------------

    /// @brief Defines the syscall index for bf_vps_op_run
    constexpr bsl::safe_uint64 BF_VPS_OP_RUN_IDX_VAL{bsl::to_u64(0x000000000000000DU)};

    /// <!-- description -->
    ///   @brief This syscall tells the microkernel to run a VP on behalf
    ///     of a given VM by executing the VP with a given VPS. This system
    ///     call only returns if an error occurs. On success, this system
    ///     call will physically execute the requested VP using the requested
    ///     VPS, and the extension will only execute again on the next VMExit.
    ///
    /// <!-- inputs/outputs -->
    ///   @param handle Set to the result of bf_handle_op_open_handle
    ///   @param vpsid The VPSID of the VPS to run
    ///   @param vpid The VPID of the VP to run
    ///   @param vmid The VMID of the VM to run
    ///   @return Returns the bf_status_t result of the syscall. See the
    ///     specification for more information about error codes.
    ///
    [[nodiscard]] inline auto
    bf_vps_op_run(                        // --
        bf_handle_t const &handle,        // --
        bsl::safe_uint16 const &vpsid,    // --
        bsl::safe_uint16 const &vpid,     // --
        bsl::safe_uint16 const &vmid) noexcept -> bf_status_t
    {
        return {bf_vps_op_run_impl(handle.hndl, vpsid.get(), vpid.get(), vmid.get())};
    }

    // -------------------------------------------------------------------------
    // bf_vps_op_run_current
    // -------------------------------------------------------------------------

    /// @brief Defines the syscall index for bf_vps_op_run_current
    constexpr bsl::safe_uint64 BF_VPS_OP_RUN_CURRENT_IDX_VAL{bsl::to_u64(0x000000000000000EU)};

    /// <!-- description -->
    ///   @brief bf_vps_op_run_current tells the microkernel to execute the
    ///     currently active VPS, VP and VM.
    ///
    /// <!-- inputs/outputs -->
    ///   @param handle Set to the result of bf_handle_op_open_handle
    ///   @return Returns the bf_status_t result of the syscall. See the
    ///     specification for more information about error codes.
    ///
    [[nodiscard]] inline auto
    bf_vps_op_run_current(    // --
        bf_handle_t const &handle) noexcept -> bf_status_t
    {
        return {bf_vps_op_run_current_impl(handle.hndl)};
    }

    // -------------------------------------------------------------------------
    // bf_vps_op_advance_ip
    // -------------------------------------------------------------------------

    /// @brief Defines the syscall index for bf_vps_op_advance_ip
    constexpr bsl::safe_uint64 BF_VPS_OP_ADVANCE_IP_IDX_VAL{bsl::to_u64(0x000000000000000FU)};

    /// <!-- description -->
    ///   @brief This syscall tells the microkernel to advance the instruction
    ///     pointer in the requested VPS.
    ///
    /// <!-- inputs/outputs -->
    ///   @param handle Set to the result of bf_handle_op_open_handle
    ///   @param vpsid The VPSID of the VPS advance the IP in
    ///   @return Returns the bf_status_t result of the syscall. See the
    ///     specification for more information about error codes.
    ///
    [[nodiscard]] inline auto
    bf_vps_op_advance_ip(             // --
        bf_handle_t const &handle,    // --
        bsl::safe_uint16 const &vpsid) noexcept -> bf_status_t
    {
        return {bf_vps_op_advance_ip_impl(handle.hndl, vpsid.get())};
    }

    // -------------------------------------------------------------------------
    // bf_vps_op_advance_ip_and_run_current
    // -------------------------------------------------------------------------

    /// @brief Defines the syscall index for bf_vps_op_advance_ip_and_run_current
    constexpr bsl::safe_uint64 BF_VPS_OP_ADVANCE_IP_AND_RUN_CURRENT_IDX_VAL{
        bsl::to_u64(0x0000000000000010U)};

    /// <!-- description -->
    ///   @brief This syscall tells the microkernel to advance the instruction
    ///     pointer in the requested VPS and run the currently active VPS, VP
    ///     and VM (i.e., this combines bf_vps_op_advance_ip and
    ///     bf_vps_op_advance_ip).
    ///
    /// <!-- inputs/outputs -->
    ///   @param handle Set to the result of bf_handle_op_open_handle
    ///   @return Returns the bf_status_t result of the syscall. See the
    ///     specification for more information about error codes.
    ///
    [[nodiscard]] inline auto
    bf_vps_op_advance_ip_and_run_current(    // --
        bf_handle_t const &handle) noexcept -> bf_status_t
    {
        return {bf_vps_op_advance_ip_and_run_current_impl(handle.hndl)};
    }

    // -------------------------------------------------------------------------
    // bf_vps_op_promote
    // -------------------------------------------------------------------------

    /// @brief Defines the syscall index for bf_vps_op_promote
    constexpr bsl::safe_uint64 BF_VPS_OP_PROMOTE_IDX_VAL{bsl::to_u64(0x0000000000000011U)};

    /// <!-- description -->
    ///   @brief This syscall tells the microkernel to promote the requested
    ///     VPS. This will stop the hypervisor complete on the physical
    ///     processor that this syscall is executed on and replace it's state
    ///     with the state in the VPS. Note that this syscall only returns
    ///     on error.
    ///
    /// <!-- inputs/outputs -->
    ///   @param handle Set to the result of bf_handle_op_open_handle
    ///   @param vpsid The VPSID of the VPS to promote
    ///
    inline void
    bf_vps_op_promote(                // --
        bf_handle_t const &handle,    // --
        bsl::safe_uint16 const &vpsid) noexcept
    {
        bf_vps_op_promote_impl(handle.hndl, vpsid.get());
    }

    // -------------------------------------------------------------------------
    // bf_intrinsic_op_read_msr
    // -------------------------------------------------------------------------

    /// @brief Defines the syscall index for bf_intrinsic_op_read_msr
    constexpr bsl::safe_uint64 BF_INTRINSIC_OP_READ_MSR_IDX_VAL{bsl::to_u64(0x0000000000000000U)};

    /// <!-- description -->
    ///   @brief Reads an MSR directly from the CPU given the address of
    ///     the MSR to read. Note that this is specific to Intel/AMD only.
    ///     Also note that not all MSRs can be read, and which MSRs that
    ///     can be read is up to the microkernel's internal policy as well
    ///     as which architecture the hypervisor is running on.
    ///
    /// <!-- inputs/outputs -->
    ///   @param handle Set to the result of bf_handle_op_open_handle
    ///   @param msr The address of the MSR to read
    ///   @param value The resulting value
    ///   @return Returns the bf_status_t result of the syscall. See the
    ///     specification for more information about error codes.
    ///
    [[nodiscard]] inline auto
    bf_intrinsic_op_read_msr(           // --
        bf_handle_t const &handle,      // --
        bsl::safe_uint32 const &msr,    // --
        bsl::safe_uint64 &value) noexcept -> bf_status_t
    {
        return {bf_intrinsic_op_read_msr_impl(handle.hndl, msr.get(), value.data())};
    }

    // -------------------------------------------------------------------------
    // bf_intrinsic_op_write_msr
    // -------------------------------------------------------------------------

    /// @brief Defines the syscall index for bf_intrinsic_op_write_msr
    constexpr bsl::safe_uint64 BF_INTRINSIC_OP_WRITE_MSR_IDX_VAL{bsl::to_u64(0x0000000000000001U)};

    /// <!-- description -->
    ///   @brief Writes to an MSR directly from the CPU given the address of
    ///     the MSR to write as well as the value to write. Note that this is
    ///     specific to Intel/AMD only. Also note that not all MSRs can be
    ///     written to, and which MSRs that can be written to is up to the
    ///     microkernel's internal policy as well as which architecture the
    ///     hypervisor is running on.
    ///
    /// <!-- inputs/outputs -->
    ///   @param handle Set to the result of bf_handle_op_open_handle
    ///   @param msr The address of the MSR to write to
    ///   @param value The value to write to the requested MSR
    ///   @return Returns the bf_status_t result of the syscall. See the
    ///     specification for more information about error codes.
    ///
    [[nodiscard]] inline auto
    bf_intrinsic_op_write_msr(          // --
        bf_handle_t const &handle,      // --
        bsl::safe_uint32 const &msr,    // --
        bsl::safe_uint64 const &value) noexcept -> bf_status_t
    {
        return {bf_intrinsic_op_write_msr_impl(handle.hndl, msr.get(), value.get())};
    }

    // -------------------------------------------------------------------------
    // bf_mem_op_alloc_page
    // -------------------------------------------------------------------------

    /// @brief Defines the syscall index for bf_mem_op_alloc_page
    constexpr bsl::safe_uint64 BF_MEM_OP_ALLOC_PAGE_IDX_VAL{bsl::to_u64(0x0000000000000000U)};

    /// <!-- description -->
    ///   @brief Allocates a page. When a page is allocated, it is removed
    ///     from the micorkernel's direct map, and placed into the extension's
    ///     direct map. This ensures the extension is free to use an allocated
    ///     page to store secrets, and extensions can also convert the virtual
    ///     address of the page to a physical page and back without issue.
    ///     Note that not all memory allocations (e.g., the heap) work this
    ///     way. Extensions should use caution when storing secrets.
    ///
    /// <!-- inputs/outputs -->
    ///   @param handle Set to the result of bf_handle_op_open_handle
    ///   @param virt The virtual address of the resulting page
    ///   @param phys The physical address of the resulting page
    ///   @return Returns the bf_status_t result of the syscall. See the
    ///     specification for more information about error codes.
    ///
    [[nodiscard]] inline auto
    bf_mem_op_alloc_page(             // --
        bf_handle_t const &handle,    // --
        bf_ptr_t &virt,               // --
        bsl::safe_uint64 &phys) noexcept -> bf_status_t
    {
        return {bf_mem_op_alloc_page_impl(handle.hndl, &virt, phys.data())};
    }

    // -------------------------------------------------------------------------
    // bf_mem_op_virt_to_phys
    // -------------------------------------------------------------------------

    /// @brief Defines the syscall index for bf_mem_op_virt_to_phys
    constexpr bsl::safe_uint64 BF_MEM_OP_VIRT_TO_PHYS_IDX_VAL{bsl::to_u64(0x0000000000000006U)};

    /// <!-- description -->
    ///   @brief bf_mem_op_virt_to_phys converts a provided virtual address
    ///     to a physical address for any virtual address allocated using
    ///     bf_mem_op_alloc_page, bf_mem_op_alloc_huge, bf_mem_op_alloc_heap
    ///     or mapped using the direct map.
    ///
    /// <!-- inputs/outputs -->
    ///   @param handle Set to the result of bf_handle_op_open_handle
    ///   @param virt The virtual address of the page to convert
    ///   @param phys The physical address of the provided virtual address
    ///   @return Returns the bf_status_t result of the syscall. See the
    ///     specification for more information about error codes.
    ///
    [[nodiscard]] inline auto
    bf_mem_op_virt_to_phys(           // --
        bf_handle_t const &handle,    // --
        bf_ptr_t const virt,          // --
        bsl::safe_uint64 &phys) noexcept -> bf_status_t
    {
        return {bf_mem_op_virt_to_phys_impl(handle.hndl, virt, phys.data())};
    }
}

#endif
