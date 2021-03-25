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

#ifndef BF_SYSCALL_T_HPP
#define BF_SYSCALL_T_HPP

#include <bf_constants.hpp>
#include <bf_reg_t.hpp>
#include <bf_syscall_impl.hpp>
#include <bf_types.hpp>

#include <bsl/debug.hpp>
#include <bsl/errc_type.hpp>
#include <bsl/finally_assert.hpp>
#include <bsl/is_unsigned.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/unlikely.hpp>
#include <bsl/unlikely_assert.hpp>

namespace syscall
{
    /// @class syscall::bf_syscall_t
    ///
    /// <!-- description -->
    ///   @brief Provides an API wrapper around all of the microkernel ABIs.
    ///     For more information about these APIs, please see the Microkernel
    ///     ABI Specification.
    ///
    ///
    class bf_syscall_t final
    {
        /// @brief stores the handle used for making syscalls.
        bf_uint64_t m_hndl{};

    public:
        /// <!-- description -->
        ///   @brief Initializes the bf_syscall_t by opening a handle and
        ///     registering all of the required handlers. If this function
        ///     fails, the handle is closed automatically.
        ///
        /// <!-- inputs/outputs -->
        ///   @param version the version provided to the extension by the
        ///     microkernel. If this API does not support the ABI versions
        ///     that the microkernel supports, this function will fail.
        ///   @param bootstrap_handler the bootstrap handler to register
        ///   @param vmexit_handler the vmexit handler to register
        ///   @param fail_handler the fail handler to register
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        initialize(
            bf_uint32_t const &version,
            bf_callback_handler_bootstrap_t const bootstrap_handler,
            bf_callback_handler_vmexit_t const vmexit_handler,
            bf_callback_handler_fail_t const fail_handler) noexcept -> bsl::errc_type
        {
            bf_status_t ret{};

            if (bsl::unlikely_assert(!version)) {
                bsl::error() << "invalid version\n" << bsl::here();
                return bsl::errc_invalid_argument;
            }

            if (bsl::unlikely_assert(version.is_zero())) {
                bsl::error() << "version cannot be zero\n" << bsl::here();
                return bsl::errc_invalid_argument;
            }

            if (bsl::unlikely_assert(nullptr == bootstrap_handler)) {
                bsl::error() << "invalid bootstrap_handler\n" << bsl::here();
                return bsl::errc_invalid_argument;
            }

            if (bsl::unlikely_assert(nullptr == vmexit_handler)) {
                bsl::error() << "invalid vmexit_handler\n" << bsl::here();
                return bsl::errc_invalid_argument;
            }

            if (bsl::unlikely_assert(nullptr == fail_handler)) {
                bsl::error() << "invalid fail_handler\n" << bsl::here();
                return bsl::errc_invalid_argument;
            }

            if (bsl::unlikely(!bf_is_spec1_supported(version))) {
                bsl::error() << "unsupported microkernel "    // --
                             << bsl::hex(version)             // --
                             << bsl::endl                     // --
                             << bsl::here();

                return bsl::errc_unsupported;
            }

            ret = bf_handle_op_open_handle_impl(BF_SPEC_ID1_VAL.get(), m_hndl.data());
            if (bsl::unlikely_assert(ret != BF_STATUS_SUCCESS)) {
                bsl::error() << "bf_handle_op_open_handle_impl failed with status "    // --
                             << bsl::hex(ret)                                          // --
                             << bsl::endl                                              // --
                             << bsl::here();

                return bsl::errc_failure;
            }

            bsl::finally_assert release_on_error{[this]() noexcept -> void {
                this->release();
            }};

            ret = bf_callback_op_register_bootstrap_impl(m_hndl.get(), bootstrap_handler);
            if (bsl::unlikely_assert(ret != BF_STATUS_SUCCESS)) {
                bsl::error() << "bf_callback_op_register_bootstrap failed with status "    // --
                             << bsl::hex(ret)                                              // --
                             << bsl::endl                                                  // --
                             << bsl::here();

                return bsl::errc_failure;
            }

            ret = bf_callback_op_register_vmexit_impl(m_hndl.get(), vmexit_handler);
            if (bsl::unlikely_assert(ret != BF_STATUS_SUCCESS)) {
                bsl::error() << "bf_callback_op_register_vmexit failed with status "    // --
                             << bsl::hex(ret)                                           // --
                             << bsl::endl                                               // --
                             << bsl::here();

                return bsl::errc_failure;
            }

            ret = bf_callback_op_register_fail_impl(m_hndl.get(), fail_handler);
            if (bsl::unlikely_assert(ret != BF_STATUS_SUCCESS)) {
                bsl::error() << "bf_callback_op_register_fail failed with status "    // --
                             << bsl::hex(ret)                                         // --
                             << bsl::endl                                             // --
                             << bsl::here();

                return bsl::errc_failure;
            }

            release_on_error.ignore();
            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Releases the bf_syscall_t by closing the handle.
        ///
        constexpr void
        release() noexcept
        {
            bsl::discard(bf_handle_op_close_handle_impl(m_hndl.get()));
            m_hndl = {};
        }

        // ---------------------------------------------------------------------
        // TLS ops
        // ---------------------------------------------------------------------

        /// <!-- description -->
        ///   @brief Returns the value of tls.rax
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the value of tls.rax
        ///
        [[nodiscard]] static constexpr auto
        bf_tls_rax() noexcept -> bf_uint64_t
        {
            return bf_tls_rax_impl();
        }

        /// <!-- description -->
        ///   @brief Sets the value of tls.rax
        ///
        /// <!-- inputs/outputs -->
        ///   @param val The value to set tls.rax to
        ///
        static constexpr void
        bf_tls_set_rax(bf_uint64_t const &val) noexcept
        {
            if (bsl::unlikely_assert(!val)) {
                bsl::alert() << "invalid val\n" << bsl::here();
                return;
            }

            bf_tls_set_rax_impl(val.get());
        }

        /// <!-- description -->
        ///   @brief Returns the value of tls.rbx
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the value of tls.rbx
        ///
        [[nodiscard]] static constexpr auto
        bf_tls_rbx() noexcept -> bf_uint64_t
        {
            return bf_tls_rbx_impl();
        }

        /// <!-- description -->
        ///   @brief Sets the value of tls.rbx
        ///
        /// <!-- inputs/outputs -->
        ///   @param val The value to set tls.rbx to
        ///
        static constexpr void
        bf_tls_set_rbx(bf_uint64_t const &val) noexcept
        {
            if (bsl::unlikely_assert(!val)) {
                bsl::alert() << "invalid val\n" << bsl::here();
                return;
            }

            bf_tls_set_rbx_impl(val.get());
        }

        /// <!-- description -->
        ///   @brief Returns the value of tls.rcx
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the value of tls.rcx
        ///
        [[nodiscard]] static constexpr auto
        bf_tls_rcx() noexcept -> bf_uint64_t
        {
            return bf_tls_rcx_impl();
        }

        /// <!-- description -->
        ///   @brief Sets the value of tls.rcx
        ///
        /// <!-- inputs/outputs -->
        ///   @param val The value to set tls.rcx to
        ///
        static constexpr void
        bf_tls_set_rcx(bf_uint64_t const &val) noexcept
        {
            if (bsl::unlikely_assert(!val)) {
                bsl::alert() << "invalid val\n" << bsl::here();
                return;
            }

            bf_tls_set_rcx_impl(val.get());
        }

        /// <!-- description -->
        ///   @brief Returns the value of tls.rdx
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the value of tls.rdx
        ///
        [[nodiscard]] static constexpr auto
        bf_tls_rdx() noexcept -> bf_uint64_t
        {
            return bf_tls_rdx_impl();
        }

        /// <!-- description -->
        ///   @brief Sets the value of tls.rdx
        ///
        /// <!-- inputs/outputs -->
        ///   @param val The value to set tls.rdx to
        ///
        static constexpr void
        bf_tls_set_rdx(bf_uint64_t const &val) noexcept
        {
            if (bsl::unlikely_assert(!val)) {
                bsl::alert() << "invalid val\n" << bsl::here();
                return;
            }

            bf_tls_set_rdx_impl(val.get());
        }

        /// <!-- description -->
        ///   @brief Returns the value of tls.rbp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the value of tls.rbp
        ///
        [[nodiscard]] static constexpr auto
        bf_tls_rbp() noexcept -> bf_uint64_t
        {
            return bf_tls_rbp_impl();
        }

        /// <!-- description -->
        ///   @brief Sets the value of tls.rbp
        ///
        /// <!-- inputs/outputs -->
        ///   @param val The value to set tls.rbp to
        ///
        static constexpr void
        bf_tls_set_rbp(bf_uint64_t const &val) noexcept
        {
            if (bsl::unlikely_assert(!val)) {
                bsl::alert() << "invalid val\n" << bsl::here();
                return;
            }

            bf_tls_set_rbp_impl(val.get());
        }

        /// <!-- description -->
        ///   @brief Returns the value of tls.rsi
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the value of tls.rsi
        ///
        [[nodiscard]] static constexpr auto
        bf_tls_rsi() noexcept -> bf_uint64_t
        {
            return bf_tls_rsi_impl();
        }

        /// <!-- description -->
        ///   @brief Sets the value of tls.rsi
        ///
        /// <!-- inputs/outputs -->
        ///   @param val The value to set tls.rsi to
        ///
        static constexpr void
        bf_tls_set_rsi(bf_uint64_t const &val) noexcept
        {
            if (bsl::unlikely_assert(!val)) {
                bsl::alert() << "invalid val\n" << bsl::here();
                return;
            }

            bf_tls_set_rsi_impl(val.get());
        }

        /// <!-- description -->
        ///   @brief Returns the value of tls.rdi
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the value of tls.rdi
        ///
        [[nodiscard]] static constexpr auto
        bf_tls_rdi() noexcept -> bf_uint64_t
        {
            return bf_tls_rdi_impl();
        }

        /// <!-- description -->
        ///   @brief Sets the value of tls.rdi
        ///
        /// <!-- inputs/outputs -->
        ///   @param val The value to set tls.rdi to
        ///
        static constexpr void
        bf_tls_set_rdi(bf_uint64_t const &val) noexcept
        {
            if (bsl::unlikely_assert(!val)) {
                bsl::alert() << "invalid val\n" << bsl::here();
                return;
            }

            bf_tls_set_rdi_impl(val.get());
        }

        /// <!-- description -->
        ///   @brief Returns the value of tls.r8
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the value of tls.r8
        ///
        [[nodiscard]] static constexpr auto
        bf_tls_r8() noexcept -> bf_uint64_t
        {
            return bf_tls_r8_impl();
        }

        /// <!-- description -->
        ///   @brief Sets the value of tls.r8
        ///
        /// <!-- inputs/outputs -->
        ///   @param val The value to set tls.r8 to
        ///
        static constexpr void
        bf_tls_set_r8(bf_uint64_t const &val) noexcept
        {
            if (bsl::unlikely_assert(!val)) {
                bsl::alert() << "invalid val\n" << bsl::here();
                return;
            }

            bf_tls_set_r8_impl(val.get());
        }

        /// <!-- description -->
        ///   @brief Returns the value of tls.r9
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the value of tls.r9
        ///
        [[nodiscard]] static constexpr auto
        bf_tls_r9() noexcept -> bf_uint64_t
        {
            return bf_tls_r9_impl();
        }

        /// <!-- description -->
        ///   @brief Sets the value of tls.r9
        ///
        /// <!-- inputs/outputs -->
        ///   @param val The value to set tls.r9 to
        ///
        static constexpr void
        bf_tls_set_r9(bf_uint64_t const &val) noexcept
        {
            if (bsl::unlikely_assert(!val)) {
                bsl::alert() << "invalid val\n" << bsl::here();
                return;
            }

            bf_tls_set_r9_impl(val.get());
        }

        /// <!-- description -->
        ///   @brief Returns the value of tls.r10
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the value of tls.r10
        ///
        [[nodiscard]] static constexpr auto
        bf_tls_r10() noexcept -> bf_uint64_t
        {
            return bf_tls_r10_impl();
        }

        /// <!-- description -->
        ///   @brief Sets the value of tls.r10
        ///
        /// <!-- inputs/outputs -->
        ///   @param val The value to set tls.r10 to
        ///
        static constexpr void
        bf_tls_set_r10(bf_uint64_t const &val) noexcept
        {
            if (bsl::unlikely_assert(!val)) {
                bsl::alert() << "invalid val\n" << bsl::here();
                return;
            }

            bf_tls_set_r10_impl(val.get());
        }

        /// <!-- description -->
        ///   @brief Returns the value of tls.r11
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the value of tls.r11
        ///
        [[nodiscard]] static constexpr auto
        bf_tls_r11() noexcept -> bf_uint64_t
        {
            return bf_tls_r11_impl();
        }

        /// <!-- description -->
        ///   @brief Sets the value of tls.r11
        ///
        /// <!-- inputs/outputs -->
        ///   @param val The value to set tls.r11 to
        ///
        static constexpr void
        bf_tls_set_r11(bf_uint64_t const &val) noexcept
        {
            if (bsl::unlikely_assert(!val)) {
                bsl::alert() << "invalid val\n" << bsl::here();
                return;
            }

            bf_tls_set_r11_impl(val.get());
        }

        /// <!-- description -->
        ///   @brief Returns the value of tls.r12
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the value of tls.r12
        ///
        [[nodiscard]] static constexpr auto
        bf_tls_r12() noexcept -> bf_uint64_t
        {
            return bf_tls_r12_impl();
        }

        /// <!-- description -->
        ///   @brief Sets the value of tls.r12
        ///
        /// <!-- inputs/outputs -->
        ///   @param val The value to set tls.r12 to
        ///
        static constexpr void
        bf_tls_set_r12(bf_uint64_t const &val) noexcept
        {
            if (bsl::unlikely_assert(!val)) {
                bsl::alert() << "invalid val\n" << bsl::here();
                return;
            }

            bf_tls_set_r12_impl(val.get());
        }

        /// <!-- description -->
        ///   @brief Returns the value of tls.r13
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the value of tls.r13
        ///
        [[nodiscard]] static constexpr auto
        bf_tls_r13() noexcept -> bf_uint64_t
        {
            return bf_tls_r13_impl();
        }

        /// <!-- description -->
        ///   @brief Sets the value of tls.r13
        ///
        /// <!-- inputs/outputs -->
        ///   @param val The value to set tls.r13 to
        ///
        static constexpr void
        bf_tls_set_r13(bf_uint64_t const &val) noexcept
        {
            if (bsl::unlikely_assert(!val)) {
                bsl::alert() << "invalid val\n" << bsl::here();
                return;
            }

            bf_tls_set_r13_impl(val.get());
        }

        /// <!-- description -->
        ///   @brief Returns the value of tls.r14
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the value of tls.r14
        ///
        [[nodiscard]] static constexpr auto
        bf_tls_r14() noexcept -> bf_uint64_t
        {
            return bf_tls_r14_impl();
        }

        /// <!-- description -->
        ///   @brief Sets the value of tls.r14
        ///
        /// <!-- inputs/outputs -->
        ///   @param val The value to set tls.r14 to
        ///
        static constexpr void
        bf_tls_set_r14(bf_uint64_t const &val) noexcept
        {
            if (bsl::unlikely_assert(!val)) {
                bsl::alert() << "invalid val\n" << bsl::here();
                return;
            }

            bf_tls_set_r14_impl(val.get());
        }

        /// <!-- description -->
        ///   @brief Returns the value of tls.r15
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the value of tls.r15
        ///
        [[nodiscard]] static constexpr auto
        bf_tls_r15() noexcept -> bf_uint64_t
        {
            return bf_tls_r15_impl();
        }

        /// <!-- description -->
        ///   @brief Sets the value of tls.r15
        ///
        /// <!-- inputs/outputs -->
        ///   @param val The value to set tls.r15 to
        ///
        static constexpr void
        bf_tls_set_r15(bf_uint64_t const &val) noexcept
        {
            if (bsl::unlikely_assert(!val)) {
                bsl::alert() << "invalid val\n" << bsl::here();
                return;
            }

            bf_tls_set_r15_impl(val.get());
        }

        /// <!-- description -->
        ///   @brief Returns the value of tls.extid
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the value of tls.extid
        ///
        [[nodiscard]] static constexpr auto
        bf_tls_extid() noexcept -> bsl::safe_uint16
        {
            return bf_tls_extid_impl();
        }

        /// <!-- description -->
        ///   @brief Returns the value of tls.vmid
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the value of tls.vmid
        ///
        [[nodiscard]] static constexpr auto
        bf_tls_vmid() noexcept -> bsl::safe_uint16
        {
            return bf_tls_vmid_impl();
        }

        /// <!-- description -->
        ///   @brief Returns the value of tls.vpid
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the value of tls.vpid
        ///
        [[nodiscard]] static constexpr auto
        bf_tls_vpid() noexcept -> bsl::safe_uint16
        {
            return bf_tls_vpid_impl();
        }

        /// <!-- description -->
        ///   @brief Returns the value of tls.vpsid
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the value of tls.vpsid
        ///
        [[nodiscard]] static constexpr auto
        bf_tls_vpsid() noexcept -> bsl::safe_uint16
        {
            return bf_tls_vpsid_impl();
        }

        /// <!-- description -->
        ///   @brief Returns the value of tls.ppid
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the value of tls.ppid
        ///
        [[nodiscard]] static constexpr auto
        bf_tls_ppid() noexcept -> bsl::safe_uint16
        {
            return bf_tls_ppid_impl();
        }

        /// <!-- description -->
        ///   @brief Returns the value of tls.online_pps
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the value of tls.online_pps
        ///
        [[nodiscard]] static constexpr auto
        bf_tls_online_pps() noexcept -> bsl::safe_uint16
        {
            return bf_tls_online_pps_impl();
        }

        // ---------------------------------------------------------------------
        // bf_vm_ops
        // ---------------------------------------------------------------------

        /// <!-- description -->
        ///   @brief This syscall tells the microkernel to create a VM
        ///     and return it's ID.
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the resulting ID, or bf_uint16_t::failure()
        ///     on failure.
        ///
        [[nodiscard]] constexpr auto
        bf_vm_op_create_vm() noexcept -> bf_uint16_t
        {
            bf_status_t ret{};
            bf_uint16_t vmid{};

            ret = bf_vm_op_create_vm_impl(m_hndl.get(), vmid.data());
            if (bsl::unlikely(ret != BF_STATUS_SUCCESS)) {
                bsl::error() << "bf_vm_op_create_vm failed with status "    // --
                             << bsl::hex(ret)                               // --
                             << bsl::endl                                   // --
                             << bsl::here();

                return bf_uint16_t::failure();
            }

            return vmid;
        }

        /// <!-- description -->
        ///   @brief This syscall tells the microkernel to destroy a VM
        ///     given an ID.
        ///
        /// <!-- inputs/outputs -->
        ///   @param vmid The VMID of the VM to destroy
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     otherwise
        ///
        [[nodiscard]] constexpr auto
        bf_vm_op_destroy_vm(bf_uint16_t const &vmid) noexcept -> bsl::errc_type
        {
            bf_status_t ret{};

            if (bsl::unlikely_assert(!vmid)) {
                bsl::error() << "invalid vmid\n" << bsl::here();
                return bsl::errc_invalid_argument;
            }

            ret = bf_vm_op_destroy_vm_impl(m_hndl.get(), vmid.get());
            if (bsl::unlikely(ret != BF_STATUS_SUCCESS)) {
                bsl::error() << "bf_vm_op_destroy_vm failed with status "    // --
                             << bsl::hex(ret)                                // --
                             << bsl::endl                                    // --
                             << bsl::here();

                return bsl::errc_failure;
            }

            return bsl::errc_success;
        }

        // ---------------------------------------------------------------------
        // bf_vp_ops
        // ---------------------------------------------------------------------

        /// <!-- description -->
        ///   @brief This syscall tells the microkernel to create a VP given the
        ///     IDs of the VM and PP the VP will be assigned to. Upon success,
        ///     this syscall returns the ID of the newly created VP.
        ///
        /// <!-- inputs/outputs -->
        ///   @param vmid The ID of the VM to assign the newly created VP to
        ///   @param ppid The ID of the PP to assign the newly created VP to
        ///   @return Returns the resulting ID, or bf_uint16_t::failure()
        ///     on failure.
        ///
        ///
        [[nodiscard]] constexpr auto
        bf_vp_op_create_vp(bf_uint16_t const &vmid, bf_uint16_t const &ppid) noexcept -> bf_uint16_t
        {
            bf_status_t ret{};
            bf_uint16_t vpid{};

            if (bsl::unlikely_assert(!vmid)) {
                bsl::error() << "invalid vmid\n" << bsl::here();
                return bf_uint16_t::failure();
            }

            if (bsl::unlikely_assert(!ppid)) {
                bsl::error() << "invalid ppid\n" << bsl::here();
                return bf_uint16_t::failure();
            }

            ret = bf_vp_op_create_vp_impl(m_hndl.get(), vmid.get(), ppid.get(), vpid.data());
            if (bsl::unlikely(ret != BF_STATUS_SUCCESS)) {
                bsl::error() << "bf_vp_op_create_vp failed with status "    // --
                             << bsl::hex(ret)                               // --
                             << bsl::endl                                   // --
                             << bsl::here();

                return bf_uint16_t::failure();
            }

            return vpid;
        }

        /// <!-- description -->
        ///   @brief This syscall tells the microkernel to destroy a VP
        ///     given an ID.
        ///
        /// <!-- inputs/outputs -->
        ///   @param vpid The VPID of the VP to destroy
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     otherwise
        ///
        [[nodiscard]] constexpr auto
        bf_vp_op_destroy_vp(bf_uint16_t const &vpid) noexcept -> bsl::errc_type
        {
            bf_status_t ret{};

            if (bsl::unlikely_assert(!vpid)) {
                bsl::error() << "invalid vpid\n" << bsl::here();
                return bsl::errc_invalid_argument;
            }

            ret = bf_vp_op_destroy_vp_impl(m_hndl.get(), vpid.get());
            if (bsl::unlikely(ret != BF_STATUS_SUCCESS)) {
                bsl::error() << "bf_vp_op_destroy_vp failed with status "    // --
                             << bsl::hex(ret)                                // --
                             << bsl::endl                                    // --
                             << bsl::here();

                return bsl::errc_failure;
            }

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief This syscall tells the microkernel to migrate a VP from one PP
        ///     to another PP. This function does not execute the VP (use
        ///     bf_vps_op_run for that), but instead allows bf_vps_op_run to
        ///     execute a VP on a PP that it was not originally assigned to.
        ///
        ///     When a VP is migrated, all of the VPSs that are assigned to the
        ///     requested VP are also migrated to this new PP as well. From an
        ///     AMD/Intel point of view, this clears the VMCS/VMCB for each VPS
        ///     assigned to the VP. On Intel, it also loads the newly cleared VPS
        ///     and sets the launched state to false, ensuring the next
        ///     bf_vps_op_run will use VMLaunch instead of VMResume.
        ///
        ///     It should be noted that the migration of a VPS from one PP to
        ///     another does not happen during the execution of this ABI. This
        ///     ABI simply tells the microkernel that the requested VP may now
        ///     execute on the requested PP. This will cause a mismatch between
        ///     the assigned PP for a VP and the assigned PP for a VPS. The
        ///     microkernel will detect this mismatch when an extension attempts
        ///     to execute bf_vps_op_run. When this occurs, the microkernel will
        ///     ensure the VP is being run on the PP it was assigned to during
        ///     migration, and then it will check to see if the PP of the VPS
        ///     matches. If it doesn't, it will then perform a migration of that
        ///     VPS at that time. This ensures that the microkernel is only
        ///     migrations VPSs when it needs to, and it ensures the VPS is
        ///     cleared an loaded (in the case of Intel) on the PP it will be
        ///     executed on, which is a requirement for VMCS migration. An
        ///     extension can determine which VPSs have been migrated by looking
        ///     at the assigned PP of a VPS. If it doesn't match the VP it was
        ///     assigned to, it has not been migrated. Finally, an extension is
        ///     free to read/write to the VPSs state, even if it has not been
        ///     migrated. The only requirement for migration is execution (meaning
        ///     VMRun/VMLaunch/VMResume).
        ///
        ///     Any additional migration responsibilities, like TSC
        ///     synchronization, must be performed by the extension.
        ///
        /// <!-- inputs/outputs -->
        ///   @param vpid The VPID of the VP to migrate
        ///   @param ppid The ID of the PP to assign the provided VP to
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     otherwise
        ///
        [[nodiscard]] constexpr auto
        bf_vp_op_migrate(bf_uint16_t const &vpid, bf_uint16_t const &ppid) noexcept
            -> bsl::errc_type
        {
            bf_status_t ret{};

            if (bsl::unlikely_assert(!vpid)) {
                bsl::error() << "invalid vpid\n" << bsl::here();
                return bsl::errc_invalid_argument;
            }

            if (bsl::unlikely_assert(!ppid)) {
                bsl::error() << "invalid ppid\n" << bsl::here();
                return bsl::errc_invalid_argument;
            }

            ret = bf_vp_op_migrate_impl(m_hndl.get(), vpid.get(), ppid.get());
            if (bsl::unlikely(ret != BF_STATUS_SUCCESS)) {
                bsl::error() << "bf_vp_op_migrate failed with status "    // --
                             << bsl::hex(ret)                             // --
                             << bsl::endl                                 // --
                             << bsl::here();

                return bsl::errc_failure;
            }

            return bsl::errc_success;
        }

        // ---------------------------------------------------------------------
        // bf_vps_ops
        // ---------------------------------------------------------------------

        /// <!-- description -->
        ///   @brief This syscall tells the microkernel to create a VPS
        ///     and return it's ID.
        ///
        /// <!-- inputs/outputs -->
        ///   @param vpid The ID of the VP to assign the newly created VPS to
        ///   @param ppid The resulting VPSID of the newly created VPS
        ///   @return Returns the resulting ID, or bf_uint16_t::failure()
        ///     on failure.
        ///
        ///
        [[nodiscard]] constexpr auto
        bf_vps_op_create_vps(bf_uint16_t const &vpid, bf_uint16_t const &ppid) noexcept
            -> bf_uint16_t
        {
            bf_status_t ret{};
            bf_uint16_t vpsid{};

            if (bsl::unlikely_assert(!vpid)) {
                bsl::error() << "invalid vpid\n" << bsl::here();
                return bf_uint16_t::failure();
            }

            if (bsl::unlikely_assert(!ppid)) {
                bsl::error() << "invalid ppid\n" << bsl::here();
                return bf_uint16_t::failure();
            }

            ret = bf_vps_op_create_vps_impl(m_hndl.get(), vpid.get(), ppid.get(), vpsid.data());
            if (bsl::unlikely(ret != BF_STATUS_SUCCESS)) {
                bsl::error() << "bf_vps_op_create_vps failed with status "    // --
                             << bsl::hex(ret)                                 // --
                             << bsl::endl                                     // --
                             << bsl::here();

                return bf_uint16_t::failure();
            }

            return vpsid;
        }

        /// <!-- description -->
        ///   @brief This syscall tells the microkernel to destroy a VPS
        ///     given an ID.
        ///
        /// <!-- inputs/outputs -->
        ///   @param vpsid The VPSID of the VPS to destroy
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     otherwise
        ///
        [[nodiscard]] constexpr auto
        bf_vps_op_destroy_vps(bf_uint16_t const &vpsid) noexcept -> bsl::errc_type
        {
            bf_status_t ret{};

            if (bsl::unlikely_assert(!vpsid)) {
                bsl::error() << "invalid vpsid\n" << bsl::here();
                return bsl::errc_invalid_argument;
            }

            ret = bf_vps_op_destroy_vps_impl(m_hndl.get(), vpsid.get());
            if (bsl::unlikely(ret != BF_STATUS_SUCCESS)) {
                bsl::error() << "bf_vps_op_destroy_vps failed with status "    // --
                             << bsl::hex(ret)                                  // --
                             << bsl::endl                                      // --
                             << bsl::here();

                return bsl::errc_failure;
            }

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief This syscall tells the microkernel to initialize a VPS using
        ///     the root VP state provided by the loader using the current PPID.
        ///
        /// <!-- inputs/outputs -->
        ///   @param vpsid The VPSID of the VPS to initialize
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     otherwise
        ///
        [[nodiscard]] constexpr auto
        bf_vps_op_init_as_root(bf_uint16_t const &vpsid) noexcept -> bsl::errc_type
        {
            bf_status_t ret{};

            if (bsl::unlikely_assert(!vpsid)) {
                bsl::error() << "invalid vpsid\n" << bsl::here();
                return bsl::errc_invalid_argument;
            }

            ret = bf_vps_op_init_as_root_impl(m_hndl.get(), vpsid.get());
            if (bsl::unlikely(ret != BF_STATUS_SUCCESS)) {
                bsl::error() << "bf_vps_op_init_as_root failed with status "    // --
                             << bsl::hex(ret)                                   // --
                             << bsl::endl                                       // --
                             << bsl::here();

                return bsl::errc_failure;
            }

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Reads an 8bit field from the VPS and returns the value. The
        ///     "index" is architecture-specific. For Intel, Appendix B, "Field
        ///     Encoding in VMCS," defines the index (or encoding). For AMD,
        ///     Appendix B, "Layout of VMCB," defines the index (or offset).
        ///
        /// <!-- inputs/outputs -->
        ///   @param vpsid The VPSID of the VPS to read from
        ///   @param index The HVE specific index defining which field to read
        ///   @return Returns the value read, or bf_uint8_t::failure()
        ///     on failure.
        ///
        [[nodiscard]] constexpr auto
        bf_vps_op_read8(bf_uint16_t const &vpsid, bf_uint64_t const &index) const noexcept
            -> bf_uint8_t
        {
            bf_status_t ret{};
            bf_uint8_t value{};

            if (bsl::unlikely_assert(!vpsid)) {
                bsl::error() << "invalid vpsid\n" << bsl::here();
                return bf_uint8_t::failure();
            }

            if (bsl::unlikely_assert(!index)) {
                bsl::error() << "invalid index\n" << bsl::here();
                return bf_uint8_t::failure();
            }

            ret = bf_vps_op_read8_impl(m_hndl.get(), vpsid.get(), index.get(), value.data());
            if (bsl::unlikely(ret != BF_STATUS_SUCCESS)) {
                bsl::error() << "bf_vps_op_read8 failed with status "    // --
                             << bsl::hex(ret)                            // --
                             << bsl::endl                                // --
                             << bsl::here();

                return bf_uint8_t::failure();
            }

            return value;
        }

        /// <!-- description -->
        ///   @brief Reads an 16bit field from the VPS and returns the value. The
        ///     "index" is architecture-specific. For Intel, Appendix B, "Field
        ///     Encoding in VMCS," defines the index (or encoding). For AMD,
        ///     Appendix B, "Layout of VMCB," defines the index (or offset).
        ///
        /// <!-- inputs/outputs -->
        ///   @param vpsid The VPSID of the VPS to read from
        ///   @param index The HVE specific index defining which field to read
        ///   @return Returns the value read, or bf_uint16_t::failure()
        ///     on failure.
        ///
        [[nodiscard]] constexpr auto
        bf_vps_op_read16(bf_uint16_t const &vpsid, bf_uint64_t const &index) const noexcept
            -> bf_uint16_t
        {
            bf_status_t ret{};
            bf_uint16_t value{};

            if (bsl::unlikely_assert(!vpsid)) {
                bsl::error() << "invalid vpsid\n" << bsl::here();
                return bf_uint16_t::failure();
            }

            if (bsl::unlikely_assert(!index)) {
                bsl::error() << "invalid index\n" << bsl::here();
                return bf_uint16_t::failure();
            }

            ret = bf_vps_op_read16_impl(m_hndl.get(), vpsid.get(), index.get(), value.data());
            if (bsl::unlikely(ret != BF_STATUS_SUCCESS)) {
                bsl::error() << "bf_vps_op_read16 failed with status "    // --
                             << bsl::hex(ret)                             // --
                             << bsl::endl                                 // --
                             << bsl::here();

                return bf_uint16_t::failure();
            }

            return value;
        }

        /// <!-- description -->
        ///   @brief Reads an 32bit field from the VPS and returns the value. The
        ///     "index" is architecture-specific. For Intel, Appendix B, "Field
        ///     Encoding in VMCS," defines the index (or encoding). For AMD,
        ///     Appendix B, "Layout of VMCB," defines the index (or offset).
        ///
        /// <!-- inputs/outputs -->
        ///   @param vpsid The VPSID of the VPS to read from
        ///   @param index The HVE specific index defining which field to read
        ///   @return Returns the value read, or bf_uint32_t::failure()
        ///     on failure.
        ///
        [[nodiscard]] constexpr auto
        bf_vps_op_read32(bf_uint16_t const &vpsid, bf_uint64_t const &index) const noexcept
            -> bf_uint32_t
        {
            bf_status_t ret{};
            bf_uint32_t value{};

            if (bsl::unlikely_assert(!vpsid)) {
                bsl::error() << "invalid vpsid\n" << bsl::here();
                return bf_uint32_t::failure();
            }

            if (bsl::unlikely_assert(!index)) {
                bsl::error() << "invalid index\n" << bsl::here();
                return bf_uint32_t::failure();
            }

            ret = bf_vps_op_read32_impl(m_hndl.get(), vpsid.get(), index.get(), value.data());
            if (bsl::unlikely(ret != BF_STATUS_SUCCESS)) {
                bsl::error() << "bf_vps_op_read32 failed with status "    // --
                             << bsl::hex(ret)                             // --
                             << bsl::endl                                 // --
                             << bsl::here();

                return bf_uint32_t::failure();
            }

            return value;
        }

        /// <!-- description -->
        ///   @brief Reads an 64bit field from the VPS and returns the value. The
        ///     "index" is architecture-specific. For Intel, Appendix B, "Field
        ///     Encoding in VMCS," defines the index (or encoding). For AMD,
        ///     Appendix B, "Layout of VMCB," defines the index (or offset).
        ///
        /// <!-- inputs/outputs -->
        ///   @param vpsid The VPSID of the VPS to read from
        ///   @param index The HVE specific index defining which field to read
        ///   @return Returns the value read, or bf_uint64_t::failure()
        ///     on failure.
        ///
        [[nodiscard]] constexpr auto
        bf_vps_op_read64(bf_uint16_t const &vpsid, bf_uint64_t const &index) const noexcept
            -> bf_uint64_t
        {
            bf_status_t ret{};
            bf_uint64_t value{};

            if (bsl::unlikely_assert(!vpsid)) {
                bsl::error() << "invalid vpsid\n" << bsl::here();
                return bf_uint64_t::failure();
            }

            if (bsl::unlikely_assert(!index)) {
                bsl::error() << "invalid index\n" << bsl::here();
                return bf_uint64_t::failure();
            }

            ret = bf_vps_op_read64_impl(m_hndl.get(), vpsid.get(), index.get(), value.data());
            if (bsl::unlikely(ret != BF_STATUS_SUCCESS)) {
                bsl::error() << "bf_vps_op_read64 failed with status "    // --
                             << bsl::hex(ret)                             // --
                             << bsl::endl                                 // --
                             << bsl::here();

                return bf_uint64_t::failure();
            }

            return value;
        }

        /// <!-- description -->
        ///   @brief Writes to an 8bit field in the VPS. The "index" is
        ///     architecture-specific. For Intel, Appendix B, "Field Encoding in
        ///     VMCS," defines the index (or encoding). For AMD, Appendix B,
        ///     "Layout of VMCB," defines the index (or offset).
        ///
        /// <!-- inputs/outputs -->
        ///   @param vpsid The VPSID of the VPS to write to
        ///   @param index The HVE specific index defining which field to write to
        ///   @param value The value to write to the requested field
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     otherwise
        ///
        [[nodiscard]] constexpr auto
        bf_vps_op_write8(
            bf_uint16_t const &vpsid, bf_uint64_t const &index, bf_uint8_t const &value) noexcept
            -> bsl::errc_type
        {
            bf_status_t ret{};

            if (bsl::unlikely_assert(!vpsid)) {
                bsl::error() << "invalid vpsid\n" << bsl::here();
                return bsl::errc_invalid_argument;
            }

            if (bsl::unlikely_assert(!index)) {
                bsl::error() << "invalid index\n" << bsl::here();
                return bsl::errc_invalid_argument;
            }

            if (bsl::unlikely_assert(!value)) {
                bsl::error() << "invalid value\n" << bsl::here();
                return bsl::errc_invalid_argument;
            }

            ret = bf_vps_op_write8_impl(m_hndl.get(), vpsid.get(), index.get(), value.get());
            if (bsl::unlikely(ret != BF_STATUS_SUCCESS)) {
                bsl::error() << "bf_vps_op_write8 failed with status "    // --
                             << bsl::hex(ret)                             // --
                             << bsl::endl                                 // --
                             << bsl::here();

                return bsl::errc_failure;
            }

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Writes to an 16bit field in the VPS. The "index" is
        ///     architecture-specific. For Intel, Appendix B, "Field Encoding in
        ///     VMCS," defines the index (or encoding). For AMD, Appendix B,
        ///     "Layout of VMCB," defines the index (or offset).
        ///
        /// <!-- inputs/outputs -->
        ///   @param vpsid The VPSID of the VPS to write to
        ///   @param index The HVE specific index defining which field to write to
        ///   @param value The value to write to the requested field
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     otherwise
        ///
        [[nodiscard]] constexpr auto
        bf_vps_op_write16(
            bf_uint16_t const &vpsid, bf_uint64_t const &index, bf_uint16_t const &value) noexcept
            -> bsl::errc_type
        {
            bf_status_t ret{};

            if (bsl::unlikely_assert(!vpsid)) {
                bsl::error() << "invalid vpsid\n" << bsl::here();
                return bsl::errc_invalid_argument;
            }

            if (bsl::unlikely_assert(!index)) {
                bsl::error() << "invalid index\n" << bsl::here();
                return bsl::errc_invalid_argument;
            }

            if (bsl::unlikely_assert(!value)) {
                bsl::error() << "invalid value\n" << bsl::here();
                return bsl::errc_invalid_argument;
            }

            ret = bf_vps_op_write16_impl(m_hndl.get(), vpsid.get(), index.get(), value.get());
            if (bsl::unlikely(ret != BF_STATUS_SUCCESS)) {
                bsl::error() << "bf_vps_op_write16 failed with status "    // --
                             << bsl::hex(ret)                              // --
                             << bsl::endl                                  // --
                             << bsl::here();

                return bsl::errc_failure;
            }

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Writes to an 32bit field in the VPS. The "index" is
        ///     architecture-specific. For Intel, Appendix B, "Field Encoding in
        ///     VMCS," defines the index (or encoding). For AMD, Appendix B,
        ///     "Layout of VMCB," defines the index (or offset).
        ///
        /// <!-- inputs/outputs -->
        ///   @param vpsid The VPSID of the VPS to write to
        ///   @param index The HVE specific index defining which field to write to
        ///   @param value The value to write to the requested field
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     otherwise
        ///
        [[nodiscard]] constexpr auto
        bf_vps_op_write32(
            bf_uint16_t const &vpsid, bf_uint64_t const &index, bf_uint32_t const &value) noexcept
            -> bsl::errc_type
        {
            bf_status_t ret{};

            if (bsl::unlikely_assert(!vpsid)) {
                bsl::error() << "invalid vpsid\n" << bsl::here();
                return bsl::errc_invalid_argument;
            }

            if (bsl::unlikely_assert(!index)) {
                bsl::error() << "invalid index\n" << bsl::here();
                return bsl::errc_invalid_argument;
            }

            if (bsl::unlikely_assert(!value)) {
                bsl::error() << "invalid value\n" << bsl::here();
                return bsl::errc_invalid_argument;
            }

            ret = bf_vps_op_write32_impl(m_hndl.get(), vpsid.get(), index.get(), value.get());
            if (bsl::unlikely(ret != BF_STATUS_SUCCESS)) {
                bsl::error() << "bf_vps_op_write32 failed with status "    // --
                             << bsl::hex(ret)                              // --
                             << bsl::endl                                  // --
                             << bsl::here();

                return bsl::errc_failure;
            }

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Writes to an 64bit field in the VPS. The "index" is
        ///     architecture-specific. For Intel, Appendix B, "Field Encoding in
        ///     VMCS," defines the index (or encoding). For AMD, Appendix B,
        ///     "Layout of VMCB," defines the index (or offset).
        ///
        /// <!-- inputs/outputs -->
        ///   @param vpsid The VPSID of the VPS to write to
        ///   @param index The HVE specific index defining which field to write to
        ///   @param value The value to write to the requested field
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     otherwise
        ///
        [[nodiscard]] constexpr auto
        bf_vps_op_write64(
            bf_uint16_t const &vpsid, bf_uint64_t const &index, bf_uint64_t const &value) noexcept
            -> bsl::errc_type
        {
            bf_status_t ret{};

            if (bsl::unlikely_assert(!vpsid)) {
                bsl::error() << "invalid vpsid\n" << bsl::here();
                return bsl::errc_invalid_argument;
            }

            if (bsl::unlikely_assert(!index)) {
                bsl::error() << "invalid index\n" << bsl::here();
                return bsl::errc_invalid_argument;
            }

            if (bsl::unlikely_assert(!value)) {
                bsl::error() << "invalid value\n" << bsl::here();
                return bsl::errc_invalid_argument;
            }

            ret = bf_vps_op_write64_impl(m_hndl.get(), vpsid.get(), index.get(), value.get());
            if (bsl::unlikely(ret != BF_STATUS_SUCCESS)) {
                bsl::error() << "bf_vps_op_write64 failed with status "    // --
                             << bsl::hex(ret)                              // --
                             << bsl::endl                                  // --
                             << bsl::here();

                return bsl::errc_failure;
            }

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Reads a CPU register from the VPS given a bf_reg_t. Note
        ///     that the bf_reg_t is architecture specific.
        ///
        /// <!-- inputs/outputs -->
        ///   @param vpsid The VPSID of the VPS to read from
        ///   @param reg A bf_reg_t defining which register to read
        ///   @return Returns the value read, or bf_uint64_t::failure()
        ///     on failure.
        ///
        [[nodiscard]] constexpr auto
        bf_vps_op_read_reg(bf_uint16_t const &vpsid, bf_reg_t const reg) const noexcept
            -> bf_uint64_t
        {
            bf_status_t ret{};
            bf_uint64_t value{};

            if (bsl::unlikely_assert(!vpsid)) {
                bsl::error() << "invalid vpsid\n" << bsl::here();
                return bf_uint64_t::failure();
            }

            ret = bf_vps_op_read_reg_impl(m_hndl.get(), vpsid.get(), reg, value.data());
            if (bsl::unlikely(ret != BF_STATUS_SUCCESS)) {
                bsl::error() << "bf_vps_op_read_reg failed with status "    // --
                             << bsl::hex(ret)                               // --
                             << bsl::endl                                   // --
                             << bsl::here();

                return bf_uint64_t::failure();
            }

            return value;
        }

        /// <!-- description -->
        ///   @brief Writes to a CPU register in the VPS given a bf_reg_t and the
        ///     value to write. Note that the bf_reg_t is architecture specific.
        ///
        /// <!-- inputs/outputs -->
        ///   @param vpsid The VPSID of the VPS to write to
        ///   @param reg A bf_reg_t defining which register to write to
        ///   @param value The value to write to the requested register
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     otherwise
        ///
        [[nodiscard]] constexpr auto
        bf_vps_op_write_reg(
            bf_uint16_t const &vpsid, bf_reg_t const reg, bf_uint64_t const &value) noexcept
            -> bsl::errc_type
        {
            bf_status_t ret{};

            if (bsl::unlikely_assert(!vpsid)) {
                bsl::error() << "invalid vpsid\n" << bsl::here();
                return bsl::errc_invalid_argument;
            }

            if (bsl::unlikely_assert(!value)) {
                bsl::error() << "invalid value\n" << bsl::here();
                return bsl::errc_invalid_argument;
            }

            ret = bf_vps_op_write_reg_impl(m_hndl.get(), vpsid.get(), reg, value.get());
            if (bsl::unlikely(ret != BF_STATUS_SUCCESS)) {
                bsl::error() << "bf_vps_op_write_reg failed with status "    // --
                             << bsl::hex(ret)                                // --
                             << bsl::endl                                    // --
                             << bsl::here();

                return bsl::errc_failure;
            }

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief bf_vps_op_run tells the microkernel to execute a given VPS on
        ///     behalf of a given VP and VM. This system call only returns if an
        ///     error occurs. On success, this system call will physically execute
        ///     the requested VM and VP using the requested VPS, and the extension
        ///     will only execute again on the next VMExit.
        ///
        ///     Unless an extension needs to change the active VM, VP or VPS, the
        ///     extension should use bf_vps_op_run_current instead of
        ///     bf_vps_op_run. bf_vps_op_run is slow as it must perform a series of
        ///     checks to determine if it has any work to perform before execution
        ///     of a VM can occur.
        ///
        ///     Unlike bf_vps_op_run_current which is really just a return to
        ///     microkernel execution, bf_vps_op_run must perform the following
        ///     operations:
        ///     - It first verifies that the provided VM, VP and VPS are all
        ///       created. Meaning, and extension must first use the create ABI
        ///       to properly create a VM, VP and VPS before it may be used.
        ///     - Next, it must ensure VM, VP and VPS assignment is correct. A
        ///       newly created VP and VPS are unassigned. Once bf_vps_op_run is
        ///       executed, the VP is assigned to the provided VM and the VPS is
        ///       assigned to the provided VP. The VP and VPS are also both
        ///       assigned to the PP bf_vps_op_run is executed on. Once these
        ///       assignments take place, an extension cannot change them, and any
        ///       attempt to run a VP or VPS on a VM, VP or PP they are not
        ///       assigned to will fail. It is impossible to change the assigned of
        ///       a VM or VP, but an extension can change the assignment of a VP
        ///       and VPSs PP by using the bf_vp_op_migrate function.
        ///     - Next, bf_vps_op_run must determine if it needs to migrate a VPS
        ///       to the PP the VPS is being executed on by bf_vps_op_run. For more
        ///       information about how this works, please see bf_vp_op_migrate.
        ///     - Finally, bf_vps_op_run must ensure the active VM, VP and VPS are
        ///       set to the VM, VP and VPS provided to this ABI. Any changes in
        ///       the active state could cause additional operations to take place.
        ///       For example, the VPS must transfer the TLS state of the general
        ///       purpose registers to its internal cache so that the VPS that is
        ///       about to become active can use the TLS block instead.
        ///
        /// <!-- inputs/outputs -->
        ///   @param vmid The VMID of the VM to run
        ///   @param vpid The VPID of the VP to run
        ///   @param vpsid The VPSID of the VPS to run
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     otherwise
        ///
        [[nodiscard]] constexpr auto
        bf_vps_op_run(
            bf_uint16_t const &vmid, bf_uint16_t const &vpid, bf_uint16_t const &vpsid) noexcept
            -> bsl::errc_type
        {
            bf_status_t ret{};

            if (bsl::unlikely_assert(!vmid)) {
                bsl::error() << "invalid vmid\n" << bsl::here();
                return bsl::errc_invalid_argument;
            }

            if (bsl::unlikely_assert(!vpid)) {
                bsl::error() << "invalid vpid\n" << bsl::here();
                return bsl::errc_invalid_argument;
            }

            if (bsl::unlikely_assert(!vpsid)) {
                bsl::error() << "invalid vpsid\n" << bsl::here();
                return bsl::errc_invalid_argument;
            }

            ret = bf_vps_op_run_impl(m_hndl.get(), vmid.get(), vpid.get(), vpsid.get());
            if (bsl::unlikely(ret != BF_STATUS_SUCCESS)) {
                bsl::error() << "bf_vps_op_run failed with status "    // --
                             << bsl::hex(ret)                          // --
                             << bsl::endl                              // --
                             << bsl::here();

                return bsl::errc_failure;
            }

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief bf_vps_op_run_current tells the microkernel to execute the
        ///     currently active VPS, VP and VM.
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     otherwise
        ///
        [[nodiscard]] constexpr auto
        bf_vps_op_run_current() noexcept -> bsl::errc_type
        {
            bf_status_t const ret{bf_vps_op_run_current_impl(m_hndl.get())};
            if (bsl::unlikely(ret != BF_STATUS_SUCCESS)) {
                bsl::error() << "bf_vps_op_run_current failed with status "    // --
                             << bsl::hex(ret)                                  // --
                             << bsl::endl                                      // --
                             << bsl::here();

                return bsl::errc_failure;
            }

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief This syscall tells the microkernel to advance the instruction
        ///     pointer in the requested VPS.
        ///
        /// <!-- inputs/outputs -->
        ///   @param vpsid The VPSID of the VPS advance the IP in
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     otherwise
        ///
        [[nodiscard]] constexpr auto
        bf_vps_op_advance_ip(bf_uint16_t const &vpsid) noexcept -> bsl::errc_type
        {
            bf_status_t ret{};

            if (bsl::unlikely_assert(!vpsid)) {
                bsl::error() << "invalid vpsid\n" << bsl::here();
                return bsl::errc_invalid_argument;
            }

            ret = bf_vps_op_advance_ip_impl(m_hndl.get(), vpsid.get());
            if (bsl::unlikely(ret != BF_STATUS_SUCCESS)) {
                bsl::error() << "bf_vps_op_advance_ip failed with status "    // --
                             << bsl::hex(ret)                                 // --
                             << bsl::endl                                     // --
                             << bsl::here();

                return bsl::errc_failure;
            }

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief This syscall tells the microkernel to advance the instruction
        ///     pointer in the currently active VPS and run the currently active
        ///     VPS, VP and VM (i.e., this combines bf_vps_op_advance_ip and
        ///     bf_vps_op_advance_ip).
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     otherwise
        ///
        [[nodiscard]] constexpr auto
        bf_vps_op_advance_ip_and_run_current() noexcept -> bsl::errc_type
        {
            bf_status_t const ret{bf_vps_op_advance_ip_and_run_current_impl(m_hndl.get())};
            if (bsl::unlikely(ret != BF_STATUS_SUCCESS)) {
                bsl::error() << "bf_vps_op_advance_ip_and_run_current failed with status "    // --
                             << bsl::hex(ret)                                                 // --
                             << bsl::endl                                                     // --
                             << bsl::here();

                return bsl::errc_failure;
            }

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief This syscall tells the microkernel to promote the requested
        ///     VPS. This will stop the hypervisor complete on the physical
        ///     processor that this syscall is executed on and replace it's state
        ///     with the state in the VPS. Note that this syscall only returns
        ///     on error.
        ///
        /// <!-- inputs/outputs -->
        ///   @param vpsid The VPSID of the VPS to promote
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     otherwise
        ///
        [[nodiscard]] constexpr auto
        bf_vps_op_promote(bf_uint16_t const &vpsid) noexcept -> bsl::errc_type
        {
            bf_status_t ret{};

            if (bsl::unlikely_assert(!vpsid)) {
                bsl::error() << "invalid vpsid\n" << bsl::here();
                return bsl::errc_invalid_argument;
            }

            ret = bf_vps_op_promote_impl(m_hndl.get(), vpsid.get());
            if (bsl::unlikely(ret != BF_STATUS_SUCCESS)) {
                bsl::error() << "bf_vps_op_promote failed with status "    // --
                             << bsl::hex(ret)                              // --
                             << bsl::endl                                  // --
                             << bsl::here();

                return bsl::errc_failure;
            }

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief bf_vps_op_clear_vps tells the microkernel to clear the VPS's
        ///     hardware cache, if one exists. How this is used depends entirely
        ///     on the hardware and is associated with AMD's VMCB Clean Bits,
        ///     and Intel's VMClear instruction. See the associated documentation
        ///     for more details. On AMD, this ABI clears the entire VMCB. For more
        ///     fine grained control, use the write ABIs to manually modify the
        ///     VMCB.
        ///
        /// <!-- inputs/outputs -->
        ///   @param vpsid The VPSID of the VPS to clear
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     otherwise
        ///
        [[nodiscard]] constexpr auto
        bf_vps_op_clear_vps(bf_uint16_t const &vpsid) noexcept -> bsl::errc_type
        {
            bf_status_t ret{};

            if (bsl::unlikely_assert(!vpsid)) {
                bsl::error() << "invalid vpsid\n" << bsl::here();
                return bsl::errc_invalid_argument;
            }

            ret = bf_vps_op_clear_vps_impl(m_hndl.get(), vpsid.get());
            if (bsl::unlikely(ret != BF_STATUS_SUCCESS)) {
                bsl::error() << "bf_vps_op_clear_vps failed with status "    // --
                             << bsl::hex(ret)                                // --
                             << bsl::endl                                    // --
                             << bsl::here();

                return bsl::errc_failure;
            }

            return bsl::errc_success;
        }

        // ---------------------------------------------------------------------
        // bf_intrinsic_ops
        // ---------------------------------------------------------------------

        /// <!-- description -->
        ///   @brief Reads an MSR directly from the CPU given the address of
        ///     the MSR to read. Note that this is specific to Intel/AMD only.
        ///     Also note that not all MSRs can be read, and which MSRs that
        ///     can be read is up to the microkernel's internal policy as well
        ///     as which architecture the hypervisor is running on.
        ///
        /// <!-- inputs/outputs -->
        ///   @param msr The address of the MSR to read
        ///   @return Returns the value read, or bf_uint64_t::failure()
        ///     on failure.
        ///
        [[nodiscard]] constexpr auto
        bf_intrinsic_op_rdmsr(bf_uint32_t const &msr) const noexcept -> bf_uint64_t
        {
            bf_status_t ret{};
            bf_uint64_t value{};

            if (bsl::unlikely_assert(!msr)) {
                bsl::error() << "invalid msr\n" << bsl::here();
                return bf_uint64_t::failure();
            }

            ret = bf_intrinsic_op_rdmsr_impl(m_hndl.get(), msr.get(), value.data());
            if (bsl::unlikely(ret != BF_STATUS_SUCCESS)) {
                bsl::error() << "bf_intrinsic_op_rdmsr failed with status "    // --
                             << bsl::hex(ret)                                  // --
                             << bsl::endl                                      // --
                             << bsl::here();

                return bf_uint64_t::failure();
            }

            return value;
        }

        /// <!-- description -->
        ///   @brief Writes to an MSR directly from the CPU given the address of
        ///     the MSR to write as well as the value to write. Note that this is
        ///     specific to Intel/AMD only. Also note that not all MSRs can be
        ///     written to, and which MSRs that can be written to is up to the
        ///     microkernel's internal policy as well as which architecture the
        ///     hypervisor is running on.
        ///
        /// <!-- inputs/outputs -->
        ///   @param msr The address of the MSR to write to
        ///   @param value The value to write to the requested MSR
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     otherwise
        ///
        [[nodiscard]] constexpr auto
        bf_intrinsic_op_wrmsr(bf_uint32_t const &msr, bf_uint64_t const &value) noexcept
            -> bsl::errc_type
        {
            bf_status_t ret{};

            if (bsl::unlikely_assert(!msr)) {
                bsl::error() << "invalid msr\n" << bsl::here();
                return bsl::errc_invalid_argument;
            }

            if (bsl::unlikely_assert(!value)) {
                bsl::error() << "invalid value\n" << bsl::here();
                return bsl::errc_invalid_argument;
            }

            ret = bf_intrinsic_op_wrmsr_impl(m_hndl.get(), msr.get(), value.get());
            if (bsl::unlikely(ret != BF_STATUS_SUCCESS)) {
                bsl::error() << "bf_intrinsic_op_wrmsr failed with status "    // --
                             << bsl::hex(ret)                                  // --
                             << bsl::endl                                      // --
                             << bsl::here();

                return bsl::errc_failure;
            }

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Invalidates the TLB mapping for a given virtual page and a
        ///     given ASID. Note that this is specific to AMD only.
        ///
        /// <!-- inputs/outputs -->
        ///   @param addr The address to invalidate
        ///   @param asid The ASID to invalidate
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     otherwise
        ///
        [[nodiscard]] constexpr auto
        bf_intrinsic_op_invlpga(bf_uint64_t const &addr, bf_uint64_t const &asid) noexcept
            -> bsl::errc_type
        {
            bf_status_t ret{};

            if (bsl::unlikely_assert(!addr)) {
                bsl::error() << "invalid addr\n" << bsl::here();
                return bsl::errc_invalid_argument;
            }

            if (bsl::unlikely_assert(!asid)) {
                bsl::error() << "invalid asid\n" << bsl::here();
                return bsl::errc_invalid_argument;
            }

            ret = bf_intrinsic_op_invlpga_impl(m_hndl.get(), addr.get(), asid.get());
            if (bsl::unlikely(ret != BF_STATUS_SUCCESS)) {
                bsl::error() << "bf_intrinsic_op_invlpga failed with status "    // --
                             << bsl::hex(ret)                                    // --
                             << bsl::endl                                        // --
                             << bsl::here();

                return bsl::errc_failure;
            }

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Invalidates mappings in the translation lookaside buffers
        ///     (TLBs) and paging-structure caches that were derived from extended
        ///     page tables (EPT). Note that this is specific to Intel only.
        ///
        /// <!-- inputs/outputs -->
        ///   @param eptp The EPTP to invalidate
        ///   @param type The INVEPT type (see the Intel SDM for details)
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     otherwise
        ///
        [[nodiscard]] constexpr auto
        bf_intrinsic_op_invept(bf_uint64_t const &eptp, bf_uint64_t const &type) noexcept
            -> bsl::errc_type
        {
            bf_status_t ret{};

            if (bsl::unlikely_assert(!eptp)) {
                bsl::error() << "invalid eptp\n" << bsl::here();
                return bsl::errc_invalid_argument;
            }

            if (bsl::unlikely_assert(!type)) {
                bsl::error() << "invalid type\n" << bsl::here();
                return bsl::errc_invalid_argument;
            }

            ret = bf_intrinsic_op_invept_impl(m_hndl.get(), eptp.get(), type.get());
            if (bsl::unlikely(ret != BF_STATUS_SUCCESS)) {
                bsl::error() << "bf_intrinsic_op_invept failed with status "    // --
                             << bsl::hex(ret)                                   // --
                             << bsl::endl                                       // --
                             << bsl::here();

                return bsl::errc_failure;
            }

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Invalidates mappings in the translation lookaside buffers
        ///     (TLBs) and paging-structure caches based on virtual-processor
        ///     identifier (VPID). Note that this is specific to Intel only.
        ///
        /// <!-- inputs/outputs -->
        ///   @param addr The address to invalidate
        ///   @param vpid The VPID to invalidate
        ///   @param type The INVVPID type (see the Intel SDM for details)
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     otherwise
        ///
        [[nodiscard]] constexpr auto
        bf_intrinsic_op_invvpid(
            bf_uint64_t const &addr, bf_uint16_t const &vpid, bf_uint64_t const &type) noexcept
            -> bsl::errc_type
        {
            bf_status_t ret{};

            if (bsl::unlikely_assert(!addr)) {
                bsl::error() << "invalid addr\n" << bsl::here();
                return bsl::errc_invalid_argument;
            }

            if (bsl::unlikely_assert(!vpid)) {
                bsl::error() << "invalid vpid\n" << bsl::here();
                return bsl::errc_invalid_argument;
            }

            if (bsl::unlikely_assert(!type)) {
                bsl::error() << "invalid type\n" << bsl::here();
                return bsl::errc_invalid_argument;
            }

            ret = bf_intrinsic_op_invvpid_impl(m_hndl.get(), addr.get(), vpid.get(), type.get());
            if (bsl::unlikely(ret != BF_STATUS_SUCCESS)) {
                bsl::error() << "bf_intrinsic_op_invvpid failed with status "    // --
                             << bsl::hex(ret)                                    // --
                             << bsl::endl                                        // --
                             << bsl::here();

                return bsl::errc_failure;
            }

            return bsl::errc_success;
        }

        // ---------------------------------------------------------------------
        // bf_mem_ops
        // ---------------------------------------------------------------------

        /// <!-- description -->
        ///   @brief bf_mem_op_alloc_page allocates a page, and maps this page
        ///     into the direct map of the VM.
        ///
        /// <!-- inputs/outputs -->
        ///   @param phys The physical address of the resulting page
        ///   @return Returns a pointer to the newly allocated memory on success,
        ///     or a nullptr on failure.
        ///
        [[nodiscard]] constexpr auto
        bf_mem_op_alloc_page(bf_uint64_t &phys) noexcept -> void *
        {
            void *ptr{};
            bf_status_t ret{};

            if (bsl::unlikely_assert(!phys)) {
                bsl::error() << "invalid phys\n" << bsl::here();
                return nullptr;
            }

            ret = bf_mem_op_alloc_page_impl(m_hndl.get(), &ptr, phys.data());
            if (bsl::unlikely(ret != BF_STATUS_SUCCESS)) {
                bsl::error() << "bf_mem_op_alloc_page failed with status "    // --
                             << bsl::hex(ret)                                 // --
                             << bsl::endl                                     // --
                             << bsl::here();

                return nullptr;
            }

            return ptr;
        }

        /// <!-- description -->
        ///   @brief bf_mem_op_alloc_page allocates a page, and maps this page
        ///     into the direct map of the VM.
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns a pointer to the newly allocated memory on success,
        ///     or a nullptr on failure.
        ///
        [[nodiscard]] constexpr auto
        bf_mem_op_alloc_page() noexcept -> void *
        {
            bf_uint64_t ignored{};
            return this->bf_mem_op_alloc_page(ignored);
        }

        /// <!-- description -->
        ///   @brief Frees a page previously allocated by bf_mem_op_alloc_page.
        ///     This operation is optional and not all microkernels may implement
        ///     it.
        ///
        /// <!-- inputs/outputs -->
        ///   @param virt The virtual address of the page to free
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     otherwise
        ///
        [[nodiscard]] constexpr auto
        bf_mem_op_free_page(void *const virt) noexcept -> bsl::errc_type
        {
            bf_status_t ret{};

            if (bsl::unlikely_assert(nullptr == virt)) {
                bsl::error() << "virt is a nullptr\n" << bsl::here();
                return bsl::errc_invalid_argument;
            }

            ret = bf_mem_op_free_page_impl(m_hndl.get(), virt);
            if (bsl::unlikely(ret != BF_STATUS_SUCCESS)) {
                bsl::error() << "bf_mem_op_free_page failed with status "    // --
                             << bsl::hex(ret)                                // --
                             << bsl::endl                                    // --
                             << bsl::here();

                return bsl::errc_failure;
            }

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief bf_mem_op_alloc_huge allocates a physically contiguous block
        ///     of memory. When allocating a page, the extension should keep in
        ///     mind the following:
        ///       - The total memory available to allocate from this pool is
        ///         extremely limited. This should only be used when absolutely
        ///         needed, and extensions should not expect more than 1 MB (might
        ///         be less) of total memory available.
        ///       - Memory allocated from the huge pool might be allocated using
        ///         different schemes. For example, the microkernel might allocate
        ///         in increments of a page, or it might use a buddy allocator that
        ///         would allocate in multiples of 2. If the allocation size
        ///         doesn't match the algorithm, internal fragmentation could
        ///         occur, further limiting the total number of allocations this
        ///         pool can support.
        ///
        /// <!-- inputs/outputs -->
        ///   @param size The total number of bytes to allocate
        ///   @param phys The physical address of the resulting memory
        ///   @return Returns a pointer to the newly allocated memory on success,
        ///     or a nullptr on failure.
        ///
        [[nodiscard]] constexpr auto
        bf_mem_op_alloc_huge(bf_uint64_t const &size, bf_uint64_t &phys) noexcept -> void *
        {
            void *ptr{};
            bf_status_t ret{};

            if (bsl::unlikely_assert(!size)) {
                bsl::error() << "invalid size\n" << bsl::here();
                return nullptr;
            }

            if (bsl::unlikely_assert(size.is_zero())) {
                bsl::error() << "size cannot be 0\n" << bsl::here();
                return nullptr;
            }

            if (bsl::unlikely_assert(!phys)) {
                bsl::error() << "invalid phys\n" << bsl::here();
                return nullptr;
            }

            ret = bf_mem_op_alloc_huge_impl(m_hndl.get(), size.get(), &ptr, phys.data());
            if (bsl::unlikely(ret != BF_STATUS_SUCCESS)) {
                bsl::error() << "bf_mem_op_alloc_huge failed with status "    // --
                             << bsl::hex(ret)                                 // --
                             << bsl::endl                                     // --
                             << bsl::here();

                return nullptr;
            }

            return ptr;
        }

        /// <!-- description -->
        ///   @brief bf_mem_op_alloc_huge allocates a physically contiguous block
        ///     of memory. When allocating a page, the extension should keep in
        ///     mind the following:
        ///       - The total memory available to allocate from this pool is
        ///         extremely limited. This should only be used when absolutely
        ///         needed, and extensions should not expect more than 1 MB (might
        ///         be less) of total memory available.
        ///       - Memory allocated from the huge pool might be allocated using
        ///         different schemes. For example, the microkernel might allocate
        ///         in increments of a page, or it might use a buddy allocator that
        ///         would allocate in multiples of 2. If the allocation size
        ///         doesn't match the algorithm, internal fragmentation could
        ///         occur, further limiting the total number of allocations this
        ///         pool can support.
        ///
        /// <!-- inputs/outputs -->
        ///   @param size The total number of bytes to allocate
        ///   @return Returns a pointer to the newly allocated memory on success,
        ///     or a nullptr on failure.
        ///
        [[nodiscard]] constexpr auto
        bf_mem_op_alloc_huge(bf_uint64_t const &size) noexcept -> void *
        {
            bf_uint64_t ignored{};
            return this->bf_mem_op_alloc_huge(size, ignored);
        }

        /// <!-- description -->
        ///   @brief Frees memory previously allocated by bf_mem_op_alloc_huge.
        ///     This operation is optional and not all microkernels may implement
        ///     it.
        ///
        /// <!-- inputs/outputs -->
        ///   @param virt The virtual address of the memory to free
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     otherwise
        ///
        [[nodiscard]] constexpr auto
        bf_mem_op_free_huge(void *const virt) noexcept -> bsl::errc_type
        {
            bf_status_t ret{};

            if (bsl::unlikely_assert(nullptr == virt)) {
                bsl::error() << "virt is a nullptr\n" << bsl::here();
                return bsl::errc_invalid_argument;
            }

            ret = bf_mem_op_free_huge_impl(m_hndl.get(), virt);
            if (bsl::unlikely(ret != BF_STATUS_SUCCESS)) {
                bsl::error() << "bf_mem_op_free_huge failed with status "    // --
                             << bsl::hex(ret)                                // --
                             << bsl::endl                                    // --
                             << bsl::here();

                return bsl::errc_failure;
            }

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief bf_mem_op_alloc_heap allocates heap memory. When allocating
        ///     heap memory, the extension should keep in mind the following:
        ///       - This ABI is designed to work similar to sbrk() to support
        ///         malloc/free implementations common with existing open source
        ///         libraries.
        ///       - Calling this ABI with with a size of 0 will return the current
        ///         heap location.
        ///       - Calling this ABI with a size (in bytes) will result in return
        ///         the previous heap location. The current heap location will be
        ///         set to the previous location, plus the provide size, rounded to
        ///         the nearest page size.
        ///       - The heap is not mapped into the direct map, so virtual to
        ///         physical (and vice versa) translations are not possible.
        ///       - There is no ability to free heap memory
        ///
        /// <!-- inputs/outputs -->
        ///   @param size The number of bytes to increase the heap by
        ///   @return Returns a pointer to the newly allocated memory on success,
        ///     or a nullptr on failure.
        ///
        [[nodiscard]] constexpr auto
        bf_mem_op_alloc_heap(bf_uint64_t const &size) noexcept -> void *
        {
            void *ptr{};
            bf_status_t ret{};

            if (bsl::unlikely_assert(!size)) {
                bsl::error() << "invalid size\n" << bsl::here();
                return nullptr;
            }

            ret = bf_mem_op_alloc_heap_impl(m_hndl.get(), size.get(), &ptr);
            if (bsl::unlikely(ret != BF_STATUS_SUCCESS)) {
                bsl::error() << "bf_mem_op_alloc_heap failed with status "    // --
                             << bsl::hex(ret)                                 // --
                             << bsl::endl                                     // --
                             << bsl::here();

                return nullptr;
            }

            return ptr;
        }

        // ---------------------------------------------------------------------
        // direct map helpers
        // ---------------------------------------------------------------------

        /// <!-- description -->
        ///   @brief Returns the value at the provided physical address
        ///     on success, or returns bsl::safe_integral<T>::failure()
        ///     on failure.
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam T the type of integral to read
        ///   @param phys the physical address to read
        ///   @return Returns the value at the provided physical address
        ///     on success, or returns bsl::safe_integral<T>::failure()
        ///     on failure.
        ///
        template<typename T = bsl::uint64>
        [[nodiscard]] static constexpr auto
        bf_read_phys(bf_uint64_t const &phys) noexcept -> bsl::safe_integral<T>
        {
            static_assert(bsl::is_unsigned<T>::value);
            bsl::safe_uintmax virt{};

            if (bsl::unlikely_assert(!phys)) {
                bsl::error() << "invalid phys\n" << bsl::here();
                return bsl::safe_integral<T>::failure();
            }

            if (bsl::unlikely_assert(phys.is_zero())) {
                bsl::error() << "phys is a nullptr\n" << bsl::here();
                return bsl::safe_integral<T>::failure();
            }

            virt = phys + HYPERVISOR_EXT_DIRECT_MAP_ADDR;
            if (bsl::unlikely_assert(!virt)) {
                bsl::error() << "bf_read_phys failed due to invalid physical address "    // --
                             << bsl::hex(phys) << bsl::endl                               // --
                             << bsl::here();

                return bsl::safe_integral<T>::failure();
            }

            return bsl::safe_integral<T>{*bsl::to_ptr<T *>(virt)};
        }

        /// <!-- description -->
        ///   @brief Writes the provided value at the provided physical address
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam T the type of integral to write
        ///   @param phys the physical address to write
        ///   @param val the value to write to the provided physical address
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     otherwise
        ///
        template<typename T = bsl::uint64>
        [[nodiscard]] static constexpr auto
        bf_write_phys(bf_uint64_t const &phys, bsl::safe_integral<T> const &val) noexcept
            -> bsl::errc_type
        {
            static_assert(bsl::is_unsigned<T>::value);
            bsl::safe_uintmax virt{};

            if (bsl::unlikely_assert(!phys)) {
                bsl::error() << "invalid phys\n" << bsl::here();
                return bsl::errc_invalid_argument;
            }

            if (bsl::unlikely_assert(phys.is_zero())) {
                bsl::error() << "phys is a nullptr\n" << bsl::here();
                return bsl::errc_invalid_argument;
            }

            if (bsl::unlikely_assert(!val)) {
                bsl::error() << "invalid val\n" << bsl::here();
                return bsl::errc_invalid_argument;
            }

            virt = phys + HYPERVISOR_EXT_DIRECT_MAP_ADDR;
            if (bsl::unlikely_assert(!virt)) {
                bsl::error() << "bf_write_phys failed due to invalid physical address "    // --
                             << bsl::hex(phys) << bsl::endl                                // --
                             << bsl::here();

                return bsl::errc_failure;
            }

            *bsl::to_ptr<T *>(virt) = val.get();
            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Performs a virtual address to physical address translation.
        ///     Note that this function only works on direct map memory, which
        ///     includes direct map addresses, allocated pages and allocated
        ///     huge memory.
        ///
        /// <!-- inputs/outputs -->
        ///   @param virt the virtual address to convert
        ///   @return Returns the resulting physical address
        ///
        [[nodiscard]] static constexpr auto
        bf_virt_to_phys(void *const virt) noexcept -> bf_uint64_t
        {
            bsl::safe_uintmax phys{};

            if (bsl::unlikely_assert(nullptr == virt)) {
                bsl::error() << "invalid virt\n" << bsl::here();
                return bf_uint64_t::failure();
            }

            phys = bsl::to_umax(virt) - HYPERVISOR_EXT_DIRECT_MAP_ADDR;
            if (bsl::unlikely(!phys)) {
                bsl::error() << "bf_virt_to_phys arithmetic overflowed\n" << bsl::here();
                return bf_uint64_t::failure();
            }

            return phys;
        }

        /// <!-- description -->
        ///   @brief Performs a physical address to virtual address translation.
        ///     Note that this function only works on direct map memory, which
        ///     includes direct map addresses, allocated pages and allocated
        ///     huge memory.
        ///
        /// <!-- inputs/outputs -->
        ///   @param phys the physical address to convert
        ///   @return Returns the resulting virtual address
        ///
        [[nodiscard]] static constexpr auto
        bf_phys_to_virt(bf_uint64_t const &phys) noexcept -> void *
        {
            bsl::safe_uintmax virt{};

            if (bsl::unlikely_assert(!phys)) {
                bsl::error() << "invalid phys\n" << bsl::here();
                return nullptr;
            }

            if (bsl::unlikely_assert(phys.is_zero())) {
                bsl::error() << "phys is a nullptr\n" << bsl::here();
                return nullptr;
            }

            virt = phys + HYPERVISOR_EXT_DIRECT_MAP_ADDR;
            if (bsl::unlikely(!virt)) {
                bsl::error() << "bf_phys_to_virt arithmetic overflowed\n" << bsl::here();
                return nullptr;
            }

            return bsl::to_ptr<void *>(virt);
        }
    };
}

#endif
