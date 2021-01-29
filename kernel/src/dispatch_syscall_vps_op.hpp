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

#ifndef DISPATCH_SYSCALL_VPS_OP_HPP
#define DISPATCH_SYSCALL_VPS_OP_HPP

#include <mk_interface.hpp>
#include <promote.hpp>

#include <bsl/convert.hpp>
#include <bsl/debug.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/unlikely.hpp>

namespace mk
{
    namespace details
    {
        /// <!-- description -->
        ///   @brief Implements the bf_vps_op_create_vps syscall
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam TLS_CONCEPT defines the type of TLS block to use
        ///   @tparam VPS_POOL_CONCEPT defines the type of VPS pool to use
        ///   @param tls the current TLS block
        ///   @param vps_pool the VPS pool to use
        ///   @return Returns syscall::BF_STATUS_SUCCESS on success or an error
        ///     code on failure.
        ///
        template<typename TLS_CONCEPT, typename VPS_POOL_CONCEPT>
        [[nodiscard]] constexpr auto
        syscall_vps_op_create_vps(TLS_CONCEPT &tls, VPS_POOL_CONCEPT &vps_pool)
            -> syscall::bf_status_t
        {
            auto const vpsid{vps_pool.allocate(tls)};
            if (bsl::unlikely(!vpsid)) {
                bsl::print<bsl::V>() << bsl::here();
                return syscall::BF_STATUS_FAILURE_UNKNOWN;
            }

            tls.ext_reg0 = bsl::to_umax(vpsid).get();
            return syscall::BF_STATUS_SUCCESS;
        }

        /// <!-- description -->
        ///   @brief Implements the bf_vps_op_destroy_vps syscall
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam TLS_CONCEPT defines the type of TLS block to use
        ///   @tparam VPS_POOL_CONCEPT defines the type of VPS pool to use
        ///   @param tls the current TLS block
        ///   @param vps_pool the VPS pool to use
        ///   @return Returns syscall::BF_STATUS_SUCCESS on success or an error
        ///     code on failure.
        ///
        template<typename TLS_CONCEPT, typename VPS_POOL_CONCEPT>
        [[nodiscard]] constexpr auto
        syscall_vps_op_destroy_vps(TLS_CONCEPT &tls, VPS_POOL_CONCEPT &vps_pool)
            -> syscall::bf_status_t
        {
            if (bsl::unlikely(!vps_pool.deallocate(bsl::to_u16_unsafe(tls.ext_reg1)))) {
                bsl::print<bsl::V>() << bsl::here();
                return syscall::BF_STATUS_FAILURE_UNKNOWN;
            }

            return syscall::BF_STATUS_SUCCESS;
        }

        /// <!-- description -->
        ///   @brief Implements the bf_vps_op_init_as_root syscall
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam TLS_CONCEPT defines the type of TLS block to use
        ///   @tparam VPS_POOL_CONCEPT defines the type of VPS pool to use
        ///   @param tls the current TLS block
        ///   @param vps_pool the VPS pool to use
        ///   @return Returns syscall::BF_STATUS_SUCCESS on success or an error
        ///     code on failure.
        ///
        template<typename TLS_CONCEPT, typename VPS_POOL_CONCEPT>
        [[nodiscard]] constexpr auto
        syscall_vps_op_init_as_root(TLS_CONCEPT &tls, VPS_POOL_CONCEPT &vps_pool)
            -> syscall::bf_status_t
        {
            auto const ret{vps_pool.state_save_to_vps(
                tls, bsl::to_u16_unsafe(tls.ext_reg1), tls.root_vp_state)};

            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return syscall::BF_STATUS_FAILURE_UNKNOWN;
            }

            return syscall::BF_STATUS_SUCCESS;
        }

        /// <!-- description -->
        ///   @brief Implements the bf_vps_op_read8 syscall
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam TLS_CONCEPT defines the type of TLS block to use
        ///   @tparam VPS_POOL_CONCEPT defines the type of VPS pool to use
        ///   @param tls the current TLS block
        ///   @param vps_pool the VPS pool to use
        ///   @return Returns syscall::BF_STATUS_SUCCESS on success or an error
        ///     code on failure.
        ///
        template<typename TLS_CONCEPT, typename VPS_POOL_CONCEPT>
        [[nodiscard]] constexpr auto
        syscall_vps_op_read8(TLS_CONCEPT &tls, VPS_POOL_CONCEPT &vps_pool) -> syscall::bf_status_t
        {
            auto const ret{vps_pool.template read<bsl::uint8>(
                tls, bsl::to_u16_unsafe(tls.ext_reg1), tls.ext_reg2)};

            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return syscall::BF_STATUS_FAILURE_UNKNOWN;
            }

            constexpr bsl::safe_uintmax mask{0xFFFFFFFFFFFFFF00};
            tls.ext_reg0 = ((tls.ext_reg0 & mask) | bsl::to_umax(ret)).get();
            return syscall::BF_STATUS_SUCCESS;
        }

        /// <!-- description -->
        ///   @brief Implements the bf_vps_op_read16 syscall
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam TLS_CONCEPT defines the type of TLS block to use
        ///   @tparam VPS_POOL_CONCEPT defines the type of VPS pool to use
        ///   @param tls the current TLS block
        ///   @param vps_pool the VPS pool to use
        ///   @return Returns syscall::BF_STATUS_SUCCESS on success or an error
        ///     code on failure.
        ///
        template<typename TLS_CONCEPT, typename VPS_POOL_CONCEPT>
        [[nodiscard]] constexpr auto
        syscall_vps_op_read16(TLS_CONCEPT &tls, VPS_POOL_CONCEPT &vps_pool) -> syscall::bf_status_t
        {
            auto const ret{vps_pool.template read<bsl::uint16>(
                tls, bsl::to_u16_unsafe(tls.ext_reg1), tls.ext_reg2)};

            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return syscall::BF_STATUS_FAILURE_UNKNOWN;
            }

            constexpr bsl::safe_uintmax mask{0xFFFFFFFFFFFF0000};
            tls.ext_reg0 = ((tls.ext_reg0 & mask) | bsl::to_umax(ret)).get();
            return syscall::BF_STATUS_SUCCESS;
        }

        /// <!-- description -->
        ///   @brief Implements the bf_vps_op_read32 syscall
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam TLS_CONCEPT defines the type of TLS block to use
        ///   @tparam VPS_POOL_CONCEPT defines the type of VPS pool to use
        ///   @param tls the current TLS block
        ///   @param vps_pool the VPS pool to use
        ///   @return Returns syscall::BF_STATUS_SUCCESS on success or an error
        ///     code on failure.
        ///
        template<typename TLS_CONCEPT, typename VPS_POOL_CONCEPT>
        [[nodiscard]] constexpr auto
        syscall_vps_op_read32(TLS_CONCEPT &tls, VPS_POOL_CONCEPT &vps_pool) -> syscall::bf_status_t
        {
            auto const ret{vps_pool.template read<bsl::uint32>(
                tls, bsl::to_u16_unsafe(tls.ext_reg1), tls.ext_reg2)};

            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return syscall::BF_STATUS_FAILURE_UNKNOWN;
            }

            constexpr bsl::safe_uintmax mask{0xFFFFFFFF00000000};
            tls.ext_reg0 = ((tls.ext_reg0 & mask) | bsl::to_umax(ret)).get();
            return syscall::BF_STATUS_SUCCESS;
        }

        /// <!-- description -->
        ///   @brief Implements the bf_vps_op_read64 syscall
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam TLS_CONCEPT defines the type of TLS block to use
        ///   @tparam VPS_POOL_CONCEPT defines the type of VPS pool to use
        ///   @param tls the current TLS block
        ///   @param vps_pool the VPS pool to use
        ///   @return Returns syscall::BF_STATUS_SUCCESS on success or an error
        ///     code on failure.
        ///
        template<typename TLS_CONCEPT, typename VPS_POOL_CONCEPT>
        [[nodiscard]] constexpr auto
        syscall_vps_op_read64(TLS_CONCEPT &tls, VPS_POOL_CONCEPT &vps_pool) -> syscall::bf_status_t
        {
            auto const ret{vps_pool.template read<bsl::uint64>(
                tls, bsl::to_u16_unsafe(tls.ext_reg1), tls.ext_reg2)};

            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return syscall::BF_STATUS_FAILURE_UNKNOWN;
            }

            tls.ext_reg0 = ret.get();
            return syscall::BF_STATUS_SUCCESS;
        }

        /// <!-- description -->
        ///   @brief Implements the bf_vps_op_write8 syscall
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam TLS_CONCEPT defines the type of TLS block to use
        ///   @tparam VPS_POOL_CONCEPT defines the type of VPS pool to use
        ///   @param tls the current TLS block
        ///   @param vps_pool the VPS pool to use
        ///   @return Returns syscall::BF_STATUS_SUCCESS on success or an error
        ///     code on failure.
        ///
        template<typename TLS_CONCEPT, typename VPS_POOL_CONCEPT>
        [[nodiscard]] constexpr auto
        syscall_vps_op_write8(TLS_CONCEPT &tls, VPS_POOL_CONCEPT &vps_pool) -> syscall::bf_status_t
        {
            auto const ret{vps_pool.template write<bsl::uint8>(
                tls,
                bsl::to_u16_unsafe(tls.ext_reg1),
                tls.ext_reg2,
                bsl::to_u8_unsafe(tls.ext_reg3))};

            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return syscall::BF_STATUS_FAILURE_UNKNOWN;
            }

            return syscall::BF_STATUS_SUCCESS;
        }

        /// <!-- description -->
        ///   @brief Implements the bf_vps_op_write16 syscall
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam TLS_CONCEPT defines the type of TLS block to use
        ///   @tparam VPS_POOL_CONCEPT defines the type of VPS pool to use
        ///   @param tls the current TLS block
        ///   @param vps_pool the VPS pool to use
        ///   @return Returns syscall::BF_STATUS_SUCCESS on success or an error
        ///     code on failure.
        ///
        template<typename TLS_CONCEPT, typename VPS_POOL_CONCEPT>
        [[nodiscard]] constexpr auto
        syscall_vps_op_write16(TLS_CONCEPT &tls, VPS_POOL_CONCEPT &vps_pool) -> syscall::bf_status_t
        {
            auto const ret{vps_pool.template write<bsl::uint16>(
                tls,
                bsl::to_u16_unsafe(tls.ext_reg1),
                tls.ext_reg2,
                bsl::to_u16_unsafe(tls.ext_reg3))};

            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return syscall::BF_STATUS_FAILURE_UNKNOWN;
            }

            return syscall::BF_STATUS_SUCCESS;
        }

        /// <!-- description -->
        ///   @brief Implements the bf_vps_op_write32 syscall
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam TLS_CONCEPT defines the type of TLS block to use
        ///   @tparam VPS_POOL_CONCEPT defines the type of VPS pool to use
        ///   @param tls the current TLS block
        ///   @param vps_pool the VPS pool to use
        ///   @return Returns syscall::BF_STATUS_SUCCESS on success or an error
        ///     code on failure.
        ///
        template<typename TLS_CONCEPT, typename VPS_POOL_CONCEPT>
        [[nodiscard]] constexpr auto
        syscall_vps_op_write32(TLS_CONCEPT &tls, VPS_POOL_CONCEPT &vps_pool) -> syscall::bf_status_t
        {
            auto const ret{vps_pool.template write<bsl::uint32>(
                tls,
                bsl::to_u16_unsafe(tls.ext_reg1),
                tls.ext_reg2,
                bsl::to_u32_unsafe(tls.ext_reg3))};

            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return syscall::BF_STATUS_FAILURE_UNKNOWN;
            }

            return syscall::BF_STATUS_SUCCESS;
        }

        /// <!-- description -->
        ///   @brief Implements the bf_vps_op_write64 syscall
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam TLS_CONCEPT defines the type of TLS block to use
        ///   @tparam VPS_POOL_CONCEPT defines the type of VPS pool to use
        ///   @param tls the current TLS block
        ///   @param vps_pool the VPS pool to use
        ///   @return Returns syscall::BF_STATUS_SUCCESS on success or an error
        ///     code on failure.
        ///
        template<typename TLS_CONCEPT, typename VPS_POOL_CONCEPT>
        [[nodiscard]] constexpr auto
        syscall_vps_op_write64(TLS_CONCEPT &tls, VPS_POOL_CONCEPT &vps_pool) -> syscall::bf_status_t
        {
            auto const ret{vps_pool.template write<bsl::uint64>(
                tls, bsl::to_u16_unsafe(tls.ext_reg1), tls.ext_reg2, tls.ext_reg3)};

            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return syscall::BF_STATUS_FAILURE_UNKNOWN;
            }

            return syscall::BF_STATUS_SUCCESS;
        }

        /// <!-- description -->
        ///   @brief Implements the bf_vps_op_read_reg syscall
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam TLS_CONCEPT defines the type of TLS block to use
        ///   @tparam VPS_POOL_CONCEPT defines the type of VPS pool to use
        ///   @param tls the current TLS block
        ///   @param vps_pool the VPS pool to use
        ///   @return Returns syscall::BF_STATUS_SUCCESS on success or an error
        ///     code on failure.
        ///
        template<typename TLS_CONCEPT, typename VPS_POOL_CONCEPT>
        [[nodiscard]] constexpr auto
        syscall_vps_op_read_reg(TLS_CONCEPT &tls, VPS_POOL_CONCEPT &vps_pool)
            -> syscall::bf_status_t
        {
            auto const ret{vps_pool.read_reg(
                tls,
                bsl::to_u16_unsafe(tls.ext_reg1),
                static_cast<syscall::bf_reg_t>(tls.ext_reg2))};

            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return syscall::BF_STATUS_FAILURE_UNKNOWN;
            }

            tls.ext_reg0 = ret.get();
            return syscall::BF_STATUS_SUCCESS;
        }

        /// <!-- description -->
        ///   @brief Implements the bf_vps_op_write_reg syscall
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam TLS_CONCEPT defines the type of TLS block to use
        ///   @tparam VPS_POOL_CONCEPT defines the type of VPS pool to use
        ///   @param tls the current TLS block
        ///   @param vps_pool the VPS pool to use
        ///   @return Returns syscall::BF_STATUS_SUCCESS on success or an error
        ///     code on failure.
        ///
        template<typename TLS_CONCEPT, typename VPS_POOL_CONCEPT>
        [[nodiscard]] constexpr auto
        syscall_vps_op_write_reg(TLS_CONCEPT &tls, VPS_POOL_CONCEPT &vps_pool)
            -> syscall::bf_status_t
        {
            auto const ret{vps_pool.write_reg(
                tls,
                bsl::to_u16_unsafe(tls.ext_reg1),
                static_cast<syscall::bf_reg_t>(tls.ext_reg2),
                tls.ext_reg3)};

            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return syscall::BF_STATUS_FAILURE_UNKNOWN;
            }

            return syscall::BF_STATUS_SUCCESS;
        }

        /// <!-- description -->
        ///   @brief Implements the bf_vps_op_run syscall
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam TLS_CONCEPT defines the type of TLS block to use
        ///   @param tls the current TLS block
        ///   @return Returns syscall::BF_STATUS_SUCCESS on success or an error
        ///     code on failure.
        ///
        template<typename TLS_CONCEPT>
        [[nodiscard]] constexpr auto
        syscall_vps_op_run(TLS_CONCEPT &tls) -> syscall::bf_status_t
        {
            tls.active_vpsid = bsl::to_u16_unsafe(tls.ext_reg1).get();
            tls.set_vpid(bsl::to_u16_unsafe(tls.ext_reg2));
            tls.set_vmid(bsl::to_u16_unsafe(tls.ext_reg3));

            /// TODO:
            /// - Need to validate that the IDs are valid. Since this will
            ///   not be executed often, we can afford to check.
            ///

            return_to_mk(bsl::ZERO_UMAX.get());
            return syscall::BF_STATUS_SUCCESS;
        }

        /// <!-- description -->
        ///   @brief Implements the bf_vps_op_run_current syscall
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns syscall::BF_STATUS_SUCCESS on success or an error
        ///     code on failure.
        ///
        [[nodiscard]] inline auto
        syscall_vps_op_run_current() -> syscall::bf_status_t
        {
            return_to_mk(bsl::ZERO_UMAX.get());
            return syscall::BF_STATUS_SUCCESS;
        }

        /// <!-- description -->
        ///   @brief Implements the bf_vps_op_advance_ip syscall
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam TLS_CONCEPT defines the type of TLS block to use
        ///   @tparam VPS_POOL_CONCEPT defines the type of VPS pool to use
        ///   @param tls the current TLS block
        ///   @param vps_pool the VPS pool to use
        ///   @return Returns syscall::BF_STATUS_SUCCESS on success or an error
        ///     code on failure.
        ///
        template<typename TLS_CONCEPT, typename VPS_POOL_CONCEPT>
        [[nodiscard]] constexpr auto
        syscall_vps_op_advance_ip(TLS_CONCEPT &tls, VPS_POOL_CONCEPT &vps_pool)
            -> syscall::bf_status_t
        {
            auto const ret{vps_pool.advance_ip(tls, bsl::to_u16_unsafe(tls.ext_reg1))};
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return syscall::BF_STATUS_FAILURE_UNKNOWN;
            }

            return syscall::BF_STATUS_SUCCESS;
        }

        /// <!-- description -->
        ///   @brief Implements the bf_vps_op_advance_ip_and_run_current syscall
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam TLS_CONCEPT defines the type of TLS block to use
        ///   @tparam VPS_POOL_CONCEPT defines the type of VPS pool to use
        ///   @param tls the current TLS block
        ///   @param vps_pool the VPS pool to use
        ///   @return Returns syscall::BF_STATUS_SUCCESS on success or an error
        ///     code on failure.
        ///
        template<typename TLS_CONCEPT, typename VPS_POOL_CONCEPT>
        [[nodiscard]] constexpr auto
        syscall_vps_op_advance_ip_and_run_current(TLS_CONCEPT &tls, VPS_POOL_CONCEPT &vps_pool)
            -> syscall::bf_status_t
        {
            auto const ret{vps_pool.advance_ip(tls, tls.active_vpsid)};
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return syscall::BF_STATUS_FAILURE_UNKNOWN;
            }

            return_to_mk(bsl::ZERO_UMAX.get());
            return syscall::BF_STATUS_SUCCESS;
        }

        /// <!-- description -->
        ///   @brief Implements the bf_vps_op_promote syscall
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam TLS_CONCEPT defines the type of TLS block to use
        ///   @tparam VPS_POOL_CONCEPT defines the type of VPS pool to use
        ///   @param tls the current TLS block
        ///   @param vps_pool the VPS pool to use
        ///   @return Returns syscall::BF_STATUS_SUCCESS on success or an error
        ///     code on failure.
        ///
        template<typename TLS_CONCEPT, typename VPS_POOL_CONCEPT>
        [[nodiscard]] constexpr auto
        syscall_vps_op_promote(TLS_CONCEPT &tls, VPS_POOL_CONCEPT &vps_pool) -> syscall::bf_status_t
        {
            auto const ret{vps_pool.vps_to_state_save(
                tls, bsl::to_u16_unsafe(tls.ext_reg1), tls.root_vp_state)};

            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return syscall::BF_STATUS_FAILURE_UNKNOWN;
            }

            promote(tls.root_vp_state);
            return syscall::BF_STATUS_SUCCESS;
        }
    }

    /// <!-- description -->
    ///   @brief Dispatches the bf_vps_op syscalls
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam TLS_CONCEPT defines the type of TLS block to use
    ///   @tparam EXT_CONCEPT defines the type of ext_t to use
    ///   @tparam VPS_POOL_CONCEPT defines the type of VPS pool to use
    ///   @param tls the current TLS block
    ///   @param ext the extension that made the syscall
    ///   @param vps_pool the VPS pool to use
    ///   @return Returns syscall::BF_STATUS_SUCCESS on success or an error
    ///     code on failure.
    ///
    template<typename TLS_CONCEPT, typename EXT_CONCEPT, typename VPS_POOL_CONCEPT>
    [[nodiscard]] constexpr auto
    dispatch_syscall_vps_op(TLS_CONCEPT &tls, EXT_CONCEPT const &ext, VPS_POOL_CONCEPT &vps_pool)
        -> syscall::bf_status_t
    {
        syscall::bf_status_t ret{};

        if (bsl::unlikely(!ext.is_handle_valid(tls.ext_reg0))) {
            bsl::error() << "invalid handle: "        // --
                         << bsl::hex(tls.ext_reg0)    // --
                         << bsl::endl                 // --
                         << bsl::here();              // --

            return syscall::BF_STATUS_FAILURE_INVALID_HANDLE;
        }

        if (bsl::unlikely(tls.ext != tls.ext_vmexit)) {
            bsl::error() << "vps_ops not allowed by ext "           // --
                         << bsl::hex(ext.id())                      // --
                         << " as it didn't register for vmexits"    // --
                         << bsl::endl                               // --
                         << bsl::here();                            // --

            return syscall::BF_STATUS_FAILURE_UNKNOWN;
        }

        switch (syscall::bf_syscall_index(tls.ext_syscall).get()) {
            case syscall::BF_VPS_OP_CREATE_VPS_IDX_VAL.get(): {
                ret = details::syscall_vps_op_create_vps(tls, vps_pool);
                if (bsl::unlikely(ret != syscall::BF_STATUS_SUCCESS)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                return ret;
            }

            case syscall::BF_VPS_OP_DESTROY_VPS_IDX_VAL.get(): {
                ret = details::syscall_vps_op_destroy_vps(tls, vps_pool);
                if (bsl::unlikely(ret != syscall::BF_STATUS_SUCCESS)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                return ret;
            }

            case syscall::BF_VPS_OP_INIT_AS_ROOT_IDX_VAL.get(): {
                ret = details::syscall_vps_op_init_as_root(tls, vps_pool);
                if (bsl::unlikely(ret != syscall::BF_STATUS_SUCCESS)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                return ret;
            }

            case syscall::BF_VPS_OP_READ8_IDX_VAL.get(): {
                ret = details::syscall_vps_op_read8(tls, vps_pool);
                if (bsl::unlikely(ret != syscall::BF_STATUS_SUCCESS)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                return ret;
            }

            case syscall::BF_VPS_OP_READ16_IDX_VAL.get(): {
                ret = details::syscall_vps_op_read16(tls, vps_pool);
                if (bsl::unlikely(ret != syscall::BF_STATUS_SUCCESS)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                return ret;
            }

            case syscall::BF_VPS_OP_READ32_IDX_VAL.get(): {
                ret = details::syscall_vps_op_read32(tls, vps_pool);
                if (bsl::unlikely(ret != syscall::BF_STATUS_SUCCESS)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                return ret;
            }

            case syscall::BF_VPS_OP_READ64_IDX_VAL.get(): {
                ret = details::syscall_vps_op_read64(tls, vps_pool);
                if (bsl::unlikely(ret != syscall::BF_STATUS_SUCCESS)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                return ret;
            }

            case syscall::BF_VPS_OP_WRITE8_IDX_VAL.get(): {
                ret = details::syscall_vps_op_write8(tls, vps_pool);
                if (bsl::unlikely(ret != syscall::BF_STATUS_SUCCESS)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                return ret;
            }

            case syscall::BF_VPS_OP_WRITE16_IDX_VAL.get(): {
                ret = details::syscall_vps_op_write16(tls, vps_pool);
                if (bsl::unlikely(ret != syscall::BF_STATUS_SUCCESS)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                return ret;
            }

            case syscall::BF_VPS_OP_WRITE32_IDX_VAL.get(): {
                ret = details::syscall_vps_op_write32(tls, vps_pool);
                if (bsl::unlikely(ret != syscall::BF_STATUS_SUCCESS)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                return ret;
            }

            case syscall::BF_VPS_OP_WRITE64_IDX_VAL.get(): {
                ret = details::syscall_vps_op_write64(tls, vps_pool);
                if (bsl::unlikely(ret != syscall::BF_STATUS_SUCCESS)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                return ret;
            }

            case syscall::BF_VPS_OP_READ_REG_IDX_VAL.get(): {
                ret = details::syscall_vps_op_read_reg(tls, vps_pool);
                if (bsl::unlikely(ret != syscall::BF_STATUS_SUCCESS)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                return ret;
            }

            case syscall::BF_VPS_OP_WRITE_REG_IDX_VAL.get(): {
                ret = details::syscall_vps_op_write_reg(tls, vps_pool);
                if (bsl::unlikely(ret != syscall::BF_STATUS_SUCCESS)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                return ret;
            }

            case syscall::BF_VPS_OP_RUN_IDX_VAL.get(): {
                ret = details::syscall_vps_op_run(tls);
                if (bsl::unlikely(ret != syscall::BF_STATUS_SUCCESS)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                return ret;
            }

            case syscall::BF_VPS_OP_RUN_CURRENT_IDX_VAL.get(): {
                ret = details::syscall_vps_op_run_current();
                if (bsl::unlikely(ret != syscall::BF_STATUS_SUCCESS)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                return ret;
            }

            case syscall::BF_VPS_OP_ADVANCE_IP_IDX_VAL.get(): {
                ret = details::syscall_vps_op_advance_ip(tls, vps_pool);
                if (bsl::unlikely(ret != syscall::BF_STATUS_SUCCESS)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                return ret;
            }

            case syscall::BF_VPS_OP_ADVANCE_IP_AND_RUN_CURRENT_IDX_VAL.get(): {
                ret = details::syscall_vps_op_advance_ip_and_run_current(tls, vps_pool);
                if (bsl::unlikely(ret != syscall::BF_STATUS_SUCCESS)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                return ret;
            }

            case syscall::BF_VPS_OP_PROMOTE_IDX_VAL.get(): {
                ret = details::syscall_vps_op_promote(tls, vps_pool);
                if (bsl::unlikely(ret != syscall::BF_STATUS_SUCCESS)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                return ret;
            }

            default: {
                bsl::error() << "unknown syscall index: "    //--
                             << bsl::hex(tls.ext_syscall)    //--
                             << bsl::endl                    //--
                             << bsl::here();                 //--

                return syscall::BF_STATUS_FAILURE_UNKNOWN;
            }
        }
    }
}

#endif
