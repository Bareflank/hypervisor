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

#ifndef SPINLOCK_T_HPP
#define SPINLOCK_T_HPP

#include <bf_constants.hpp>
#include <tls_t.hpp>
#include <yield.hpp>

#include <bsl/convert.hpp>
#include <bsl/debug.hpp>
#include <bsl/is_constant_evaluated.hpp>
#include <bsl/safe_integral.hpp>

#pragma clang diagnostic ignored "-Watomic-implicit-seq-cst"

namespace mk
{
    /// @brief defines when an esr has not executed
    constexpr auto SPINLOCK_ESR_NOT_EXECUTED{0_umax};

    /// @class mk::spinlock_t
    ///
    /// <!-- description -->
    ///   @brief Implements a spinlock_t
    ///
    /// <!-- notes -->
    ///   @note This spinlock_t is designed to detect and prevent deadlock
    ///     when the same PP attempts to take the lock more than once. This
    ///     could occur for example if a hardware exception fires before
    ///     the lock is released. It also handles the case when the lock is
    ///     taken, and then an ESR fires that is legit and must take the
    ///     lock as well.
    ///
    class spinlock_t final
    {
        /// @brief stores the ppid that currently owns the lock (non-ESR)
        bsl::safe_uint16 m_std_ppid;
        /// @brief stores the ppid that currently owns the lock (ESR)
        bsl::safe_uint16 m_esr_ppid;
        /// @brief stores whether or not the lock is acquired
        _Atomic bool m_flag;

    public:
        /// <!-- description -->
        ///   @brief Default constructor.
        ///
        // We cannot member initialize atomics so this is not possible
        // NOLINTNEXTLINE(bsl-class-member-init)
        constexpr spinlock_t() noexcept    // --
            : m_std_ppid{bsl::safe_uint16::failure()}, m_esr_ppid{bsl::safe_uint16::failure()}
        {
            // This is the only way to initialize this
            // NOLINTNEXTLINE(bsl-implicit-conversions-forbidden)
            m_flag = false;
        }

        /// <!-- description -->
        ///   @brief Destructor
        ///
        constexpr ~spinlock_t() noexcept = default;

        /// <!-- description -->
        ///   @brief copy constructor
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being copied
        ///
        constexpr spinlock_t(spinlock_t const &o) noexcept = delete;

        /// <!-- description -->
        ///   @brief move constructor
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being moved
        ///
        constexpr spinlock_t(spinlock_t &&o) noexcept = default;

        /// <!-- description -->
        ///   @brief copy assignment
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being copied
        ///   @return a reference to *this
        ///
        [[maybe_unused]] auto operator=(spinlock_t const &o) &noexcept -> spinlock_t & = delete;

        /// <!-- description -->
        ///   @brief move assignment
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being moved
        ///   @return a reference to *this
        ///
        [[maybe_unused]] auto operator=(spinlock_t &&o) &noexcept -> spinlock_t & = default;

        /// <!-- description -->
        ///   @brief Locks the spinlock_t. This will not return until the
        ///     spinlock_t can be successfully acquired.
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///
        constexpr void
        lock(tls_t const &tls) noexcept
        {
            if (bsl::is_constant_evaluated()) {
                return;
            }

            /// NOTE:
            /// - Perform deadlock detection. If deadlock is detected, we
            ///   return as it means that this PP has already acquired the
            ///   lock with no means that unlock.
            ///

            if (tls.ppid == m_std_ppid) {
                if (tls.esr_ip != SPINLOCK_ESR_NOT_EXECUTED) {
                    if (!m_esr_ppid) {
                        m_esr_ppid = tls.ppid;
                        return;
                    }

                    bsl::touch();
                }
                else {
                    bsl::touch();
                }

                bsl::alert() << "pp "                                       // --
                             << bsl::hex(tls.ppid)                          // --
                             << " acquired the same lock more than once"    // --
                             << bsl::endl;                                  // --

                return;
            }

            if (tls.ppid == m_esr_ppid) {
                if (tls.esr_ip == SPINLOCK_ESR_NOT_EXECUTED) {
                    m_std_ppid = tls.ppid;
                    return;
                }

                bsl::alert() << "pp "                                       // --
                             << bsl::hex(tls.ppid)                          // --
                             << " acquired the same lock more than once"    // --
                             << bsl::endl;                                  // --

                return;
            }

            /// NOTE:
            /// - The __c11_atomic_exchange here attempts to set the lock to
            ///   true. If it is already true, __c11_atomic_exchange will
            ///   return true, which means that the lock was already taken
            ///   by another PP. If this occurs, we need to wait until the
            ///   value that __c11_atomic_exchange returns is false, meaning
            ///   the lock was released. If __c11_atomic_exchange returns
            ///   false right off the bat, it means that the lock was never
            ///   taken at all, and there is nothing else to do.
            /// - The call to __c11_atomic_load reads the value of the lock,
            ///   and will continue to loop while the lock is true, meaning
            ///   it is held by another PP. The reason that __c11_atomic_load
            ///   is called instead of just looping using __c11_atomic_exchange
            ///   all the time is __c11_atomic_exchange uses a fence to ensure
            ///   proper ordering which is expensive. __c11_atomic_load in
            ///   this case, since we used __ATOMIC_RELAXED does not include
            ///   the fence, and so it can loop without killing the pipeline.
            /// - The only issue with this implementation is that once the
            ///   call to __c11_atomic_load returns, we still have not acquired
            ///   the lock as this is what __c11_atomic_exchange does. It is
            ///   possible that between when __c11_atomic_load returns and
            ///   __c11_atomic_exchange executes, another PP will have grabbed
            ///   the lock. Research has shown however that even with this
            ///   issue, this implemenation is the best for a spinlock_t WRT
            ///   overall performance.
            ///

            while (__c11_atomic_exchange(&m_flag, true, __ATOMIC_ACQUIRE)) {
                while (__c11_atomic_load(&m_flag, __ATOMIC_RELAXED)) {
                    yield();
                }
            }

            if (tls.esr_ip == SPINLOCK_ESR_NOT_EXECUTED) {
                m_std_ppid = tls.ppid;
            }
            else {
                m_esr_ppid = tls.ppid;
            }
        }

        /// <!-- description -->
        ///   @brief Unlocks the spinlock_t.
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///
        constexpr void
        unlock(tls_t const &tls) noexcept
        {
            if (bsl::is_constant_evaluated()) {
                return;
            }

            /// NOTE:
            /// - Before we release the lock, we need to make sure that
            ///   we are not holding the lock in both the normal case,
            ///   and the ESR case. If both have been released, we are clear
            ///   to release the lock.
            ///

            if (tls.esr_ip == SPINLOCK_ESR_NOT_EXECUTED) {
                m_std_ppid = bsl::safe_uint16::failure();
            }
            else {
                m_esr_ppid = bsl::safe_uint16::failure();
            }

            if (!!m_std_ppid) {
                return;
            }

            if (!!m_esr_ppid) {
                return;
            }

            /// NOTE:
            /// - Here, we simply need to set the lock flag to false,
            ///   indicating that we no longer are holding the lock. We
            ///   use __ATOMIC_RELEASE to ensure proper memory ordering.
            ///

            __c11_atomic_store(&m_flag, false, __ATOMIC_RELEASE);
        }

        /// <!-- description -->
        ///   @brief Returns true if the spinlock_t is locked
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns true if the spinlock_t is locked
        ///
        [[nodiscard]] constexpr auto
        is_locked() const noexcept -> bool
        {
            return static_cast<bool>(m_flag);
        }
    };
}

#endif
