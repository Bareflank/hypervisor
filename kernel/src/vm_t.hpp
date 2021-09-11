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

#ifndef VM_T_HPP
#define VM_T_HPP

#include <allocated_status_t.hpp>
#include <bf_constants.hpp>
#include <ext_pool_t.hpp>
#include <tls_t.hpp>
#include <vp_pool_t.hpp>

#include <bsl/array.hpp>
#include <bsl/debug.hpp>
#include <bsl/ensures.hpp>
#include <bsl/errc_type.hpp>
#include <bsl/expects.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/unlikely.hpp>

namespace mk
{
    /// @class mk::vm_t
    ///
    /// <!-- description -->
    ///   @brief Defines the microkernel's notion of a VM
    ///
    class vm_t final
    {
        /// @brief stores the ID associated with this vm_t
        bsl::safe_u16 m_id{};
        /// @brief stores whether or not this vm_t is allocated.
        allocated_status_t m_allocated{};
        /// @brief stores whether or not this vm_t is active.
        bsl::array<bool, HYPERVISOR_MAX_PPS.get()> m_active{};

    public:
        /// <!-- description -->
        ///   @brief Initializes this vm_t
        ///
        /// <!-- inputs/outputs -->
        ///   @param i the ID for this vm_t
        ///
        constexpr void
        initialize(bsl::safe_u16 const &i) noexcept
        {
            bsl::expects(this->id() == syscall::BF_INVALID_ID);

            bsl::expects(i.is_valid_and_checked());
            bsl::expects(i != syscall::BF_INVALID_ID);

            m_id = ~i;
        }

        /// <!-- description -->
        ///   @brief Release the vm_t.
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_tls the current TLS block
        ///   @param mut_page_pool the page_pool_t to use
        ///   @param mut_ext_pool the ext_pool_t to use
        ///
        constexpr void
        release(tls_t &mut_tls, page_pool_t &mut_page_pool, ext_pool_t &mut_ext_pool) noexcept
        {
            this->deallocate(mut_tls, mut_page_pool, mut_ext_pool);
            m_id = {};
        }

        /// <!-- description -->
        ///   @brief Returns the ID of this vm_t
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the ID of this vm_t
        ///
        [[nodiscard]] constexpr auto
        id() const noexcept -> bsl::safe_u16
        {
            bsl::ensures(m_id.is_valid_and_checked());
            return ~m_id;
        }

        /// <!-- description -->
        ///   @brief Allocates this vm_t
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_tls the current TLS block
        ///   @param mut_page_pool the page_pool_t to use
        ///   @param mut_ext_pool the ext_pool_t to use
        ///   @return Returns ID of the newly allocated vm_t
        ///
        [[nodiscard]] constexpr auto
        allocate(tls_t &mut_tls, page_pool_t &mut_page_pool, ext_pool_t &mut_ext_pool) noexcept
            -> bsl::safe_u16
        {
            bsl::expects(this->id() != syscall::BF_INVALID_ID);
            bsl::expects(allocated_status_t::deallocated == m_allocated);

            auto const ret{mut_ext_pool.signal_vm_created(mut_tls, mut_page_pool, this->id())};
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::safe_u16::failure();
            }

            m_allocated = allocated_status_t::allocated;
            return this->id();
        }

        /// <!-- description -->
        ///   @brief Deallocates this vm_t
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_tls the current TLS block
        ///   @param mut_page_pool the page_pool_t to use
        ///   @param mut_ext_pool the ext_pool_t to use
        ///
        constexpr void
        deallocate(tls_t &mut_tls, page_pool_t &mut_page_pool, ext_pool_t &mut_ext_pool) noexcept
        {
            bsl::expects(this->is_active(mut_tls).is_invalid());

            mut_ext_pool.signal_vm_destroyed(mut_tls, mut_page_pool, this->id());
            m_allocated = allocated_status_t::deallocated;
        }

        /// <!-- description -->
        ///   @brief Returns true if this vm_t is deallocated, false otherwise
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns true if this vm_t is deallocated, false otherwise
        ///
        [[nodiscard]] constexpr auto
        is_deallocated() const noexcept -> bool
        {
            return m_allocated == allocated_status_t::deallocated;
        }

        /// <!-- description -->
        ///   @brief Returns true if this vm_t is allocated, false otherwise
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns true if this vm_t is allocated, false otherwise
        ///
        [[nodiscard]] constexpr auto
        is_allocated() const noexcept -> bool
        {
            return m_allocated == allocated_status_t::allocated;
        }

        /// <!-- description -->
        ///   @brief Sets this vm_t as active.
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_tls the current TLS block
        ///
        constexpr void
        set_active(tls_t &mut_tls) noexcept
        {
            auto const ppid{bsl::to_idx(mut_tls.ppid)};

            bsl::expects(allocated_status_t::allocated == m_allocated);
            bsl::expects(syscall::BF_INVALID_ID == mut_tls.active_vpid);
            bsl::expects(ppid < m_active.size());

            *m_active.at_if(ppid) = true;
            mut_tls.active_vmid = this->id().get();
        }

        /// <!-- description -->
        ///   @brief Sets this vm_t as inactive.
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_tls the current TLS block
        ///
        constexpr void
        set_inactive(tls_t &mut_tls) noexcept
        {
            auto const ppid{bsl::to_idx(mut_tls.ppid)};

            bsl::expects(allocated_status_t::allocated == m_allocated);
            bsl::expects(this->id() == mut_tls.active_vpid);
            bsl::expects(ppid < m_active.size());

            *m_active.at_if(ppid) = false;
            mut_tls.active_vmid = syscall::BF_INVALID_ID.get();
        }

        /// <!-- description -->
        ///   @brief Returns the ID of the first identified PP this vm_t is
        ///     active on. If the vm_t is not active, bsl::safe_u16::failure()
        ///     is returned.
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @return Returns the ID of the first identified PP this vm_t is
        ///     active on. If the vm_t is not active, bsl::safe_u16::failure()
        ///     is returned.
        ///
        [[nodiscard]] constexpr auto
        is_active(tls_t const &tls) const noexcept -> bsl::safe_u16
        {
            auto const online_pps{bsl::to_umx(tls.online_pps)};
            bsl::expects(online_pps <= m_active.size());

            for (bsl::safe_idx mut_i{}; mut_i < online_pps; ++mut_i) {
                if (*m_active.at_if(mut_i)) {
                    return bsl::to_u16(mut_i);
                }

                bsl::touch();
            }

            return bsl::safe_u16::failure();
        }

        /// <!-- description -->
        ///   @brief Returns true if this vm_t is active on the current PP,
        ///     false otherwise
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @return Returns true if this vm_t is active on the current PP,
        ///     false otherwise
        ///
        [[nodiscard]] constexpr auto
        is_active_on_this_pp(tls_t const &tls) const noexcept -> bool
        {
            bsl::expects(bsl::to_umx(tls.ppid) < m_active.size());
            return *m_active.at_if(bsl::to_idx(tls.ppid));
        }

        /// <!-- description -->
        ///   @brief Dumps the vm_t
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///
        constexpr void
        dump(tls_t const &tls) const noexcept
        {
            if constexpr (BSL_DEBUG_LEVEL == bsl::CRITICAL_ONLY) {
                return;
            }

            bsl::print() << bsl::mag << "vm [";
            bsl::print() << bsl::rst << bsl::hex(this->id());
            bsl::print() << bsl::mag << "] dump: ";
            bsl::print() << bsl::rst << bsl::endl;

            /// Header
            ///

            bsl::print() << bsl::ylw << "+---------------------+";
            bsl::print() << bsl::rst << bsl::endl;

            bsl::print() << bsl::ylw << "| ";
            bsl::print() << bsl::cyn << bsl::fmt{"^12s", "description "};
            bsl::print() << bsl::ylw << "| ";
            bsl::print() << bsl::cyn << bsl::fmt{"^6s", "value "};
            bsl::print() << bsl::ylw << "| ";
            bsl::print() << bsl::rst << bsl::endl;

            bsl::print() << bsl::ylw << "+---------------------+";
            bsl::print() << bsl::rst << bsl::endl;

            /// Allocated
            ///

            bsl::print() << bsl::ylw << "| ";
            bsl::print() << bsl::rst << bsl::fmt{"<12s", "allocated "};
            bsl::print() << bsl::ylw << "| ";
            if (this->is_allocated()) {
                bsl::print() << bsl::grn << bsl::fmt{"^6s", "yes "};
            }
            else {
                bsl::print() << bsl::red << bsl::fmt{"^6s", "no "};
            }
            bsl::print() << bsl::ylw << "| ";
            bsl::print() << bsl::rst << bsl::endl;

            /// Active
            ///

            bsl::print() << bsl::ylw << "| ";
            bsl::print() << bsl::rst << bsl::fmt{"<12s", "active "};
            bsl::print() << bsl::ylw << "| ";
            if (this->is_active(tls).is_valid()) {
                bsl::print() << bsl::grn << bsl::fmt{"^6s", "yes "};
            }
            else {
                bsl::print() << bsl::red << bsl::fmt{"^6s", "no "};
            }
            bsl::print() << bsl::ylw << "| ";
            bsl::print() << bsl::rst << bsl::endl;

            /// Footer
            ///

            bsl::print() << bsl::ylw << "+---------------------+";
            bsl::print() << bsl::rst << bsl::endl;
        }
    };
}

#endif
