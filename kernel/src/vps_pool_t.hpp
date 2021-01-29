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

#ifndef VPS_POOL_T_HPP
#define VPS_POOL_T_HPP

#include <bsl/array.hpp>
#include <bsl/debug.hpp>
#include <bsl/errc_type.hpp>
#include <bsl/finally.hpp>
#include <bsl/unlikely.hpp>

namespace mk
{
    /// @class mk::vps_pool_t
    ///
    /// <!-- description -->
    ///   @brief TODO
    ///
    /// <!-- template parameters -->
    ///   @tparam VPS_CONCEPT the type of vps_t that this class manages.
    ///   @tparam INTRINSIC_CONCEPT defines the type of intrinsics to use
    ///   @tparam PAGE_POOL_CONCEPT defines the type of page pool to use
    ///   @tparam MAX_VPSS the max number of VPSs supported
    ///
    template<
        typename VPS_CONCEPT,
        typename INTRINSIC_CONCEPT,
        typename PAGE_POOL_CONCEPT,
        bsl::uintmax MAX_VPSS>
    class vps_pool_t final
    {
        /// @brief stores true if initialized() has been executed
        bool m_initialized;
        /// @brief stores a reference to the intrinsics to use
        INTRINSIC_CONCEPT &m_intrinsic;
        /// @brief stores a reference to the page pool to use
        PAGE_POOL_CONCEPT &m_page_pool;
        /// @brief stores the first VPS_CONCEPT in the VPS_CONCEPT linked list
        VPS_CONCEPT *m_head;
        /// @brief stores the VPS_CONCEPTs in the VPS_CONCEPT linked list
        bsl::array<VPS_CONCEPT, MAX_VPSS> m_pool;

    public:
        /// @brief an alias for VPS_CONCEPT
        using vps_type = VPS_CONCEPT;
        /// @brief an alias for INTRINSIC_CONCEPT
        using intrinsic_type = INTRINSIC_CONCEPT;
        /// @brief an alias for PAGE_POOL_CONCEPT
        using page_pool_type = PAGE_POOL_CONCEPT;

        /// <!-- description -->
        ///   @brief Creates a vps_pool_t
        ///
        /// <!-- inputs/outputs -->
        ///   @param intrinsic the intrinsics to use
        ///   @param page_pool the page pool to use
        ///
        explicit constexpr vps_pool_t(
            INTRINSIC_CONCEPT &intrinsic, PAGE_POOL_CONCEPT &page_pool) noexcept
            : m_initialized{}, m_intrinsic{intrinsic}, m_page_pool{page_pool}, m_head{}, m_pool{}
        {}

        /// <!-- description -->
        ///   @brief Initializes this vps_pool_t
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     otherwise
        ///
        [[nodiscard]] constexpr auto
        initialize() &noexcept -> bsl::errc_type
        {
            bsl::errc_type ret{};

            if (bsl::unlikely(m_initialized)) {
                bsl::error() << "vps_pool_t already initialized\n" << bsl::here();
                return bsl::errc_failure;
            }

            bsl::finally release_on_error{[this]() noexcept -> void {
                this->release();
            }};

            VPS_CONCEPT *prev{};
            for (auto const vps : m_pool) {
                ret = vps.data->initialize(&m_intrinsic, &m_page_pool, bsl::to_u16(vps.index));
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return bsl::errc_failure;
                }

                if (nullptr != prev) {
                    prev->set_next(vps.data);
                }
                else {
                    m_head = vps.data;
                }

                prev = vps.data;
            }

            release_on_error.ignore();
            m_initialized = true;

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Release the vps_t
        ///
        constexpr void
        release() &noexcept
        {
            for (auto const vps : m_pool) {
                vps.data->release();
            }

            m_head = {};
            m_initialized = {};
        }

        /// <!-- description -->
        ///   @brief Destroyes a previously created vps_pool_t
        ///
        constexpr ~vps_pool_t() noexcept = default;

        /// <!-- description -->
        ///   @brief copy constructor
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being copied
        ///
        constexpr vps_pool_t(vps_pool_t const &o) noexcept = delete;

        /// <!-- description -->
        ///   @brief move constructor
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being moved
        ///
        constexpr vps_pool_t(vps_pool_t &&o) noexcept = default;

        /// <!-- description -->
        ///   @brief copy assignment
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being copied
        ///   @return a reference to *this
        ///
        [[maybe_unused]] constexpr auto operator=(vps_pool_t const &o) &noexcept
            -> vps_pool_t & = delete;

        /// <!-- description -->
        ///   @brief move assignment
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being moved
        ///   @return a reference to *this
        ///
        [[maybe_unused]] constexpr auto operator=(vps_pool_t &&o) &noexcept
            -> vps_pool_t & = default;

        /// <!-- description -->
        ///   @brief Allocates a vps from the vps pool. We set the allocated
        ///     vps_t's next() to itself, which indicates that it has been
        ///     allocated.
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam TLS_CONCEPT defines the type of TLS block to use
        ///   @param tls the current TLS block
        ///   @return Returns ID of the newly allocated vps
        ///
        template<typename TLS_CONCEPT>
        [[nodiscard]] constexpr auto
        allocate(TLS_CONCEPT &tls) &noexcept -> bsl::safe_uint16
        {
            if (bsl::unlikely(!m_initialized)) {
                bsl::error() << "vps_pool_t not initialized\n" << bsl::here();
                return bsl::safe_uint16::zero(true);
            }

            if (bsl::unlikely(nullptr == m_head)) {
                bsl::error() << "vps pool out of vpss\n" << bsl::here();
                return bsl::safe_uint16::zero(true);
            }

            if (bsl::unlikely(!m_head->allocate(tls))) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::safe_uint16::zero(true);
            }

            auto *const vps{m_head};
            m_head = m_head->next();

            vps->set_next(vps);
            return vps->id();
        }

        /// <!-- description -->
        ///   @brief Returns a vps previously allocated using the allocate
        ///     function to the vps pool.
        ///
        /// <!-- inputs/outputs -->
        ///   @param vpsid the ID of the vps to deallocate
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     otherwise
        ///
        [[nodiscard]] constexpr auto
        deallocate(bsl::safe_uint16 const &vpsid) &noexcept -> bsl::errc_type
        {
            if (bsl::unlikely(!m_initialized)) {
                bsl::error() << "vps_pool_t not initialized\n" << bsl::here();
                return bsl::errc_failure;
            }

            auto *const vps{m_pool.at_if(bsl::to_umax(vpsid))};
            if (bsl::unlikely(nullptr == vps)) {
                bsl::error() << "invalid vpsid: "    // --
                             << bsl::hex(vpsid)      // --
                             << bsl::endl            // --
                             << bsl::here();         // --

                return bsl::errc_failure;
            }

            if (vps->next() != vps) {
                bsl::error() << "vps with id "            // --
                             << bsl::hex(vpsid)           // --
                             << " was never allocated"    // --
                             << bsl::endl                 // --
                             << bsl::here();              // --

                return bsl::errc_failure;
            }

            vps->deallocate();
            vps->set_next(m_head);
            m_head = vps;

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Stores the provided state in the requested VPS.
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam TLS_CONCEPT defines the type of TLS block to use
        ///   @tparam STATE_SAVE_CONCEPT the type of state save to use
        ///   @param tls the current TLS block
        ///   @param vpsid the ID of the VPS to set the state to
        ///   @param state the state to set the VPS to
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     otherwise
        ///
        template<typename TLS_CONCEPT, typename STATE_SAVE_CONCEPT>
        [[nodiscard]] constexpr auto
        state_save_to_vps(
            TLS_CONCEPT &tls,
            bsl::safe_uint16 const &vpsid,
            STATE_SAVE_CONCEPT const *const state) &noexcept -> bsl::errc_type
        {
            auto *const vps{m_pool.at_if(bsl::to_umax(vpsid))};
            if (bsl::unlikely(nullptr == vps)) {
                bsl::error() << "invalid vpsid: "    // --
                             << bsl::hex(vpsid)      // --
                             << bsl::endl            // --
                             << bsl::here();         // --

                return bsl::errc_failure;
            }

            return vps->state_save_to_vps(tls, state);
        }

        /// <!-- description -->
        ///   @brief Stores the requested VPS state in the provided state save.
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam TLS_CONCEPT defines the type of TLS block to use
        ///   @tparam STATE_SAVE_CONCEPT the type of state save to use
        ///   @param tls the current TLS block
        ///   @param vpsid the ID of the VPS to set the state to
        ///   @param state the state save to store the VPS state to
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     otherwise
        ///
        template<typename TLS_CONCEPT, typename STATE_SAVE_CONCEPT>
        [[nodiscard]] constexpr auto
        vps_to_state_save(
            TLS_CONCEPT &tls,
            bsl::safe_uint16 const &vpsid,
            STATE_SAVE_CONCEPT *const state) &noexcept -> bsl::errc_type
        {
            auto *const vps{m_pool.at_if(bsl::to_umax(vpsid))};
            if (bsl::unlikely(nullptr == vps)) {
                bsl::error() << "invalid vpsid: "    // --
                             << bsl::hex(vpsid)      // --
                             << bsl::endl            // --
                             << bsl::here();         // --

                return bsl::errc_failure;
            }

            return vps->vps_to_state_save(tls, state);
        }

        /// <!-- description -->
        ///   @brief Reads a field from the requested VPS given the index of
        ///     the field to read.
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam TLS_CONCEPT defines the type of TLS block to use
        ///   @tparam FIELD_TYPE the type (i.e., size) of field to read
        ///   @param tls the current TLS block
        ///   @param vpsid the ID of the VPS to read from
        ///   @param index the index of the field to read from the VPS
        ///   @return Returns the value of the requested field from the
        ///     requested VPS or bsl::safe_integral<FIELD_TYPE>::zero(true)
        ///     on failure.
        ///
        template<typename FIELD_TYPE, typename TLS_CONCEPT>
        [[nodiscard]] constexpr auto
        read(TLS_CONCEPT &tls, bsl::safe_uint16 const &vpsid, bsl::safe_uintmax const &index)
            &noexcept -> bsl::safe_integral<FIELD_TYPE>
        {
            auto *const vps{m_pool.at_if(bsl::to_umax(vpsid))};
            if (bsl::unlikely(nullptr == vps)) {
                bsl::error() << "invalid vpsid: "    // --
                             << bsl::hex(vpsid)      // --
                             << bsl::endl            // --
                             << bsl::here();         // --

                return bsl::safe_integral<FIELD_TYPE>::zero(true);
            }

            return vps->template read<FIELD_TYPE>(tls, index);
        }

        /// <!-- description -->
        ///   @brief Writes a field to the requested VPS given the index of
        ///     the field and the value to write.
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam TLS_CONCEPT defines the type of TLS block to use
        ///   @tparam FIELD_TYPE the type (i.e., size) of field to write
        ///   @param tls the current TLS block
        ///   @param vpsid the ID of the VPS to write to
        ///   @param index the index of the field to write to the VPS
        ///   @param value the value to write to the VPS
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     otherwise
        ///
        template<typename FIELD_TYPE, typename TLS_CONCEPT>
        [[nodiscard]] constexpr auto
        write(
            TLS_CONCEPT &tls,
            bsl::safe_uint16 const &vpsid,
            bsl::safe_uintmax const &index,
            bsl::safe_integral<FIELD_TYPE> const &value) &noexcept -> bsl::errc_type
        {
            auto *const vps{m_pool.at_if(bsl::to_umax(vpsid))};
            if (bsl::unlikely(nullptr == vps)) {
                bsl::error() << "invalid vpsid: "    // --
                             << bsl::hex(vpsid)      // --
                             << bsl::endl            // --
                             << bsl::here();         // --

                return bsl::errc_failure;
            }

            return vps->template write<FIELD_TYPE>(tls, index, value);
        }

        /// <!-- description -->
        ///   @brief Reads a field from the requested VPS given a bf_reg_t
        ///     defining the field to read.
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam TLS_CONCEPT defines the type of TLS block to use
        ///   @param tls the current TLS block
        ///   @param vpsid the ID of the VPS to read from
        ///   @param reg a bf_reg_t defining the field to read from the VPS
        ///   @return Returns the value of the requested field from the
        ///     requested VPS or bsl::safe_uintmax::zero(true) on failure.
        ///
        template<typename TLS_CONCEPT>
        [[nodiscard]] constexpr auto
        read_reg(
            TLS_CONCEPT &tls, bsl::safe_uint16 const &vpsid, syscall::bf_reg_t const reg) &noexcept
            -> bsl::safe_uintmax
        {
            auto *const vps{m_pool.at_if(bsl::to_umax(vpsid))};
            if (bsl::unlikely(nullptr == vps)) {
                bsl::error() << "invalid vpsid: "    // --
                             << bsl::hex(vpsid)      // --
                             << bsl::endl            // --
                             << bsl::here();         // --

                return bsl::safe_uintmax::zero(true);
            }

            return vps->read_reg(tls, reg);
        }

        /// <!-- description -->
        ///   @brief Writes a field to the requested VPS given a bf_reg_t
        ///     defining the field and a value to write.
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam TLS_CONCEPT defines the type of TLS block to use
        ///   @param tls the current TLS block
        ///   @param vpsid the ID of the VPS to write to
        ///   @param reg a bf_reg_t defining the field to write to the VPS
        ///   @param value the value to write to the VPS
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     otherwise
        ///
        template<typename TLS_CONCEPT>
        [[nodiscard]] constexpr auto
        write_reg(
            TLS_CONCEPT &tls,
            bsl::safe_uint16 const &vpsid,
            syscall::bf_reg_t const reg,
            bsl::safe_uintmax const &value) &noexcept -> bsl::errc_type
        {
            auto *const vps{m_pool.at_if(bsl::to_umax(vpsid))};
            if (bsl::unlikely(nullptr == vps)) {
                bsl::error() << "invalid vpsid: "    // --
                             << bsl::hex(vpsid)      // --
                             << bsl::endl            // --
                             << bsl::here();         // --

                return bsl::errc_failure;
            }

            return vps->write_reg(tls, reg, value);
        }

        /// <!-- description -->
        ///   @brief Runs the requested VPS. Note that this function does not
        ///     return until a VMExit occurs. Once complete, this function
        ///     will return the VMExit reason.
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam TLS_CONCEPT defines the type of TLS block to use
        ///   @param tls the current TLS block
        ///   @param vpsid the ID of the VPS to run
        ///   @return Returns the VMExit reason on success, or
        ///     bsl::safe_uintmax::zero(true) on failure.
        ///
        template<typename TLS_CONCEPT>
        [[nodiscard]] constexpr auto
        run(TLS_CONCEPT &tls, bsl::safe_uint16 const &vpsid) &noexcept -> bsl::safe_uintmax
        {
            auto *const vps{m_pool.at_if(bsl::to_umax(vpsid))};
            if (bsl::unlikely(nullptr == vps)) {
                bsl::error() << "invalid vpsid: "    // --
                             << bsl::hex(vpsid)      // --
                             << bsl::endl            // --
                             << bsl::here();         // --

                return bsl::safe_uintmax::zero(true);
            }

            return vps->run(tls);
        }

        /// <!-- description -->
        ///   @brief Advance the IP of the requested VPS
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam TLS_CONCEPT defines the type of TLS block to use
        ///   @param tls the current TLS block
        ///   @param vpsid the ID of the VPS to advance the IP for
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     otherwise
        ///
        template<typename TLS_CONCEPT>
        [[nodiscard]] constexpr auto
        advance_ip(TLS_CONCEPT &tls, bsl::safe_uint16 const &vpsid) &noexcept -> bsl::errc_type
        {
            auto *const vps{m_pool.at_if(bsl::to_umax(vpsid))};
            if (bsl::unlikely(nullptr == vps)) {
                bsl::error() << "invalid vpsid: "    // --
                             << bsl::hex(vpsid)      // --
                             << bsl::endl            // --
                             << bsl::here();         // --

                return bsl::errc_failure;
            }

            return vps->advance_ip(tls);
        }

        /// <!-- description -->
        ///   @brief Dumps the requested VPS
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam TLS_CONCEPT defines the type of TLS block to use
        ///   @param tls the current TLS block
        ///   @param vpsid the ID of the VPS to dump
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     otherwise
        ///
        template<typename TLS_CONCEPT>
        [[nodiscard]] constexpr auto
        dump(TLS_CONCEPT &tls, bsl::safe_uint16 const &vpsid) &noexcept -> bsl::errc_type
        {
            auto *const vps{m_pool.at_if(bsl::to_umax(vpsid))};
            if (bsl::unlikely(nullptr == vps)) {
                bsl::error() << "invalid vpsid: "    // --
                             << bsl::hex(vpsid)      // --
                             << bsl::endl            // --
                             << bsl::here();         // --

                return bsl::errc_failure;
            }

            vps->dump(tls);
            return bsl::errc_success;
        }
    };
}

#endif
