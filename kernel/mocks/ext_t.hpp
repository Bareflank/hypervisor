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

#ifndef MOCKS_EXT_T_HPP
#define MOCKS_EXT_T_HPP

#include <alloc_huge_t.hpp>
#include <alloc_page_t.hpp>
#include <bf_constants.hpp>
#include <huge_pool_t.hpp>
#include <intrinsic_t.hpp>
#include <mk_args_t.hpp>
#include <page_pool_t.hpp>
#include <root_page_table_t.hpp>
#include <tls_t.hpp>

#include <bsl/convert.hpp>
#include <bsl/debug.hpp>
#include <bsl/discard.hpp>
#include <bsl/ensures.hpp>
#include <bsl/errc_type.hpp>
#include <bsl/expects.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/touch.hpp>
#include <bsl/unlikely.hpp>

/// TODO:
/// - Add support for multiple extensions. For this to work, we will need
///   support for PCID and the global flag should be turned off. This will
///   ensure that swaps to another extension (which require a CR3 change),
///   will not destroy performance. To ensure the hypervisor can support
///   systems without PCID, projects that use more than one extension like
///   MicroV should compile the additional extensions into both the main
///   extension, and the additional ones. On systems that don't have PCID,
///   it would call itself. Systems with PCID would call through IPC. You
///   could then have compile/runtime flags for forcing one path over the
///   other in situations where performace or security take precedence.
/// - Since the microkernel doesn't have a timer, the only way another
///   extension will execute is from some sort of IPC interface where an
///   extension calls into another extension to perform an action and then
///   returns a result. The best way to handle this would be to use an
///   instruction sequence similar to a VMCall and VMExit. The extension
///   would execute bf_ipc_op_call, which could take at most 6 arguments
///   that match the SysV calling conventions. The additional extension
///   would execute and then return using bf_ipc_op_return. There would
///   need to be some logic in the syscall code to make sure that this
///   return function was used properly (meaning you cannot return unless
///   you have been called, and you cannot run if you have been called).
///   From there, all that is finally needed is some way to share memory.
///   There are two options here. Shared memory, or a memcpy ABI. IMO, we
///   should use a memcpy ABI as shared memory really complicates things.
///   If shared memory is used, we should make sure, that like freeing a
///   page, unmapping shared memory is optional, meaning the microkernel
///   is nor required to honor the request.
/// - The TLS block that we use for the general purpose registers will need
///   to be shared as it is currently a problem. This way, a swap to another
///   extension only has to update the extension ID in that block, and then
///   swap CR3. The best way to handle this would be to have the extension
///   pool can allocate the shared portion of the TLS blocks for all of the
///   online PPs and then give this page to each extension as it initializes.
///   Then all we have to do is make sure that there is no state in there that
///   would be a problem for the extensions to share, which right now is just
///   the extension ID. If additional state is added to the ABI that is a
///   problem, we will either have to copy the entire block on each swap,
///   or make add a second page to the ABI, one that is shared, and one that
///   is not.

namespace mk
{
    /// <!-- description -->
    ///   @brief Defines an extension WRT to the microkernel. Whenever an
    ///     executes, it must go through this class to do so. This class
    ///     also maintains all of the resources given to an extension, as
    ///     well as the extension's memory map, ELF file, stack, TLS blocks,
    ///     and all of it's memory map functions.
    ///
    class ext_t final
    {
        /// @brief stores the ID associated with this ext_t
        bsl::safe_u16 m_id{};
        /// @brief stores the extension's handle
        bsl::safe_u16 m_handle{};
        /// @brief stores true if start() has been executed
        bool m_has_executed_start{};
        /// @brief stores true if fail_entry() is being executed
        bool m_is_executing_fail{};

        /// @brief stores the main IP registered by the extension
        bsl::safe_u64 m_entry_ip{};
        /// @brief stores the bootstrap IP registered by the extension
        bsl::safe_u64 m_bootstrap_ip{};
        /// @brief stores the vmexit IP registered by the extension
        bsl::safe_u64 m_vmexit_ip{};
        /// @brief stores the fail IP registered by the extension
        bsl::safe_u64 m_fail_ip{};

    public:
        /// <!-- description -->
        ///   @brief Initializes this ext_t
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param page_pool the page_pool_t to use
        ///   @param i the ID for this ext_t
        ///   @param file the ELF file for this ext_t
        ///   @param system_rpt the system RPT provided by the loader
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        initialize(
            tls_t const &tls,
            page_pool_t const &page_pool,
            bsl::safe_u16 const &i,
            loader::ext_elf_file_t const *const file,
            root_page_table_t const &system_rpt) noexcept -> bsl::errc_type
        {
            bsl::expects(i.is_valid_and_checked());
            bsl::expects(i != syscall::BF_INVALID_ID);

            bsl::discard(file);
            bsl::discard(page_pool);
            bsl::discard(system_rpt);

            m_id = ~i;
            return tls.test_ret;
        }

        /// <!-- description -->
        ///   @brief Release the ext_t
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param page_pool the page_pool_t to use
        ///   @param huge_pool the huge_pool_t to use
        ///
        constexpr void
        release(
            tls_t const &tls, page_pool_t const &page_pool, huge_pool_t const &huge_pool) noexcept
        {
            bsl::discard(tls);
            bsl::discard(page_pool);
            bsl::discard(huge_pool);

            m_fail_ip = {};
            m_vmexit_ip = {};
            m_bootstrap_ip = {};

            m_is_executing_fail = {};
            m_has_executed_start = {};
            m_handle = {};
            m_id = {};
        }

        /// <!-- description -->
        ///   @brief Returns the ID of this ext_t
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the ID of this ext_t
        ///
        [[nodiscard]] constexpr auto
        id() const noexcept -> bsl::safe_u16
        {
            bsl::ensures(m_id.is_valid_and_checked());
            return ~m_id;
        }

        /// <!-- description -->
        ///   @brief Returns the bootstrap IP for this extension.
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the bootstrap IP for this extension.
        ///
        [[nodiscard]] constexpr auto
        bootstrap_ip() const noexcept -> bsl::safe_u64 const &
        {
            bsl::ensures(m_bootstrap_ip.is_valid_and_checked());
            return m_bootstrap_ip;
        }

        /// <!-- description -->
        ///   @brief Sets the bootstrap IP for this extension. This should
        ///     be called by the syscall dispatcher as the result of a
        ///     syscall from the extension defining what IP the extension
        ///     would like to use for bootstrapping.
        ///
        /// <!-- inputs/outputs -->
        ///   @param ip the bootstrap IP to use
        ///
        constexpr void
        set_bootstrap_ip(bsl::safe_u64 const &ip) noexcept
        {
            bsl::expects(ip.is_valid_and_checked());
            bsl::expects(ip.is_pos());

            m_bootstrap_ip = ip;
        }

        /// <!-- description -->
        ///   @brief Returns the VMExit IP for this extension.
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the VMExit IP for this extension.
        ///
        [[nodiscard]] constexpr auto
        vmexit_ip() const noexcept -> bsl::safe_u64 const &
        {
            bsl::ensures(m_vmexit_ip.is_valid_and_checked());
            return m_vmexit_ip;
        }

        /// <!-- description -->
        ///   @brief Sets the VMExit IP for this extension. This should
        ///     be called by the syscall dispatcher as the result of a
        ///     syscall from the extension defining what IP the extension
        ///     would like to use for VMExits.
        ///
        /// <!-- inputs/outputs -->
        ///   @param ip the VMExit IP to use
        ///
        constexpr void
        set_vmexit_ip(bsl::safe_u64 const &ip) noexcept
        {
            bsl::expects(ip.is_valid_and_checked());
            bsl::expects(ip.is_pos());

            m_vmexit_ip = ip;
        }

        /// <!-- description -->
        ///   @brief Returns the fast fail IP for this extension.
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the fast fail IP for this extension.
        ///
        [[nodiscard]] constexpr auto
        fail_ip() const noexcept -> bsl::safe_u64 const &
        {
            bsl::ensures(m_fail_ip.is_valid_and_checked());
            return m_fail_ip;
        }

        /// <!-- description -->
        ///   @brief Sets the fast fail IP for this extension. This should
        ///     be called by the syscall dispatcher as the result of a
        ///     syscall from the extension defining what IP the extension
        ///     would like to use for fail callbacks.
        ///
        /// <!-- inputs/outputs -->
        ///   @param ip the fail IP to use
        ///
        constexpr void
        set_fail_ip(bsl::safe_u64 const &ip) noexcept
        {
            bsl::expects(ip.is_valid_and_checked());
            bsl::expects(ip.is_pos());

            m_fail_ip = ip;
        }

        /// <!-- description -->
        ///   @brief Opens a handle and returns the resulting handle
        ///
        /// <!-- inputs/outputs -->
        ///   @return Opens a handle and returns the resulting handle
        ///
        [[nodiscard]] constexpr auto
        open_handle() noexcept -> bsl::safe_u64
        {
            if (bsl::unlikely(m_handle.is_pos())) {
                bsl::error() << "handle already opened\n" << bsl::here();
                return bsl::safe_u64::failure();
            }

            m_handle = m_id;
            return this->handle();
        }

        /// <!-- description -->
        ///   @brief Closes a previously opened handle
        ///
        constexpr void
        close_handle() noexcept
        {
            m_handle = {};
        }

        /// <!-- description -->
        ///   @brief Returns true if provided handle is valid
        ///
        /// <!-- inputs/outputs -->
        ///   @param hndl the handle to verify
        ///   @return Returns true if provided handle is valid
        ///
        [[nodiscard]] constexpr auto
        is_handle_valid(bsl::safe_u64 const &hndl) const noexcept -> bool
        {
            bsl::expects(hndl.is_valid_and_checked());
            return hndl == this->handle();
        }

        /// <!-- description -->
        ///   @brief Returns the ID of this ext_t
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the ID of this ext_t
        ///
        [[nodiscard]] constexpr auto
        handle() const noexcept -> bsl::safe_u64
        {
            bsl::ensures(m_handle.is_valid_and_checked());
            return ~bsl::to_u64(m_handle);
        }

        /// <!-- description -->
        ///   @brief Returns true if the extension's main function has
        ///     completed it's execution.
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns true if the extension's main function has
        ///     completed it's execution.
        ///
        [[nodiscard]] constexpr auto
        is_started() const noexcept -> bool
        {
            return m_has_executed_start;
        }

        /// <!-- description -->
        ///   @brief Returns true if the extension's main function is
        ///     executing the fail_entry().
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns true if the extension's main function is
        ///     executing the fail_entry().
        ///
        [[nodiscard]] constexpr auto
        is_executing_fail() const noexcept -> bool
        {
            return m_is_executing_fail;
        }

        /// <!-- description -->
        ///   @brief Allocates a page and maps it into the extension's
        ///     address space.
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param page_pool the page_pool_t to use
        ///   @return Returns a alloc_page_t containing the virtual address and
        ///     physical address of the page. If an error occurs, this
        ///     function will return an invalid virtual and physical address.
        ///
        [[nodiscard]] static constexpr auto
        alloc_page(tls_t const &tls, page_pool_t const &page_pool) noexcept -> alloc_page_t
        {
            bsl::discard(page_pool);
            return {tls.test_virt, tls.test_phys};
        }

        /// <!-- description -->
        ///   @brief Allocates a physically contiguous block of memory and maps
        ///     it into the extension's address space.
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param page_pool the page_pool_t to use
        ///   @param huge_pool the huge_pool_t to use
        ///   @param size the total number of bytes to allocate
        ///   @return Returns a huge_t containing the virtual address and
        ///     physical address of the memory block. If an error occurs, this
        ///     function will return an invalid virtual and physical address.
        ///
        [[nodiscard]] static constexpr auto
        alloc_huge(
            tls_t const &tls,
            page_pool_t const &page_pool,
            huge_pool_t const &huge_pool,
            bsl::safe_umx const &size) noexcept -> alloc_huge_t
        {
            bsl::expects(size.is_valid_and_checked());
            bsl::expects(size.is_pos());

            bsl::discard(page_pool);
            bsl::discard(huge_pool);

            return {tls.test_virt, tls.test_phys};
        }

        /// <!-- description -->
        ///   @brief Maps a page into the direct map portion of the requested
        ///     VM's direct map RPT given a physical address to map.
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param page_pool the page_pool_t to use
        ///   @param vmid the ID of the VM to map page_phys to
        ///   @param page_phys the physical address to map
        ///   @return Returns the virtual address the physical address was
        ///     mapped to in the direct map. On failure returns
        ///     bsl::safe_u64::failure().
        ///
        [[nodiscard]] static constexpr auto
        map_page_direct(
            tls_t const &tls,
            page_pool_t const &page_pool,
            bsl::safe_u16 const &vmid,
            bsl::safe_u64 const &page_phys) noexcept -> bsl::safe_u64
        {
            bsl::discard(page_pool);
            bsl::discard(vmid);
            bsl::discard(page_phys);

            return tls.test_virt;
        }

        /// <!-- description -->
        ///   @brief Unmaps a page from the direct map portion of the requested
        ///     VM's direct map RPT given a virtual address to unmap.
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param page_pool the page_pool_t to use
        ///   @param intrinsic the intrinsic_t to use
        ///   @param vmid the ID of the VM to unmap page_virt to
        ///   @param page_virt the virtual address to map
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] static constexpr auto
        unmap_page_direct(
            tls_t const &tls,
            page_pool_t const &page_pool,
            intrinsic_t const &intrinsic,
            bsl::safe_u16 const &vmid,
            bsl::safe_u64 const &page_virt) noexcept -> bsl::errc_type
        {
            bsl::discard(page_pool);
            bsl::discard(intrinsic);
            bsl::discard(vmid);
            bsl::discard(page_virt);

            return tls.test_ret;
        }

        /// <!-- description -->
        ///   @brief Tells the extension that a VM was created so that it
        ///     can initialize it's VM specific resources.
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param page_pool the page_pool_t to use
        ///   @param vmid the ID of the VM that was created.
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] static constexpr auto
        signal_vm_created(
            tls_t const &tls, page_pool_t const &page_pool, bsl::safe_u16 const &vmid) noexcept
            -> bsl::errc_type
        {
            bsl::discard(page_pool);
            bsl::discard(vmid);

            return tls.test_ret;
        }

        /// <!-- description -->
        ///   @brief Tells the extension that a VM was destroyed so that it
        ///     can release it's VM specific resources.
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param page_pool the page_pool_t to use
        ///   @param vmid the ID of the VM that was destroyed.
        ///
        static constexpr void
        signal_vm_destroyed(
            tls_t const &tls, page_pool_t const &page_pool, bsl::safe_u16 const &vmid) noexcept
        {
            bsl::discard(tls);
            bsl::discard(page_pool);
            bsl::discard(vmid);
        }

        /// <!-- description -->
        ///   @brief Tells the extension that the requested VM was set to
        ///     active and therefore it's memory map should change on this PP.
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param intrinsic the intrinsic_t to use
        ///   @param vmid the ID of the VM that was created.
        ///
        static constexpr void
        signal_vm_active(
            tls_t const &tls, intrinsic_t const &intrinsic, bsl::safe_u16 const &vmid) noexcept
        {
            bsl::discard(tls);
            bsl::discard(intrinsic);
            bsl::discard(vmid);
        }

        /// <!-- description -->
        ///   @brief Starts the extension by executing it's _start entry point.
        ///     If the extension has not been initialized, this function will
        ///     return bsl::errc_success.
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param intrinsic the intrinsic_t to use
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        start(tls_t const &tls, intrinsic_t const &intrinsic) noexcept -> bsl::errc_type
        {
            bsl::discard(intrinsic);

            if (tls.test_ret) {
                m_has_executed_start = true;
            }
            else {
                bsl::touch();
            }

            return tls.test_ret;
        }

        /// <!-- description -->
        ///   @brief Bootstraps the extension by executing it's bootstrap entry
        ///     point. If the extension has not been initialized, this function
        ///     will return bsl::errc_success.
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param intrinsic the intrinsic_t to use
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] static constexpr auto
        bootstrap(tls_t const &tls, intrinsic_t const &intrinsic) noexcept -> bsl::errc_type
        {
            bsl::discard(intrinsic);
            return tls.test_ret;
        }

        /// <!-- description -->
        ///   @brief Bootstraps the extension by executing it's bootstrap entry
        ///     point. If the extension has not been initialized, this function
        ///     will return bsl::errc_success.
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param intrinsic the intrinsic_t to use
        ///   @param exit_reason the reason for the VMExit
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] static constexpr auto
        vmexit(
            tls_t const &tls,
            intrinsic_t const &intrinsic,
            bsl::safe_u64 const &exit_reason) noexcept -> bsl::errc_type
        {
            bsl::discard(intrinsic);
            bsl::discard(exit_reason);

            return tls.test_ret;
        }

        /// <!-- description -->
        ///   @brief Bootstraps the extension by executing it's bootstrap entry
        ///     point. If the extension has not been initialized, this function
        ///     will return bsl::errc_success.
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param intrinsic the intrinsic_t to use
        ///   @param errc the reason for the failure, which is CPU
        ///     specific. On x86, this is a combination of the exception
        ///     vector and error code.
        ///   @param addr contains a faulting address if the fail reason
        ///     is associated with an error that involves a faulting address (
        ///     for example like a page fault). Otherwise, the value of this
        ///     input is undefined.
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        fail(
            tls_t const &tls,
            intrinsic_t const &intrinsic,
            bsl::safe_u64 const &errc,
            bsl::safe_u64 const &addr) noexcept -> bsl::errc_type
        {
            bsl::discard(intrinsic);
            bsl::discard(errc);
            bsl::discard(addr);

            if (tls.test_ret) {
                m_is_executing_fail = true;
            }
            else {
                bsl::touch();
            }

            return tls.test_ret;
        }

        /// <!-- description -->
        ///   @brief Dumps the vm_t
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///
        static constexpr void
        dump(tls_t const &tls) noexcept
        {
            bsl::discard(tls);
        }
    };
}

#endif
