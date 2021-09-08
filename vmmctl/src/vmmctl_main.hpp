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

#ifndef VMMCTL_MAIN_HPP
#define VMMCTL_MAIN_HPP

#include <debug_ring_t.hpp>
#include <dump_vmm_args_t.hpp>
#include <ifmap.hpp>
#include <ioctl.hpp>
#include <loader_platform_interface.hpp>
#include <start_vmm_args_t.hpp>
#include <stop_vmm_args_t.hpp>

#include <bsl/arguments.hpp>
#include <bsl/array.hpp>
#include <bsl/carray.hpp>
#include <bsl/convert.hpp>
#include <bsl/debug.hpp>
#include <bsl/errc_type.hpp>
#include <bsl/move.hpp>
#include <bsl/safe_idx.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/span.hpp>
#include <bsl/string_view.hpp>
#include <bsl/touch.hpp>
#include <bsl/unlikely.hpp>

namespace vmmctl
{
    /// @brief defines the IOCTL version this code supports.
    constexpr auto IOCTL_VERSION{1_umx};

    /// @class vmmctl::vmmctl_main
    ///
    /// <!-- description -->
    ///   @brief Provides the main implementation of the vmmctl application.
    ///     This application is used to start and stop the VMM as well as
    ///     to dump the contents of the VMM's internal debug ring to the
    ///     console for debugging.
    ///
    class vmmctl_main final
    {
        /// @brief stores the mapped ELF file for the microkernel
        ifmap m_mapped_mk_elf_file{};
        /// @brief stores the mapped ELF files for each extension
        bsl::array<ifmap, HYPERVISOR_MAX_EXTENSIONS.get()> m_mapped_ext_elf_files{};
        /// @brief stores the arguments for starting the VMM.
        loader::start_vmm_args_t m_start_vmm_ctl_args{};
        /// @brief stores the arguments for stopping the VMM.
        loader::stop_vmm_args_t m_stop_vmm_ctl_args{IOCTL_VERSION.get()};
        /// @brief stores the arguments for dumping the VMM.
        loader::dump_vmm_args_t m_dump_vmm_ctl_args{IOCTL_VERSION.get(), {}};

        /// <!-- description -->
        ///   @brief Displays the help menu for vmmctl
        ///
        static constexpr void
        help() noexcept
        {
            bsl::print() << "Usage: vmmctl start microkernel ext1 <ext2> ..." << bsl::endl;
            bsl::print() << "  or:  vmmctl stop" << bsl::endl;
            bsl::print() << "  or:  vmmctl dump" << bsl::endl;
            bsl::print() << bsl::endl;
            bsl::print() << "A utility for managing the Bareflank Hypervisor's VMM";
            bsl::print() << bsl::endl;
        }

        /// <!-- description -->
        ///   @brief Writes a provided request to the loader given an ioctl
        ///     to the loader as well as the arguments to send to the loader.
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam R the type that defines the request to give the loader
        ///   @tparam A the type that defines the arguments to give the loader
        ///   @param request the request to give the loader
        ///   @param ctl the ioctl to the loader
        ///   @param ctl_args the arguments to give the loader
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     otherwise
        ///
        template<typename R, typename A>
        [[nodiscard]] constexpr auto
        write_data(R const &request, ioctl const &ctl, A const *const ctl_args) const noexcept
            -> bsl::errc_type
        {
            bool const ret{ctl.write_data(request, ctl_args, bsl::to_umx(sizeof(A)))};
            if (bsl::unlikely(!ret)) {
                bsl::error() << "vmmctl failed. check kernel logs details\n";
                return bsl::errc_failure;
            }

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Writes a provided request to the loader given an ioctl
        ///     to the loader as well as the arguments to send to the loader.
        ///     The results of the ioctl are returned in the provided args.
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam R the type that defines the request to give the loader
        ///   @tparam A the type that defines the arguments to give the loader
        ///   @param request the request to give the loader
        ///   @param ctl the ioctl to the loader
        ///   @param pmut_ctl_args the arguments to give the loader
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     otherwise
        ///
        template<typename R, typename A>
        [[nodiscard]] constexpr auto
        read_write_data(R const &request, ioctl const &ctl, A *const pmut_ctl_args) const noexcept
            -> bsl::errc_type
        {
            bool const ret{ctl.read_write_data(request, pmut_ctl_args, bsl::to_umx(sizeof(A)))};
            if (bsl::unlikely(!ret)) {
                bsl::error() << "vmmctl failed. check kernel logs details\n";
                return bsl::errc_failure;
            }

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Starts the VMM given a set of ioctl arguments to send
        ///     to the loader.
        ///
        /// <!-- inputs/outputs -->
        ///   @param ctl_args the command line arguments provided by the user.
        ///   @return Returns bsl::errc_success if the VMM was successfully
        ///     started, otherwise returns bsl::errc_failure.
        ///
        [[nodiscard]] constexpr auto
        start_vmm(loader::start_vmm_args_t const *const ctl_args) const noexcept -> bsl::errc_type
        {
            ioctl const ctl{loader::DEVICE_NAME};
            if (bsl::unlikely(!ctl)) {
                return bsl::errc_failure;
            }

            return this->write_data(loader::START_VMM, ctl, ctl_args);
        }

        /// <!-- description -->
        ///   @brief Stops the VMM given a set of ioctl arguments to send
        ///     to the loader.
        ///
        /// <!-- inputs/outputs -->
        ///   @param ctl_args the command line arguments provided by the user.
        ///   @return Returns bsl::errc_success if the VMM was successfully
        ///     stopped, otherwise returns bsl::errc_failure.
        ///
        [[nodiscard]] constexpr auto
        stop_vmm(loader::stop_vmm_args_t const *const ctl_args) const noexcept -> bsl::errc_type
        {
            ioctl const ctl{loader::DEVICE_NAME};
            if (bsl::unlikely(!ctl)) {
                return bsl::errc_failure;
            }

            return this->write_data(loader::STOP_VMM, ctl, ctl_args);
        }

        /// <!-- description -->
        ///   @brief Dumps the VMM given a set of ioctl arguments to send
        ///     to the loader.
        ///
        /// <!-- inputs/outputs -->
        ///   @param pmut_ctl_args the command line arguments provided by the user.
        ///   @return Returns bsl::errc_success if the VMM was successfully
        ///     dumped to the console, otherwise returns bsl::errc_failure.
        ///
        [[nodiscard]] constexpr auto
        dump_vmm(loader::dump_vmm_args_t *const pmut_ctl_args) const noexcept -> bsl::errc_type
        {
            ioctl const ctl{loader::DEVICE_NAME};
            if (bsl::unlikely(!ctl)) {
                return bsl::errc_failure;
            }

            auto const ret{this->read_write_data(loader::DUMP_VMM, ctl, pmut_ctl_args)};
            if (bsl::unlikely(bsl::errc_success != ret)) {
                return ret;
            }

            bsl::safe_idx mut_epos{pmut_ctl_args->debug_ring.epos};
            bsl::safe_idx mut_spos{pmut_ctl_args->debug_ring.spos};

            if (!(pmut_ctl_args->debug_ring.buf.size() > mut_epos)) {
                mut_epos = {};
            }
            else {
                bsl::touch();
            }

            if (mut_spos == mut_epos) {
                bsl::alert() << "no debug data to dump\n";
                return bsl::errc_success;
            }

            while (mut_spos != mut_epos) {
                if (!(pmut_ctl_args->debug_ring.buf.size() > mut_spos)) {
                    mut_spos = {};
                }
                else {
                    bsl::touch();
                }

                bsl::print() << *pmut_ctl_args->debug_ring.buf.at_if(mut_spos.get());
                ++mut_spos;
            }

            bsl::print() << bsl::endl;
            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Maps an ELF file by getting the filename and path from
        ///     the arguments provided by the user, opening the ELF file, and
        ///     then storing the newly opened map in the map provided. Returns
        ///     bsl::errc_success and increments the provided arguments if the
        ///     ELF file was successfully mapped, otherwise this function
        ///     returns bsl::errc_failure.
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_args the user provided arguments. It is assumed that the
        ///     "front" of these args stores a string containing the filename
        ///     and path to the ELF file to map and store.
        ///   @param mut_map the map to store the newly opened ELF file.
        ///   @return Returns bsl::errc_success and increments the provided
        ///     arguments if the ELF file was successfully mapped, otherwise
        ///     this function returns bsl::errc_failure.
        ///
        [[nodiscard]] static constexpr auto
        map_elf_file(bsl::arguments &mut_args, ifmap &mut_map) noexcept -> bsl::errc_type
        {
            mut_map = ifmap{mut_args.front<bsl::string_view>()};
            if (bsl::unlikely(!mut_map)) {
                return bsl::errc_failure;
            }

            ++mut_args;
            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief This function maps the microkernel ELF file provided by
        ///     the user. When we map the ELF file, we store the map in a
        ///     private member variable. This ensures the map is not unmapped
        ///     until the start command is complete.
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_args the arguments provided by the user.
        ///   @return Returns bsl::errc_success and increments the provided
        ///     arguments if the microkernel ELF file was successfully mapped,
        ///     otherwise this function returns bsl::errc_failure.
        ///
        [[nodiscard]] constexpr auto
        map_mk_elf_file_from_user(bsl::arguments &mut_args) noexcept -> bsl::errc_type
        {
            return this->map_elf_file(mut_args, m_mapped_mk_elf_file);
        }

        /// <!-- description -->
        ///   @brief This function maps the extension ELF files provided by
        ///     the user. When we map the ELF files, we store the maps in a
        ///     private member variable. This ensures the maps are not unmapped
        ///     until the start command is complete.
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_args the arguments provided by the user.
        ///   @return Returns bsl::errc_success and increments the provided
        ///     arguments if the extension ELF filed were successfully mapped,
        ///     otherwise this function returns bsl::errc_failure.
        ///
        [[nodiscard]] constexpr auto
        map_ext_elf_files_from_user(bsl::arguments &mut_args) noexcept -> bsl::errc_type
        {
            for (auto &mut_mapped_ext_elf_file : m_mapped_ext_elf_files) {
                if (mut_args.is_invalid()) {
                    break;
                }

                auto const ret{this->map_elf_file(mut_args, mut_mapped_ext_elf_file)};
                if (bsl::unlikely(!ret)) {
                    return ret;
                }

                bsl::touch();
            }

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Converts the extension ELF files from an array of ifmaps
        ///     to an array of buffer_t structs so that the ELF files can be
        ///     passed to the loader.
        ///
        /// <!-- inputs/outputs -->
        ///   @return Return resulting array of buffer_t structs
        ///
        [[nodiscard]] constexpr auto
        convert_mapped_ext_elf_files_to_array_of_spans() const noexcept
            -> loader::ext_elf_files_type
        {
            using dst_t = loader::ext_elf_files_type;
            using src_t = decltype(m_mapped_ext_elf_files);
            static_assert(dst_t::size() == src_t::size());

            dst_t mut_files{};
            for (bsl::safe_idx mut_i{}; mut_i < m_mapped_ext_elf_files.size(); ++mut_i) {
                *mut_files.at_if(mut_i) = m_mapped_ext_elf_files.at_if(mut_i)->view();
            }

            return mut_files;
        }

        /// <!-- description -->
        ///   @brief Given arguments from the user, this function creates the
        ///     ioctl equivalent arguments that the loader expects for
        ///     starting the VMM
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_args the user provided arguments
        ///   @param mut_start_args the resulting start_vmm_args_t
        ///   @return The resulting ioctl arguments
        ///
        [[nodiscard]] constexpr auto
        make_start_vmm_args(
            bsl::arguments &mut_args, loader::start_vmm_args_t &mut_start_args) noexcept
            -> bsl::errc_type
        {
            auto const remaining{mut_args.remaining()};

            if (bsl::unlikely(bsl::safe_umx::magic_0() == remaining)) {
                bsl::error() << "missing the microkernel elf file\n";
                return bsl::errc_failure;
            }

            if (bsl::unlikely(bsl::safe_umx::magic_1() == remaining)) {
                bsl::error() << "at least one extension is required\n";
                return bsl::errc_failure;
            }

            if (bsl::unlikely(!this->map_mk_elf_file_from_user(mut_args))) {
                return bsl::errc_failure;
            }

            if (bsl::unlikely(!this->map_ext_elf_files_from_user(mut_args))) {
                return bsl::errc_failure;
            }

            mut_start_args = loader::start_vmm_args_t{
                IOCTL_VERSION.get(),
                0U,
                0U,
                m_mapped_mk_elf_file.view(),
                this->convert_mapped_ext_elf_files_to_array_of_spans()};

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief This function is called if an error was encountered while
        ///     attempting to parse the command that the user provided.
        ///
        /// <!-- inputs/outputs -->
        ///   @param cmd the user provided command
        ///
        static constexpr void
        process_cmd_output_error(bsl::string_view const &cmd) noexcept
        {
            if (cmd.empty()) {
                bsl::error() << "missing command. ";
            }
            else {
                bsl::error() << "invalid command: \"" << cmd << "\". ";
            }

            bsl::print() << "use vmmctl -h for usage info\n";
        }

        /// <!-- description -->
        ///   @brief Process the user provided command line arguments assuming
        ///     the first argument is the command while also ignoring "help".
        ///     If the user provided command succeeds, this function
        ///     will return bsl::errc_success, otherwise this function
        ///     will return bsl::errc_failure.
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_args the command line arguments provided by the user.
        ///   @return If the user provided command succeeds, this function
        ///     will return bsl::errc_success, otherwise this function
        ///     will return bsl::errc_failure.
        ///
        [[nodiscard]] constexpr auto
        process_cmd(bsl::arguments &&mut_args) noexcept -> bsl::errc_type
        {
            auto const cmd{mut_args.front<bsl::string_view>()};
            ++mut_args;

            if (cmd == "start") {
                auto const ret{this->make_start_vmm_args(mut_args, m_start_vmm_ctl_args)};
                if (bsl::unlikely(!ret)) {
                    return ret;
                }

                return this->start_vmm(&m_start_vmm_ctl_args);
            }

            if (cmd == "stop") {
                return this->stop_vmm(&m_stop_vmm_ctl_args);
            }

            if (cmd == "dump") {
                return this->dump_vmm(&m_dump_vmm_ctl_args);
            }

            this->process_cmd_output_error(cmd);
            return bsl::errc_failure;
        }

    public:
        /// <!-- description -->
        ///   @brief Process the user provided command line arguments.
        ///     If the user provided command succeeds, this function
        ///     will return bsl::errc_success, otherwise this function
        ///     will return bsl::errc_failure.
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_args the command line arguments provided by the user.
        ///   @return If the user provided command succeeds, this function
        ///     will return bsl::errc_success, otherwise this function
        ///     will return bsl::errc_failure.
        ///
        [[nodiscard]] constexpr auto
        process(bsl::arguments &&mut_args) noexcept -> bsl::errc_type
        {
            if (mut_args.get<bool>("-h")) {
                this->help();
                return bsl::errc_success;
            }

            if (mut_args.get<bool>("--help")) {
                this->help();
                return bsl::errc_success;
            }

            return this->process_cmd(bsl::move(mut_args));
        }
    };
}

#endif
