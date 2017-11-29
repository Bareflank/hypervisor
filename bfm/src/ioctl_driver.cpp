//
// Bareflank Hypervisor
// Copyright (C) 2015 Assured Information Security, Inc.
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 2.1 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA

#include <bfgsl.h>
#include <bffile.h>
#include <bfjson.h>
#include <bfstring.h>
#include <bfshuffle.h>
#include <bfelf_loader.h>
#include <bfvmcallinterface.h>
#include <bfdriverinterface.h>

#include <ioctl_driver.h>

#ifndef BFM_DEFAULT_VMM
#define BFM_DEFAULT_VMM bfvmm
#endif

ioctl_driver::ioctl_driver(gsl::not_null<file *> f,
                           gsl::not_null<ioctl *> ctl,
                           gsl::not_null<command_line_parser *> clp) :
    m_file(f),
    m_ioctl(ctl),
    m_clp(clp)
{ }

void
ioctl_driver::process()
{
    switch (m_clp->cmd()) {
        case command_line_parser::command_type::help:
            return;

        case command_line_parser::command_type::load:
            return this->load_vmm();

        case command_line_parser::command_type::unload:
            return this->unload_vmm();

        case command_line_parser::command_type::start:
            return this->start_vmm();

        case command_line_parser::command_type::stop:
            return this->stop_vmm();

        case command_line_parser::command_type::quick:
            return this->quick_vmm();

        case command_line_parser::command_type::dump:
            return this->dump_vmm();

        case command_line_parser::command_type::status:
            return this->vmm_status();

        case command_line_parser::command_type::vmcall:
            return this->vmcall();
    }
}

void
ioctl_driver::load_vmm()
{
    auto filename = vmm_filename();
    auto module_list = vmm_module_list(filename);

    switch (get_status()) {
        case VMM_RUNNING: stop_vmm();       // falls through
        case VMM_LOADED: unload_vmm();      // falls through
        case VMM_UNLOADED: break;
        case VMM_CORRUPT: throw std::runtime_error("vmm corrupt");
        default: throw std::runtime_error("unknown status");
    }

    auto ___ = gsl::on_failure([&] {
        unload_vmm();
    });

    for (const auto &module : module_list) {
        m_ioctl->call_ioctl_add_module(m_file->read_binary(module));
    }

    m_ioctl->call_ioctl_load_vmm();
}

void
ioctl_driver::unload_vmm()
{
    switch (get_status()) {
        case VMM_RUNNING: stop_vmm();
        case VMM_LOADED: break;
        case VMM_UNLOADED: break;
        case VMM_CORRUPT: throw std::runtime_error("vmm corrupt");
        default: throw std::runtime_error("unknown status");
    }

    m_ioctl->call_ioctl_unload_vmm();
}

void
ioctl_driver::start_vmm()
{
    switch (get_status()) {
        case VMM_RUNNING: stop_vmm();
        case VMM_LOADED: break;
        case VMM_UNLOADED: throw std::runtime_error("vmm must be loaded first");
        case VMM_CORRUPT: throw std::runtime_error("vmm corrupt");
        default: throw std::runtime_error("unknown status");
    }

    m_ioctl->call_ioctl_start_vmm();
}

void
ioctl_driver::stop_vmm()
{
    switch (get_status()) {
        case VMM_RUNNING: break;
        case VMM_LOADED: return;
        case VMM_UNLOADED: return;
        case VMM_CORRUPT: throw std::runtime_error("vmm corrupt");
        default: throw std::runtime_error("unknown status");
    }

    m_ioctl->call_ioctl_stop_vmm();
}

void
ioctl_driver::quick_vmm()
{
    load_vmm();
    start_vmm();
}

void
ioctl_driver::dump_vmm()
{
    auto drr = ioctl::drr_type{};
    auto buffer = std::make_unique<char[]>(DEBUG_RING_SIZE);

    switch (get_status()) {
        case VMM_RUNNING: break;
        case VMM_LOADED: break;
        case VMM_UNLOADED: throw std::runtime_error("vmm must be loaded first");
        case VMM_CORRUPT: throw std::runtime_error("vmm corrupt");
        default: throw std::runtime_error("unknown status");
    }

    m_ioctl->call_ioctl_dump_vmm(&drr, m_clp->vcpuid());

    if (debug_ring_read(&drr, buffer.get(), DEBUG_RING_SIZE) > 0) {
        std::cout << buffer.get();
    }

    std::cout << '\n';
}

void
ioctl_driver::vmm_status()
{
    switch (get_status()) {
        case VMM_UNLOADED: std::cout << "vmm unloaded\n"; return;
        case VMM_LOADED: std::cout << "vmm loaded\n"; return;
        case VMM_RUNNING: std::cout << "vmm running\n"; return;
        case VMM_CORRUPT: std::cout << "vmm corrupt\n"; return;
        default: throw std::runtime_error("unknown status");
    }
}

void
ioctl_driver::vmcall()
{
    auto regs = m_clp->registers();

    switch (get_status()) {
        case VMM_RUNNING: break;
        case VMM_LOADED: throw std::runtime_error("vmm must be running first");
        case VMM_UNLOADED: throw std::runtime_error("vmm must be running first");
        case VMM_CORRUPT: throw std::runtime_error("vmm corrupt");
        default: throw std::runtime_error("unknown status");
    }

    switch (regs.r00) {
        case VMCALL_VERSIONS:
            this->vmcall_versions(regs);
            break;

        case VMCALL_REGISTERS:
            this->vmcall_registers(regs);
            break;

        case VMCALL_DATA:
            this->vmcall_data(regs);
            break;

        case VMCALL_EVENT:
            this->vmcall_event(regs);
            break;

        case VMCALL_UNITTEST:
            this->vmcall_unittest(regs);
            break;

        default:
            throw std::logic_error("unknown vmcall opcode");
    }
}

void
ioctl_driver::vmcall_send_regs(registers_type &regs)
{
    _vmcall(&regs);

    if (regs.r01 != 0) {
        throw std::runtime_error("ioctl failed: IOCTL_VMCALL");
    }
}

void
ioctl_driver::vmcall_versions(registers_type &regs)
{
    this->vmcall_send_regs(regs);

    switch (regs.r02) {
        case VMCALL_VERSION_PROTOCOL:
            std::cout << "VMCALL_VERSIONS: " << view_as_pointer(regs.r03) << std::endl;
            break;

        case VMCALL_VERSION_BAREFLANK:
            std::cout << "BAREFLANK_VERSION_MAJOR: " << view_as_pointer(regs.r03) << std::endl;
            std::cout << "BAREFLANK_VERSION_MINOR: " << view_as_pointer(regs.r04) << std::endl;
            std::cout << "BAREFLANK_VERSION_PATCH: " << view_as_pointer(regs.r05) << std::endl;
            break;

        case VMCALL_VERSION_USER:
            std::cout << "USER_VERSION_MAJOR: " << view_as_pointer(regs.r03) << std::endl;
            std::cout << "USER_VERSION_MINOR: " << view_as_pointer(regs.r04) << std::endl;
            std::cout << "USER_VERSION_PATCH: " << view_as_pointer(regs.r05) << std::endl;
            break;

        default:
            break;
    }
}

void
ioctl_driver::vmcall_registers(registers_type &regs)
{
    this->vmcall_send_regs(regs);

    std::cout << "r02: " << view_as_pointer(regs.r02) << std::endl;
    std::cout << "r03: " << view_as_pointer(regs.r03) << std::endl;
    std::cout << "r04: " << view_as_pointer(regs.r04) << std::endl;
    std::cout << "r05: " << view_as_pointer(regs.r05) << std::endl;
    std::cout << "r06: " << view_as_pointer(regs.r06) << std::endl;
    std::cout << "r07: " << view_as_pointer(regs.r07) << std::endl;
    std::cout << "r08: " << view_as_pointer(regs.r08) << std::endl;
    std::cout << "r09: " << view_as_pointer(regs.r09) << std::endl;
    std::cout << "r10: " << view_as_pointer(regs.r10) << std::endl;
    std::cout << "r11: " << view_as_pointer(regs.r11) << std::endl;
    std::cout << "r12: " << view_as_pointer(regs.r12) << std::endl;
}

void
ioctl_driver::vmcall_data(registers_type &regs)
{
    switch (regs.r04) {
        case VMCALL_DATA_STRING_UNFORMATTED:
        case VMCALL_DATA_STRING_JSON:
            this->vmcall_data_string(regs);
            break;

        case VMCALL_DATA_BINARY_UNFORMATTED:
            this->vmcall_data_binary(regs);
            break;

        default:
            throw std::logic_error("unknown vmcall data type");
            break;
    }
}

void
ioctl_driver::vmcall_data_string(registers_type &regs)
{
    auto obuffer = std::make_unique<char[]>(VMCALL_OUT_BUFFER_SIZE);

    regs.r08 = reinterpret_cast<decltype(regs.r08)>(obuffer.get());
    regs.r09 = VMCALL_OUT_BUFFER_SIZE;

    vmcall_send_regs(regs);

    switch (regs.r07) {
        case VMCALL_DATA_STRING_JSON:

            if (regs.r09 >= VMCALL_OUT_BUFFER_SIZE) {
                throw std::out_of_range("return output buffer size out of range");
            }

            std::cout << "received from vmm: \n" << json::parse(std::string(obuffer.get(), regs.r09)).dump(4) << '\n';
            break;

        case VMCALL_DATA_STRING_UNFORMATTED:

            if (regs.r09 >= VMCALL_OUT_BUFFER_SIZE) {
                throw std::out_of_range("return output buffer size out of range");
            }

            std::cout << "received from vmm: " << std::string(obuffer.get(), regs.r09) << '\n';
            break;

        default:
            break;
    }
}

void
ioctl_driver::vmcall_data_binary(registers_type &regs)
{
    auto ifile_buffer = m_file->read_binary(m_clp->ifile());
    auto ofile_buffer = file::binary_data(VMCALL_OUT_BUFFER_SIZE);

    regs.r05 = reinterpret_cast<decltype(regs.r05)>(ifile_buffer.data());
    regs.r06 = ifile_buffer.size();
    regs.r08 = reinterpret_cast<decltype(regs.r08)>(ofile_buffer.data());
    regs.r09 = VMCALL_OUT_BUFFER_SIZE;

    vmcall_send_regs(regs);

    switch (regs.r07) {
        case VMCALL_DATA_BINARY_UNFORMATTED:

            if (regs.r09 >= VMCALL_OUT_BUFFER_SIZE) {
                throw std::out_of_range("return output buffer size out of range");
            }

            ofile_buffer.resize(regs.r09);
            m_file->write_binary(m_clp->ofile(), ofile_buffer);
            break;

        default:
            break;
    }
}

void
ioctl_driver::vmcall_event(registers_type &regs)
{
    vmcall_send_regs(regs);
    std::cout << "success" << std::endl;
}

void
ioctl_driver::vmcall_unittest(registers_type &regs)
{
    vmcall_send_regs(regs);
    std::cout << "\033[1;36m" << std::hex << "0x" << regs.r02 << std::dec << ":\033[1;32m passed\033[0m\n";
}

ioctl_driver::list_type
ioctl_driver::library_path()
{
    list_type paths;

    for (const auto &path : bfn::split(std::getenv("BF_LIBRARY_PATH"), ';')) {
        paths.emplace_back(path);
    }

    paths.emplace_back(bfstringify(BAREFLANK_VMM_BIN_PATH));
    paths.emplace_back(bfstringify(BAREFLANK_VMM_LIB_PATH));

    return paths;
}

ioctl_driver::filename_type
ioctl_driver::vmm_filename()
{
    auto filename = m_clp->modules();

    if (!filename.empty()) {
        return filename;
    }

    if (auto vmm_path = std::getenv("BF_VMM_PATH")) {
        return {vmm_path};
    }

    return bfstringify(BAREFLANK_VMM_BIN_PATH) bfstringify(BFM_DEFAULT_VMM);
}

ioctl_driver::list_type
ioctl_driver::vmm_module_list(const filename_type &filename)
{
    list_type module_list;

    if (m_file->extension(filename) == ".modules") {
        for (const auto &module : json::parse(m_file->read_text(filename))) {
            module_list.push_back(module);
        }
    }
    else {
        bfn::buffer buffer{};
        bfelf_binary_t binary{};

        module_list = bfelf_read_binary_and_get_needed_list(
                          m_file, filename, library_path(), buffer, binary);

        bfn::shuffle(module_list);
        module_list.push_back(filename);
    }

    return module_list;
}

ioctl_driver::status_type
ioctl_driver::get_status() const
{
    status_type status = -1;
    m_ioctl->call_ioctl_vmm_status(&status);

    return status;
}
