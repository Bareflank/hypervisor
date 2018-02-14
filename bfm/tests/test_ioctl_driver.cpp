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

#include <test_support.h>

#ifdef _HIPPOMOCKS__ENABLE_CFUNC_MOCKING_SUPPORT

ioctl::status_type g_status = 0;
using clpc = command_line_parser_command;

static file *
setup_file(MockRepository &mocks)
{
    auto fil = mocks.Mock<file>();

    mocks.OnCall(fil, file::read_text).Return(std::string{});
    mocks.OnCall(fil, file::write_text);
    mocks.OnCall(fil, file::write_binary);
    mocks.OnCall(fil, file::extension).Return(".modules"_s);
    mocks.OnCall(fil, file::exists).Return(true);

    mocks.OnCall(fil, file::read_binary).Do([&](auto) {
        return file::binary_data{};
    });

    return fil;
}

static ioctl *
setup_ioctl(MockRepository &mocks, ioctl::status_type status)
{
    auto ctl = mocks.Mock<ioctl>();

    g_status = status;

    mocks.OnCall(ctl, ioctl::open);
    mocks.OnCall(ctl, ioctl::call_ioctl_add_module);
    mocks.OnCall(ctl, ioctl::call_ioctl_load_vmm);
    mocks.OnCall(ctl, ioctl::call_ioctl_unload_vmm);
    mocks.OnCall(ctl, ioctl::call_ioctl_start_vmm);
    mocks.OnCall(ctl, ioctl::call_ioctl_stop_vmm);
    mocks.OnCall(ctl, ioctl::call_ioctl_dump_vmm);

    mocks.OnCall(ctl, ioctl::call_ioctl_vmm_status).Do([&](auto s) {
        *s = g_status;
    });

    return ctl;
}

static command_line_parser *
setup_command_line_parser(MockRepository &mocks, clpc type)
{
    auto clp = mocks.Mock<command_line_parser>();

    mocks.OnCall(clp, command_line_parser::cmd).Return(type);
    mocks.OnCall(clp, command_line_parser::modules).Return(std::string{"test"});
    mocks.OnCall(clp, command_line_parser::vcpuid).Return(0);

    return clp;
}

TEST_CASE("test ioctl driver process invalid file")
{
    MockRepository mocks;

    auto fil = static_cast<file *>(nullptr);
    auto ctl = mocks.Mock<ioctl>();
    auto clp = mocks.Mock<command_line_parser>();

    CHECK_THROWS(ioctl_driver(fil, ctl, clp));
}

TEST_CASE("test ioctl driver process invalid ioctl")
{
    MockRepository mocks;

    auto fil = mocks.Mock<file>();
    auto ctl = static_cast<ioctl *>(nullptr);
    auto clp = mocks.Mock<command_line_parser>();

    CHECK_THROWS(ioctl_driver(fil, ctl, clp));
}

TEST_CASE("test ioctl driver process invalid command line parser")
{
    MockRepository mocks;

    auto fil = mocks.Mock<file>();
    auto ctl = mocks.Mock<ioctl>();
    auto clp = static_cast<command_line_parser *>(nullptr);

    CHECK_THROWS(ioctl_driver(fil, ctl, clp));
}

TEST_CASE("test ioctl driver library path not set")
{
    MockRepository mocks;

    auto fil = setup_file(mocks);
    auto ctl = setup_ioctl(mocks, VMM_UNLOADED);
    auto clp = setup_command_line_parser(mocks, clpc::help);

    mocks.OnCallFunc(std::getenv).Do([&](auto) {
        return nullptr;
    });

    auto driver = ioctl_driver(fil, ctl, clp);
    CHECK(driver.library_path().size() == 2);
}

TEST_CASE("test ioctl driver library path multiple paths")
{
    MockRepository mocks;
    char path[] = "path1;path2";

    auto fil = setup_file(mocks);
    auto ctl = setup_ioctl(mocks, VMM_UNLOADED);
    auto clp = setup_command_line_parser(mocks, clpc::help);

    mocks.OnCallFunc(std::getenv).Do([&](auto) {
        return path;
    });

    auto driver = ioctl_driver(fil, ctl, clp);
    CHECK(driver.library_path().size() == 4);
}

TEST_CASE("test ioctl driver vmm filename with module filename")
{
    MockRepository mocks;

    auto fil = setup_file(mocks);
    auto ctl = setup_ioctl(mocks, VMM_UNLOADED);
    auto clp = setup_command_line_parser(mocks, clpc::help);

    mocks.OnCall(clp, command_line_parser::modules).Return("test.modules"_s);

    auto driver = ioctl_driver(fil, ctl, clp);
    CHECK(driver.vmm_filename() == "test.modules");
}

TEST_CASE("test ioctl driver vmm filename with env filename")
{
    MockRepository mocks;
    char filename[] = "test.modules";

    auto fil = setup_file(mocks);
    auto ctl = setup_ioctl(mocks, VMM_UNLOADED);
    auto clp = setup_command_line_parser(mocks, clpc::help);

    mocks.OnCall(clp, command_line_parser::modules).Return(""_s);

    mocks.OnCallFunc(std::getenv).Do([&](auto) {
        return filename;
    });

    auto driver = ioctl_driver(fil, ctl, clp);
    CHECK(driver.vmm_filename() == "test.modules");
}

TEST_CASE("test ioctl driver vmm filename with default filename")
{
    MockRepository mocks;

    auto fil = setup_file(mocks);
    auto ctl = setup_ioctl(mocks, VMM_UNLOADED);
    auto clp = setup_command_line_parser(mocks, clpc::help);

    mocks.OnCall(clp, command_line_parser::modules).Return(std::string{""});

    mocks.OnCallFunc(std::getenv).Do([&](auto) {
        return nullptr;
    });

    auto driver = ioctl_driver(fil, ctl, clp);
    CHECK_THROWS(driver.vmm_filename());
}

TEST_CASE("test ioctl driver vmm module list empty module list")
{
    MockRepository mocks;

    auto fil = setup_file(mocks);
    auto ctl = setup_ioctl(mocks, VMM_UNLOADED);
    auto clp = setup_command_line_parser(mocks, clpc::help);

    auto driver = ioctl_driver(fil, ctl, clp);
    CHECK_THROWS(driver.vmm_module_list("test.modules"));
}

TEST_CASE("test ioctl driver vmm module list invalid module list")
{
    MockRepository mocks;

    auto fil = setup_file(mocks);
    auto ctl = setup_ioctl(mocks, VMM_UNLOADED);
    auto clp = setup_command_line_parser(mocks, clpc::help);

    mocks.OnCall(fil, file::read_text).Return("bad_json");

    auto driver = ioctl_driver(fil, ctl, clp);
    CHECK_THROWS(driver.vmm_module_list("test.modules"));
}

TEST_CASE("test ioctl driver vmm module list valid empty json")
{
    MockRepository mocks;

    auto fil = setup_file(mocks);
    auto ctl = setup_ioctl(mocks, VMM_UNLOADED);
    auto clp = setup_command_line_parser(mocks, clpc::help);

    mocks.OnCall(fil, file::read_text).Return("{}");

    auto driver = ioctl_driver(fil, ctl, clp);
    CHECK(driver.vmm_module_list("test.modules").empty());
}

TEST_CASE("test ioctl driver vmm module list valid json")
{
    MockRepository mocks;

    auto fil = setup_file(mocks);
    auto ctl = setup_ioctl(mocks, VMM_UNLOADED);
    auto clp = setup_command_line_parser(mocks, clpc::help);

    mocks.OnCall(fil, file::read_text).Return(R"({"test":"test.bin"})");

    auto driver = ioctl_driver(fil, ctl, clp);
    CHECK(!driver.vmm_module_list("test.modules").empty());
}

auto g_empty_needed_list = false;

ioctl_driver::list_type
test_bfelf_read_binary_and_get_needed_list(
    gsl::not_null<file *> f,
    const std::string &filename,
    const std::vector<std::string> &paths,
    bfn::buffer &buffer,
    bfelf_binary_t &binary)
{
    bfignored(f);
    bfignored(filename);
    bfignored(paths);
    bfignored(buffer);
    bfignored(binary);

    if (g_empty_needed_list) {
        return {};
    }

    return {"module1.bin", "module2.bin"};
}

TEST_CASE("test ioctl driver vmm module list empty needed list")
{
    MockRepository mocks;
    ioctl_driver::list_type module_list{"test.bin"};

    auto fil = setup_file(mocks);
    auto ctl = setup_ioctl(mocks, VMM_UNLOADED);
    auto clp = setup_command_line_parser(mocks, clpc::help);

    g_empty_needed_list = true;
    auto ___ = gsl::finally([&] {
        g_empty_needed_list = false;
    });

    mocks.OnCallFunc(bfelf_read_binary_and_get_needed_list).Do(
        test_bfelf_read_binary_and_get_needed_list);

    mocks.OnCall(fil, file::extension).Return(".bin"_s);

    auto driver = ioctl_driver(fil, ctl, clp);
    CHECK(driver.vmm_module_list("test.bin") == module_list);
}

TEST_CASE("test ioctl driver vmm module list non-empty needed list")
{
    MockRepository mocks;

    auto fil = setup_file(mocks);
    auto ctl = setup_ioctl(mocks, VMM_UNLOADED);
    auto clp = setup_command_line_parser(mocks, clpc::help);

    mocks.OnCallFunc(bfelf_read_binary_and_get_needed_list).Do(
        test_bfelf_read_binary_and_get_needed_list);

    mocks.OnCall(fil, file::extension).Return(".bin"_s);

    auto driver = ioctl_driver(fil, ctl, clp);
    CHECK(driver.vmm_module_list("test.bin").size() == 3);
}

TEST_CASE("test ioctl driver process help")
{
    MockRepository mocks;

    auto fil = setup_file(mocks);
    auto ctl = setup_ioctl(mocks, VMM_UNLOADED);
    auto clp = setup_command_line_parser(mocks, clpc::help);

    auto driver = ioctl_driver(fil, ctl, clp);
    CHECK_NOTHROW(driver.process());
}

TEST_CASE("test ioctl driver process load vmm running")
{
    MockRepository mocks;

    auto fil = setup_file(mocks);
    auto ctl = setup_ioctl(mocks, VMM_RUNNING);
    auto clp = setup_command_line_parser(mocks, clpc::load);

    mocks.OnCall(fil, file::read_text).Return(
        R"({})"
    );

    mocks.ExpectCall(ctl, ioctl::call_ioctl_stop_vmm);
    mocks.ExpectCall(ctl, ioctl::call_ioctl_unload_vmm);
    mocks.ExpectCall(ctl, ioctl::call_ioctl_load_vmm);

    auto driver = ioctl_driver(fil, ctl, clp);
    CHECK_NOTHROW(driver.process());
}

TEST_CASE("test ioctl driver process load vmm loaded")
{
    MockRepository mocks;

    auto fil = setup_file(mocks);
    auto ctl = setup_ioctl(mocks, VMM_LOADED);
    auto clp = setup_command_line_parser(mocks, clpc::load);

    mocks.OnCall(fil, file::read_text).Return(
        R"({})"
    );

    mocks.ExpectCall(ctl, ioctl::call_ioctl_unload_vmm);
    mocks.ExpectCall(ctl, ioctl::call_ioctl_load_vmm);

    auto driver = ioctl_driver(fil, ctl, clp);
    CHECK_NOTHROW(driver.process());
}

TEST_CASE("test ioctl driver process load vmm corrupt")
{
    MockRepository mocks;

    auto fil = setup_file(mocks);
    auto ctl = setup_ioctl(mocks, VMM_CORRUPT);
    auto clp = setup_command_line_parser(mocks, clpc::load);

    mocks.OnCall(fil, file::read_text).Return(
        R"({})"
    );

    auto driver = ioctl_driver(fil, ctl, clp);
    CHECK_THROWS(driver.process());
}

TEST_CASE("test ioctl driver process load vmm unknown status")
{
    MockRepository mocks;

    auto fil = setup_file(mocks);
    auto ctl = setup_ioctl(mocks, -1);
    auto clp = setup_command_line_parser(mocks, clpc::load);

    mocks.OnCall(fil, file::read_text).Return(
        R"({})"
    );

    auto driver = ioctl_driver(fil, ctl, clp);
    CHECK_THROWS(driver.process());
}

TEST_CASE("test ioctl driver process load load failed")
{
    MockRepository mocks;

    auto fil = setup_file(mocks);
    auto ctl = setup_ioctl(mocks, VMM_UNLOADED);
    auto clp = setup_command_line_parser(mocks, clpc::load);

    mocks.OnCall(fil, file::read_text).Return(
        R"({"test":"test.bin"})"
    );

    mocks.ExpectCall(ctl, ioctl::call_ioctl_load_vmm).Throw(std::runtime_error("error"));

    auto driver = ioctl_driver(fil, ctl, clp);
    CHECK_THROWS(driver.process());
}

TEST_CASE("test ioctl driver process add module fails")
{
    MockRepository mocks;

    auto fil = setup_file(mocks);
    auto ctl = setup_ioctl(mocks, VMM_UNLOADED);
    auto clp = setup_command_line_parser(mocks, clpc::load);

    mocks.OnCall(fil, file::read_text).Return(
        R"({"test":"test.bin"})"
    );

    mocks.ExpectCall(ctl, ioctl::call_ioctl_add_module).Throw(std::runtime_error("error"));

    auto driver = ioctl_driver(fil, ctl, clp);
    CHECK_THROWS(driver.process());
}

TEST_CASE("test ioctl driver process load success")
{
    MockRepository mocks;

    auto fil = setup_file(mocks);
    auto ctl = setup_ioctl(mocks, VMM_UNLOADED);
    auto clp = setup_command_line_parser(mocks, clpc::load);

    mocks.OnCall(fil, file::read_text).Return(
        R"({"test":"test.bin"})"
    );

    mocks.ExpectCall(ctl, ioctl::call_ioctl_add_module);
    mocks.ExpectCall(ctl, ioctl::call_ioctl_load_vmm);

    auto driver = ioctl_driver(fil, ctl, clp);
    CHECK_NOTHROW(driver.process());
}

TEST_CASE("test ioctl driver process unload vmm running")
{
    MockRepository mocks;

    auto fil = setup_file(mocks);
    auto ctl = setup_ioctl(mocks, VMM_RUNNING);
    auto clp = setup_command_line_parser(mocks, clpc::unload);

    mocks.ExpectCall(ctl, ioctl::call_ioctl_stop_vmm);
    mocks.ExpectCall(ctl, ioctl::call_ioctl_unload_vmm);

    auto driver = ioctl_driver(fil, ctl, clp);
    CHECK_NOTHROW(driver.process());
}

TEST_CASE("test ioctl driver process unload vmm loaded")
{
    MockRepository mocks;

    auto fil = setup_file(mocks);
    auto ctl = setup_ioctl(mocks, VMM_LOADED);
    auto clp = setup_command_line_parser(mocks, clpc::unload);

    mocks.NeverCall(ctl, ioctl::call_ioctl_stop_vmm);
    mocks.ExpectCall(ctl, ioctl::call_ioctl_unload_vmm);

    auto driver = ioctl_driver(fil, ctl, clp);
    CHECK_NOTHROW(driver.process());
}

TEST_CASE("test ioctl driver process unload vmm unloaded")
{
    MockRepository mocks;

    auto fil = setup_file(mocks);
    auto ctl = setup_ioctl(mocks, VMM_UNLOADED);
    auto clp = setup_command_line_parser(mocks, clpc::unload);

    mocks.NeverCall(ctl, ioctl::call_ioctl_stop_vmm);
    mocks.ExpectCall(ctl, ioctl::call_ioctl_unload_vmm);

    auto driver = ioctl_driver(fil, ctl, clp);
    CHECK_NOTHROW(driver.process());
}

TEST_CASE("test ioctl driver process unload vmm corrupt")
{
    MockRepository mocks;

    auto fil = setup_file(mocks);
    auto ctl = setup_ioctl(mocks, VMM_CORRUPT);
    auto clp = setup_command_line_parser(mocks, clpc::unload);

    auto driver = ioctl_driver(fil, ctl, clp);
    CHECK_THROWS(driver.process());
}

TEST_CASE("test ioctl driver process unload vmm unknown status")
{
    MockRepository mocks;

    auto fil = setup_file(mocks);
    auto ctl = setup_ioctl(mocks, -1);
    auto clp = setup_command_line_parser(mocks, clpc::unload);

    auto driver = ioctl_driver(fil, ctl, clp);
    CHECK_THROWS(driver.process());
}

TEST_CASE("test ioctl driver process unload unload failed")
{
    MockRepository mocks;

    auto fil = setup_file(mocks);
    auto ctl = setup_ioctl(mocks, VMM_LOADED);
    auto clp = setup_command_line_parser(mocks, clpc::unload);

    mocks.OnCall(ctl, ioctl::call_ioctl_unload_vmm).Throw(std::runtime_error("error"));

    auto driver = ioctl_driver(fil, ctl, clp);
    CHECK_THROWS(driver.process());
}

TEST_CASE("test ioctl driver process unload success")
{
    MockRepository mocks;

    auto fil = setup_file(mocks);
    auto ctl = setup_ioctl(mocks, VMM_LOADED);
    auto clp = setup_command_line_parser(mocks, clpc::unload);

    auto driver = ioctl_driver(fil, ctl, clp);
    CHECK_NOTHROW(driver.process());
}

TEST_CASE("test ioctl driver process start vmm running")
{
    MockRepository mocks;

    auto fil = setup_file(mocks);
    auto ctl = setup_ioctl(mocks, VMM_RUNNING);
    auto clp = setup_command_line_parser(mocks, clpc::start);

    mocks.ExpectCall(ctl, ioctl::call_ioctl_stop_vmm);
    mocks.ExpectCall(ctl, ioctl::call_ioctl_start_vmm);

    auto driver = ioctl_driver(fil, ctl, clp);
    CHECK_NOTHROW(driver.process());
}

TEST_CASE("test ioctl driver process start vmm loaded")
{
    MockRepository mocks;

    auto fil = setup_file(mocks);
    auto ctl = setup_ioctl(mocks, VMM_LOADED);
    auto clp = setup_command_line_parser(mocks, clpc::start);

    mocks.NeverCall(ctl, ioctl::call_ioctl_stop_vmm);
    mocks.ExpectCall(ctl, ioctl::call_ioctl_start_vmm);

    auto driver = ioctl_driver(fil, ctl, clp);
    CHECK_NOTHROW(driver.process());
}

TEST_CASE("test ioctl driver process start vmm unloaded")
{
    MockRepository mocks;

    auto fil = setup_file(mocks);
    auto ctl = setup_ioctl(mocks, VMM_UNLOADED);
    auto clp = setup_command_line_parser(mocks, clpc::start);

    mocks.NeverCall(ctl, ioctl::call_ioctl_stop_vmm);
    mocks.NeverCall(ctl, ioctl::call_ioctl_start_vmm);

    auto driver = ioctl_driver(fil, ctl, clp);
    CHECK_THROWS(driver.process());
}

TEST_CASE("test ioctl driver process start vmm corrupt")
{
    MockRepository mocks;

    auto fil = setup_file(mocks);
    auto ctl = setup_ioctl(mocks, VMM_CORRUPT);
    auto clp = setup_command_line_parser(mocks, clpc::start);

    mocks.NeverCall(ctl, ioctl::call_ioctl_start_vmm);

    auto driver = ioctl_driver(fil, ctl, clp);
    CHECK_THROWS(driver.process());
}

TEST_CASE("test ioctl driver process start vmm unknown status")
{
    MockRepository mocks;

    auto fil = setup_file(mocks);
    auto ctl = setup_ioctl(mocks, -1);
    auto clp = setup_command_line_parser(mocks, clpc::start);

    mocks.NeverCall(ctl, ioctl::call_ioctl_start_vmm);

    auto driver = ioctl_driver(fil, ctl, clp);
    CHECK_THROWS(driver.process());
}

TEST_CASE("test ioctl driver process start start failed")
{
    MockRepository mocks;

    auto fil = setup_file(mocks);
    auto ctl = setup_ioctl(mocks, VMM_LOADED);
    auto clp = setup_command_line_parser(mocks, clpc::start);

    mocks.OnCall(ctl, ioctl::call_ioctl_start_vmm).Throw(std::runtime_error("error"));

    auto driver = ioctl_driver(fil, ctl, clp);
    CHECK_THROWS(driver.process());
}

TEST_CASE("test ioctl driver process start success")
{
    MockRepository mocks;

    auto fil = setup_file(mocks);
    auto ctl = setup_ioctl(mocks, VMM_LOADED);
    auto clp = setup_command_line_parser(mocks, clpc::start);

    auto driver = ioctl_driver(fil, ctl, clp);
    CHECK_NOTHROW(driver.process());
}

TEST_CASE("test ioctl driver process stop vmm loaded")
{
    MockRepository mocks;

    auto fil = setup_file(mocks);
    auto ctl = setup_ioctl(mocks, VMM_LOADED);
    auto clp = setup_command_line_parser(mocks, clpc::stop);

    mocks.NeverCall(ctl, ioctl::call_ioctl_stop_vmm);

    auto driver = ioctl_driver(fil, ctl, clp);
    CHECK_NOTHROW(driver.process());
}

TEST_CASE("test ioctl driver process stop vmm unloaded")
{
    MockRepository mocks;

    auto fil = setup_file(mocks);
    auto ctl = setup_ioctl(mocks, VMM_UNLOADED);
    auto clp = setup_command_line_parser(mocks, clpc::stop);

    mocks.NeverCall(ctl, ioctl::call_ioctl_stop_vmm);

    auto driver = ioctl_driver(fil, ctl, clp);
    CHECK_NOTHROW(driver.process());
}

TEST_CASE("test ioctl driver process stop vmm corrupt")
{
    MockRepository mocks;

    auto fil = setup_file(mocks);
    auto ctl = setup_ioctl(mocks, VMM_CORRUPT);
    auto clp = setup_command_line_parser(mocks, clpc::stop);

    mocks.NeverCall(ctl, ioctl::call_ioctl_stop_vmm);

    auto driver = ioctl_driver(fil, ctl, clp);
    CHECK_THROWS(driver.process());
}

TEST_CASE("test ioctl driver process stop vmm unknown status")
{
    MockRepository mocks;

    auto fil = setup_file(mocks);
    auto ctl = setup_ioctl(mocks, -1);
    auto clp = setup_command_line_parser(mocks, clpc::stop);

    mocks.NeverCall(ctl, ioctl::call_ioctl_stop_vmm);

    auto driver = ioctl_driver(fil, ctl, clp);
    CHECK_THROWS(driver.process());
}

TEST_CASE("test ioctl driver process stop stop failed")
{
    MockRepository mocks;

    auto fil = setup_file(mocks);
    auto ctl = setup_ioctl(mocks, VMM_RUNNING);
    auto clp = setup_command_line_parser(mocks, clpc::stop);

    mocks.OnCall(ctl, ioctl::call_ioctl_stop_vmm).Throw(std::runtime_error("error"));

    auto driver = ioctl_driver(fil, ctl, clp);
    CHECK_THROWS(driver.process());
}

TEST_CASE("test ioctl driver process stop success")
{
    MockRepository mocks;

    auto fil = setup_file(mocks);
    auto ctl = setup_ioctl(mocks, VMM_RUNNING);
    auto clp = setup_command_line_parser(mocks, clpc::stop);

    auto driver = ioctl_driver(fil, ctl, clp);
    CHECK_NOTHROW(driver.process());
}

TEST_CASE("test ioctl driver process quick success")
{
    MockRepository mocks;

    auto fil = setup_file(mocks);
    auto ctl = setup_ioctl(mocks, VMM_RUNNING);
    auto clp = setup_command_line_parser(mocks, clpc::quick);

    mocks.OnCall(fil, file::read_text).Return(
        R"({})"
    );

    auto driver = ioctl_driver(fil, ctl, clp);
    CHECK_NOTHROW(driver.process());
}

TEST_CASE("test ioctl driver process dump vmm unloaded")
{
    MockRepository mocks;

    auto fil = setup_file(mocks);
    auto ctl = setup_ioctl(mocks, VMM_UNLOADED);
    auto clp = setup_command_line_parser(mocks, clpc::dump);

    mocks.NeverCall(ctl, ioctl::call_ioctl_dump_vmm);

    auto driver = ioctl_driver(fil, ctl, clp);
    CHECK_THROWS(driver.process());
}

TEST_CASE("test ioctl driver process dump vmm corrupted")
{
    MockRepository mocks;

    auto fil = setup_file(mocks);
    auto ctl = setup_ioctl(mocks, VMM_CORRUPT);
    auto clp = setup_command_line_parser(mocks, clpc::dump);

    mocks.NeverCall(ctl, ioctl::call_ioctl_dump_vmm);

    auto driver = ioctl_driver(fil, ctl, clp);
    CHECK_THROWS(driver.process());
}

TEST_CASE("test ioctl driver process dump vmm unknown status")
{
    MockRepository mocks;

    auto fil = setup_file(mocks);
    auto ctl = setup_ioctl(mocks, -1);
    auto clp = setup_command_line_parser(mocks, clpc::dump);

    mocks.NeverCall(ctl, ioctl::call_ioctl_dump_vmm);

    auto driver = ioctl_driver(fil, ctl, clp);
    CHECK_THROWS(driver.process());
}

TEST_CASE("test ioctl driver process dump dump failed")
{
    MockRepository mocks;

    auto fil = setup_file(mocks);
    auto ctl = setup_ioctl(mocks, VMM_LOADED);
    auto clp = setup_command_line_parser(mocks, clpc::dump);

    mocks.OnCall(ctl, ioctl::call_ioctl_dump_vmm).Throw(std::runtime_error("error"));

    auto driver = ioctl_driver(fil, ctl, clp);
    CHECK_THROWS(driver.process());
}

TEST_CASE("test ioctl driver process dump success running")
{
    MockRepository mocks;

    auto fil = setup_file(mocks);
    auto ctl = setup_ioctl(mocks, VMM_RUNNING);
    auto clp = setup_command_line_parser(mocks, clpc::dump);

    mocks.OnCall(ctl, ioctl::call_ioctl_dump_vmm).Do([](gsl::not_null<ioctl::drr_pointer> drr, auto) {
        drr->spos = 0;
        drr->epos = 3;
        drr->buf[0] = 'h';
        drr->buf[1] = 'i';
        drr->buf[2] = '\n';
    });

    auto driver = ioctl_driver(fil, ctl, clp);
    CHECK_NOTHROW(driver.process());
}

TEST_CASE("test ioctl driver process dump success loaded")
{
    MockRepository mocks;

    auto fil = setup_file(mocks);
    auto ctl = setup_ioctl(mocks, VMM_LOADED);
    auto clp = setup_command_line_parser(mocks, clpc::dump);

    mocks.OnCall(ctl, ioctl::call_ioctl_dump_vmm).Do([](gsl::not_null<ioctl::drr_pointer> drr, auto) {
        drr->spos = 0;
        drr->epos = 3;
        drr->buf[0] = 'h';
        drr->buf[1] = 'i';
        drr->buf[2] = '\n';
    });

    auto driver = ioctl_driver(fil, ctl, clp);
    CHECK_NOTHROW(driver.process());
}

TEST_CASE("test ioctl driver process vmm status running")
{
    MockRepository mocks;

    auto fil = setup_file(mocks);
    auto ctl = setup_ioctl(mocks, VMM_RUNNING);
    auto clp = setup_command_line_parser(mocks, clpc::status);

    auto driver = ioctl_driver(fil, ctl, clp);
    CHECK_NOTHROW(driver.process());
}

TEST_CASE("test ioctl driver process vmm status loaded")
{
    MockRepository mocks;

    auto fil = setup_file(mocks);
    auto ctl = setup_ioctl(mocks, VMM_LOADED);
    auto clp = setup_command_line_parser(mocks, clpc::status);

    auto driver = ioctl_driver(fil, ctl, clp);
    CHECK_NOTHROW(driver.process());
}

TEST_CASE("test ioctl driver process vmm status unloaded")
{
    MockRepository mocks;

    auto fil = setup_file(mocks);
    auto ctl = setup_ioctl(mocks, VMM_UNLOADED);
    auto clp = setup_command_line_parser(mocks, clpc::status);

    auto driver = ioctl_driver(fil, ctl, clp);
    CHECK_NOTHROW(driver.process());
}

TEST_CASE("test ioctl driver process vmm status corrupt")
{
    MockRepository mocks;

    auto fil = setup_file(mocks);
    auto ctl = setup_ioctl(mocks, VMM_CORRUPT);
    auto clp = setup_command_line_parser(mocks, clpc::status);

    auto driver = ioctl_driver(fil, ctl, clp);
    CHECK_NOTHROW(driver.process());
}

TEST_CASE("test ioctl driver process vmm status unknown status")
{
    MockRepository mocks;

    auto fil = setup_file(mocks);
    auto ctl = setup_ioctl(mocks, -1);
    auto clp = setup_command_line_parser(mocks, clpc::status);

    auto driver = ioctl_driver(fil, ctl, clp);
    CHECK_THROWS(driver.process());
}

#endif
