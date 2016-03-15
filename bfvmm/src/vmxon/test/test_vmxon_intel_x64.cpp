//
// Bareflank Hypervisor
//
// Copyright (C) 2015 Assured Information Security, Inc.
// Author: Rian Quinn        <quinnr@ainfosec.com>
// Author: Brendan Kerrigan  <kerriganb@ainfosec.com>
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

#include <test.h>
#include <vmxon/vmxon_intel_x64.h>
#include <vmxon/vmxon_exceptions_intel_x64.h>
#include <memory_manager/memory_manager.h>



// void
// vmxon_ut::test_vmxon_start_uninitialized()
// {
//     vmxon_intel_x64 vmxon(0);
//     EXPECT_TRUE(vmxon.start() == vmxon_error::failure);
// }

// void
// vmxon_ut::test_vmxon_stop_uninitialized()
// {
//     vmxon_intel_x64 vmxon(0);
//     EXPECT_TRUE(vmxon.stop() == vmxon_error::failure);
// }

// void
// vmxon_ut::test_verify_cpuid_vmx_supported_failed()
// {
//     MockRepository mocks;
//     intrinsics_intel_x64 *intrinsics = mocks.Mock<intrinsics_intel_x64>();

//     vmxon_intel_x64 vmxon(intrinsics);

//     mocks.OnCall(intrinsics, intrinsics_intel_x64::cpuid_ecx).Return(0);

//     RUN_UNITTEST_WITH_MOCKS(mocks, [&]
//     {
//         EXPECT_TRUE(vmxon.verify_cpuid_vmx_supported() == vmxon_error::not_supported);
//     });
// }

// void
// vmxon_ut::test_verify_cpuid_vmx_supported_success()
// {
//     MockRepository mocks;
//     intrinsics_intel_x64 *intrinsics = mocks.Mock<intrinsics_intel_x64>();

//     vmxon_intel_x64 vmxon(intrinsics);

//     mocks.OnCall(intrinsics, intrinsics_intel_x64::cpuid_ecx).Return((1 << 5));

//     RUN_UNITTEST_WITH_MOCKS(mocks, [&]
//     {
//         EXPECT_TRUE(vmxon.verify_cpuid_vmx_supported() == vmxon_error::success);
//     });
// }

// void
// vmxon_ut::test_verify_vmx_capabilities_msr_failed_invalid_physical_address_width()
// {
//     MockRepository mocks;
//     intrinsics_intel_x64 *intrinsics = mocks.Mock<intrinsics_intel_x64>();

//     vmxon_intel_x64 vmxon(intrinsics);

//     mocks.OnCall(intrinsics, intrinsics_intel_x64::read_msr).With(IA32_VMX_BASIC_MSR).Return((1ll << 48));

//     RUN_UNITTEST_WITH_MOCKS(mocks, [&]
//     {
//         EXPECT_TRUE(vmxon.verify_vmx_capabilities_msr() == vmxon_error::not_supported);
//     });
// }

// void
// vmxon_ut::test_verify_vmx_capabilities_msr_failed_invalid_memory_type()
// {
//     MockRepository mocks;
//     intrinsics_intel_x64 *intrinsics = mocks.Mock<intrinsics_intel_x64>();

//     vmxon_intel_x64 vmxon(intrinsics);

//     mocks.OnCall(intrinsics, intrinsics_intel_x64::read_msr).With(IA32_VMX_BASIC_MSR).Return(0);

//     RUN_UNITTEST_WITH_MOCKS(mocks, [&]
//     {
//         EXPECT_TRUE(vmxon.verify_vmx_capabilities_msr() == vmxon_error::not_supported);
//     });
// }

// void
// vmxon_ut::test_verify_vmx_capabilities_msr_success()
// {
//     MockRepository mocks;
//     intrinsics_intel_x64 *intrinsics = mocks.Mock<intrinsics_intel_x64>();

//     vmxon_intel_x64 vmxon(intrinsics);

//     mocks.OnCall(intrinsics, intrinsics_intel_x64::read_msr).With(IA32_VMX_BASIC_MSR).Return((6ll << 50));

//     RUN_UNITTEST_WITH_MOCKS(mocks, [&]
//     {
//         EXPECT_TRUE(vmxon.verify_vmx_capabilities_msr() == vmxon_error::success);
//     });
// }

// void
// vmxon_ut::test_verify_ia32_vmx_cr0_fixed_msr_failed_fixed0()
// {
//     MockRepository mocks;
//     intrinsics_intel_x64 *intrinsics = mocks.Mock<intrinsics_intel_x64>();

//     vmxon_intel_x64 vmxon(intrinsics);

//     mocks.OnCall(intrinsics, intrinsics_intel_x64::read_cr0).Return(0);
//     mocks.OnCall(intrinsics, intrinsics_intel_x64::read_msr).With(IA32_VMX_CR0_FIXED0_MSR).Return(0x1);
//     mocks.OnCall(intrinsics, intrinsics_intel_x64::read_msr).With(IA32_VMX_CR0_FIXED1_MSR).Return(0xFFFFFFFFFFFFFFFF);

//     RUN_UNITTEST_WITH_MOCKS(mocks, [&]
//     {
//         EXPECT_TRUE(vmxon.verify_ia32_vmx_cr0_fixed_msr() == vmxon_error::not_supported);
//     });
// }

// void
// vmxon_ut::test_verify_ia32_vmx_cr0_fixed_msr_failed_fixed1()
// {
//     MockRepository mocks;
//     intrinsics_intel_x64 *intrinsics = mocks.Mock<intrinsics_intel_x64>();

//     vmxon_intel_x64 vmxon(intrinsics);

//     mocks.OnCall(intrinsics, intrinsics_intel_x64::read_cr0).Return(0xFFFFFFFFFFFFFFFF);
//     mocks.OnCall(intrinsics, intrinsics_intel_x64::read_msr).With(IA32_VMX_CR0_FIXED0_MSR).Return(0);
//     mocks.OnCall(intrinsics, intrinsics_intel_x64::read_msr).With(IA32_VMX_CR0_FIXED1_MSR).Return(0xFFFFFFFFFFFFFFF7);

//     RUN_UNITTEST_WITH_MOCKS(mocks, [&]
//     {
//         EXPECT_TRUE(vmxon.verify_ia32_vmx_cr0_fixed_msr() == vmxon_error::not_supported);
//     });
// }

// void
// vmxon_ut::test_verify_ia32_vmx_cr0_fixed_msr_success()
// {
//     MockRepository mocks;
//     intrinsics_intel_x64 *intrinsics = mocks.Mock<intrinsics_intel_x64>();

//     vmxon_intel_x64 vmxon(intrinsics);

//     mocks.OnCall(intrinsics, intrinsics_intel_x64::read_cr0).Return(0x1);
//     mocks.OnCall(intrinsics, intrinsics_intel_x64::read_msr).With(IA32_VMX_CR0_FIXED0_MSR).Return(0x1);
//     mocks.OnCall(intrinsics, intrinsics_intel_x64::read_msr).With(IA32_VMX_CR0_FIXED1_MSR).Return(0xFFFFFFFFFFFFFFF7);

//     RUN_UNITTEST_WITH_MOCKS(mocks, [&]
//     {
//         EXPECT_TRUE(vmxon.verify_ia32_vmx_cr0_fixed_msr() == vmxon_error::success);
//     });
// }

// void
// vmxon_ut::test_verify_ia32_vmx_cr4_fixed_msr_failed_fixed0()
// {
//     MockRepository mocks;
//     intrinsics_intel_x64 *intrinsics = mocks.Mock<intrinsics_intel_x64>();

//     vmxon_intel_x64 vmxon(intrinsics);

//     mocks.OnCall(intrinsics, intrinsics_intel_x64::read_cr4).Return(0);
//     mocks.OnCall(intrinsics, intrinsics_intel_x64::read_msr).With(IA32_VMX_CR4_FIXED0_MSR).Return(0x1);
//     mocks.OnCall(intrinsics, intrinsics_intel_x64::read_msr).With(IA32_VMX_CR4_FIXED1_MSR).Return(0xFFFFFFFFFFFFFFFF);

//     RUN_UNITTEST_WITH_MOCKS(mocks, [&]
//     {
//         EXPECT_TRUE(vmxon.verify_ia32_vmx_cr4_fixed_msr() == vmxon_error::not_supported);
//     });
// }

// void
// vmxon_ut::test_verify_ia32_vmx_cr4_fixed_msr_failed_fixed1()
// {
//     MockRepository mocks;
//     intrinsics_intel_x64 *intrinsics = mocks.Mock<intrinsics_intel_x64>();

//     vmxon_intel_x64 vmxon(intrinsics);

//     mocks.OnCall(intrinsics, intrinsics_intel_x64::read_cr4).Return(0xFFFFFFFFFFFFFFFF);
//     mocks.OnCall(intrinsics, intrinsics_intel_x64::read_msr).With(IA32_VMX_CR4_FIXED0_MSR).Return(0);
//     mocks.OnCall(intrinsics, intrinsics_intel_x64::read_msr).With(IA32_VMX_CR4_FIXED1_MSR).Return(0xFFFFFFFFFFFFFFF7);

//     RUN_UNITTEST_WITH_MOCKS(mocks, [&]
//     {
//         EXPECT_TRUE(vmxon.verify_ia32_vmx_cr4_fixed_msr() == vmxon_error::not_supported);
//     });
// }

// void
// vmxon_ut::test_verify_ia32_vmx_cr4_fixed_msr_success()
// {
//     MockRepository mocks;
//     intrinsics_intel_x64 *intrinsics = mocks.Mock<intrinsics_intel_x64>();

//     vmxon_intel_x64 vmxon(intrinsics);

//     mocks.OnCall(intrinsics, intrinsics_intel_x64::read_cr4).Return(0x1);
//     mocks.OnCall(intrinsics, intrinsics_intel_x64::read_msr).With(IA32_VMX_CR4_FIXED0_MSR).Return(0x1);
//     mocks.OnCall(intrinsics, intrinsics_intel_x64::read_msr).With(IA32_VMX_CR4_FIXED1_MSR).Return(0xFFFFFFFFFFFFFFF7);

//     RUN_UNITTEST_WITH_MOCKS(mocks, [&]
//     {
//         EXPECT_TRUE(vmxon.verify_ia32_vmx_cr4_fixed_msr() == vmxon_error::success);
//     });
// }

// void
// vmxon_ut::test_verify_ia32_feature_control_msr_failed()
// {
//     MockRepository mocks;
//     intrinsics_intel_x64 *intrinsics = mocks.Mock<intrinsics_intel_x64>();

//     vmxon_intel_x64 vmxon(intrinsics);

//     mocks.OnCall(intrinsics, intrinsics_intel_x64::read_msr).With(IA32_FEATURE_CONTROL_MSR).Return(0);

//     RUN_UNITTEST_WITH_MOCKS(mocks, [&]
//     {
//         EXPECT_TRUE(vmxon.verify_ia32_feature_control_msr() == vmxon_error::not_supported);
//     });
// }

// void
// vmxon_ut::test_verify_ia32_feature_control_msr_success()
// {
//     MockRepository mocks;
//     intrinsics_intel_x64 *intrinsics = mocks.Mock<intrinsics_intel_x64>();

//     vmxon_intel_x64 vmxon(intrinsics);

//     mocks.OnCall(intrinsics, intrinsics_intel_x64::read_msr).With(IA32_FEATURE_CONTROL_MSR).Return(1);

//     RUN_UNITTEST_WITH_MOCKS(mocks, [&]
//     {
//         EXPECT_TRUE(vmxon.verify_ia32_feature_control_msr() == vmxon_error::success);
//     });
// }

// void
// vmxon_ut::test_verify_v8086_disabled_failed()
// {
//     MockRepository mocks;
//     intrinsics_intel_x64 *intrinsics = mocks.Mock<intrinsics_intel_x64>();

//     vmxon_intel_x64 vmxon(intrinsics);

//     mocks.OnCall(intrinsics, intrinsics_intel_x64::read_rflags).Return(RFLAGS_VM_VIRTUAL_8086_MODE);

//     RUN_UNITTEST_WITH_MOCKS(mocks, [&]
//     {
//         EXPECT_TRUE(vmxon.verify_v8086_disabled() == vmxon_error::not_supported);
//     });
// }

// void
// vmxon_ut::test_verify_v8086_disabled_success()
// {
//     MockRepository mocks;
//     intrinsics_intel_x64 *intrinsics = mocks.Mock<intrinsics_intel_x64>();

//     vmxon_intel_x64 vmxon(intrinsics);

//     mocks.OnCall(intrinsics, intrinsics_intel_x64::read_rflags).Return(0);

//     RUN_UNITTEST_WITH_MOCKS(mocks, [&]
//     {
//         EXPECT_TRUE(vmxon.verify_v8086_disabled() == vmxon_error::success);
//     });
// }

// void
// vmxon_ut::test_verify_vmx_operation_enabled_failed()
// {
//     MockRepository mocks;
//     intrinsics_intel_x64 *intrinsics = mocks.Mock<intrinsics_intel_x64>();

//     vmxon_intel_x64 vmxon(intrinsics);

//     mocks.OnCall(intrinsics, intrinsics_intel_x64::read_cr4).Return(0);

//     RUN_UNITTEST_WITH_MOCKS(mocks, [&]
//     {
//         EXPECT_TRUE(vmxon.verify_vmx_operation_enabled() == vmxon_error::failure);
//     });
// }

// void
// vmxon_ut::test_verify_vmx_operation_enabled_success()
// {
//     MockRepository mocks;
//     intrinsics_intel_x64 *intrinsics = mocks.Mock<intrinsics_intel_x64>();

//     vmxon_intel_x64 vmxon(intrinsics);

//     mocks.OnCall(intrinsics, intrinsics_intel_x64::read_cr4).Return(CR4_VMXE_VMX_ENABLE_BIT);

//     RUN_UNITTEST_WITH_MOCKS(mocks, [&]
//     {
//         EXPECT_TRUE(vmxon.verify_vmx_operation_enabled() == vmxon_error::success);
//     });
// }

// void
// vmxon_ut::test_verify_vmx_operation_disabled_failed()
// {
//     MockRepository mocks;
//     intrinsics_intel_x64 *intrinsics = mocks.Mock<intrinsics_intel_x64>();

//     vmxon_intel_x64 vmxon(intrinsics);

//     mocks.OnCall(intrinsics, intrinsics_intel_x64::read_cr4).Return(CR4_VMXE_VMX_ENABLE_BIT);

//     RUN_UNITTEST_WITH_MOCKS(mocks, [&]
//     {
//         EXPECT_TRUE(vmxon.verify_vmx_operation_disabled() == vmxon_error::failure);
//     });
// }

// void
// vmxon_ut::test_verify_vmx_operation_disabled_success()
// {
//     MockRepository mocks;
//     intrinsics_intel_x64 *intrinsics = mocks.Mock<intrinsics_intel_x64>();

//     vmxon_intel_x64 vmxon(intrinsics);

//     mocks.OnCall(intrinsics, intrinsics_intel_x64::read_cr4).Return(0);

//     RUN_UNITTEST_WITH_MOCKS(mocks, [&]
//     {
//         EXPECT_TRUE(vmxon.verify_vmx_operation_disabled() == vmxon_error::success);
//     });
// }

// void
// vmxon_ut::test_enable_vmx_operation_success()
// {
//     MockRepository mocks;
//     intrinsics_intel_x64 *intrinsics = mocks.Mock<intrinsics_intel_x64>();

//     vmxon_intel_x64 vmxon(intrinsics);

//     mocks.OnCall(intrinsics, intrinsics_intel_x64::read_cr4).Return(0);
//     mocks.ExpectCall(intrinsics, intrinsics_intel_x64::write_cr4).With(CR4_VMXE_VMX_ENABLE_BIT);

//     RUN_UNITTEST_WITH_MOCKS(mocks, [&]
//     {
//         EXPECT_TRUE(vmxon.enable_vmx_operation() == vmxon_error::success);
//     });
// }

// void
// vmxon_ut::test_disable_vmx_operation_success()
// {
//     MockRepository mocks;
//     intrinsics_intel_x64 *intrinsics = mocks.Mock<intrinsics_intel_x64>();

//     vmxon_intel_x64 vmxon(intrinsics);

//     mocks.OnCall(intrinsics, intrinsics_intel_x64::read_cr4).Return(0xFFFFFFFFFFFFFFFF);
//     mocks.ExpectCall(intrinsics, intrinsics_intel_x64::write_cr4).With(~CR4_VMXE_VMX_ENABLE_BIT);

//     RUN_UNITTEST_WITH_MOCKS(mocks, [&]
//     {
//         EXPECT_TRUE(vmxon.disable_vmx_operation() == vmxon_error::success);
//     });
// }

// void
// vmxon_ut::test_create_vmxon_region_out_of_memory()
// {
//     // MockRepository mocks;
//     // memory_manager *mm = mocks.Mock<memory_manager>();
//     // intrinsics_intel_x64 *intrinsics = mocks.Mock<intrinsics_intel_x64>();

//     // vmxon_intel_x64 vmxon(intrinsics);
//     // vmxon.init(intrinsics, mm);

//     // mocks.OnCall(mm, memory_manager::alloc_page).Return(memory_manager_error::out_of_memory);

//     // RUN_UNITTEST_WITH_MOCKS(mocks, [&]
//     // {
//     //     EXPECT_TRUE(vmxon.create_vmxon_region() == vmxon_error::out_of_memory);
//     // });
// }

// // memory_manager_error::type
// // alloc_page_wrong_size(page *pg)
// // {
// //     if (pg == 0)
// //         return memory_manager_error::failure;

// //     *pg = page((void *)4, (void *)8, 15);

// //     return memory_manager_error::success;
// // }

// void
// vmxon_ut::test_create_vmxon_region_misaligned_page()
// {
//     // MockRepository mocks;
//     // memory_manager *mm = mocks.Mock<memory_manager>();
//     // intrinsics_intel_x64 *intrinsics = mocks.Mock<intrinsics_intel_x64>();

//     // vmxon_intel_x64 vmxon(intrinsics);
//     // vmxon.init(intrinsics, mm);

//     // mocks.OnCall(mm, memory_manager::alloc_page).Do(alloc_page_wrong_size);
//     // mocks.OnCall(intrinsics, intrinsics_intel_x64::read_msr).Return((4096LL << 32));

//     // RUN_UNITTEST_WITH_MOCKS(mocks, [&]
//     // {
//     //     EXPECT_TRUE(vmxon.create_vmxon_region() == vmxon_error::not_supported);
//     // });
// }

// // memory_manager_error::type
// // alloc_page_not_page_aligned(page *pg)
// // {
// //     if (pg == 0)
// //         return memory_manager_error::failure;

// //     *pg = page((void *)16, (void *)23, 4096);

// //     return memory_manager_error::success;
// // }

void
vmxon_ut::test_create_vmxon_region_not_page_aligned()
{
    auto region = (char *)malloc(5000);

    if (((uintptr_t)region & 0x0000000000000FFF) == 0)
        region++;

    MockRepository mocks;
    memory_manager *mm = mocks.Mock<memory_manager>();
    intrinsics_intel_x64 *intrinsics = mocks.Mock<intrinsics_intel_x64>();
    mocks.OnCallFunc(memory_manager::instance).Return(mm);

    mocks.OnCall(mm, memory_manager::malloc_aligned).Return(region);
    mocks.OnCall(mm, memory_manager::virt_to_phys).Return(region);
    mocks.OnCall(intrinsics, intrinsics_intel_x64::read_msr).Return(0);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        vmxon_intel_x64 vmxon(intrinsics);
        EXPECT_EXCEPTION(vmxon.create_vmxon_region(), bfn::invalid_alignmnet_error);
    });
}

// void
// vmxon_ut::test_release_vmxon_region()
// {
//     // MockRepository mocks;
//     // memory_manager *mm = mocks.Mock<memory_manager>();
//     // intrinsics_intel_x64 *intrinsics = mocks.Mock<intrinsics_intel_x64>();

//     // vmxon_intel_x64 vmxon(intrinsics);
//     // vmxon.init(intrinsics, mm);

//     // mocks.ExpectCall(mm, memory_manager::free_page);

//     // RUN_UNITTEST_WITH_MOCKS(mocks, [&]
//     // {
//     //     EXPECT_TRUE(vmxon.release_vmxon_region() == vmxon_error::success);
//     // });
// }

// void
// vmxon_ut::test_execute_vmxon_already_on()
// {
//     // MockRepository mocks;
//     // intrinsics_intel_x64 *intrinsics = mocks.Mock<intrinsics_intel_x64>();

//     // vmxon_intel_x64 vmxon(intrinsics);

//     // auto &mock1 = mocks.ExpectCall(intrinsics, intrinsics_intel_x64::vmxon).Return(true);
//     // auto &mock2 = mocks.NeverCall(intrinsics, intrinsics_intel_x64::vmxon).After(mock1);

//     // RUN_UNITTEST_WITH_MOCKS(mocks, [&]
//     // {
//     //     EXPECT_TRUE(vmxon.execute_vmxon() == vmxon_error::success);
//     // });
// }

// void
// vmxon_ut::test_execute_vmxon_failed()
// {
//     // MockRepository mocks;
//     // intrinsics_intel_x64 *intrinsics = mocks.Mock<intrinsics_intel_x64>();

//     // vmxon_intel_x64 vmxon(intrinsics);

//     // mocks.ExpectCall(intrinsics, intrinsics_intel_x64::vmxon).Return(false);

//     // RUN_UNITTEST_WITH_MOCKS(mocks, [&]
//     // {
//     //     EXPECT_TRUE(vmxon.execute_vmxon() == vmxon_error::failure);
//     // });
// }

// void
// vmxon_ut::test_execute_vmxoff_already_off()
// {
//     MockRepository mocks;
//     intrinsics_intel_x64 *intrinsics = mocks.Mock<intrinsics_intel_x64>();

//     vmxon_intel_x64 vmxon(intrinsics);

//     mocks.NeverCall(intrinsics, intrinsics_intel_x64::vmxoff);

//     RUN_UNITTEST_WITH_MOCKS(mocks, [&]
//     {
//         EXPECT_TRUE(vmxon.execute_vmxoff() == vmxon_error::success);
//     });
// }

// void
// vmxon_ut::test_execute_vmxoff_failed()
// {
//     // MockRepository mocks;
//     // intrinsics_intel_x64 *intrinsics = mocks.Mock<intrinsics_intel_x64>();

//     // vmxon_intel_x64 vmxon(intrinsics);

//     // mocks.ExpectCall(intrinsics, intrinsics_intel_x64::vmxon).Return(true);
//     // mocks.ExpectCall(intrinsics, intrinsics_intel_x64::vmxoff).Return(true);

//     // RUN_UNITTEST_WITH_MOCKS(mocks, [&]
//     // {
//     //     EXPECT_TRUE(vmxon.execute_vmxon() == vmxon_error::success);
//     //     EXPECT_TRUE(vmxon.execute_vmxoff() == vmxon_error::success);
//     // });
// }
