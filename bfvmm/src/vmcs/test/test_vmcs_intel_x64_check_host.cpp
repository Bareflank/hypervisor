//
// Bareflank Hypervisor
//
// Copyright (C) 2015 Assured Information Security, Inc.
// Author: Rian Quinn        <quinnr@ainfosec.com>
// Author: Brendan Kerrigan  <kerriganb@ainfosec.com>
// Author: Connor Davis      <davisc@ainfosec.com>
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

#include <test.h>
#include <string>

static struct control_flow_path path;

static void
setup_check_host_cr0_for_unsupported_bits_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { g_vmcs_fields[VMCS_HOST_CR0] = 0; g_msrs[IA32_VMX_CR0_FIXED0_MSR] = 0; };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { g_msrs[IA32_VMX_CR0_FIXED0_MSR] = 1; };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("invalid cr0"));
    cfg.push_back(path);
}

static void
setup_check_host_cr4_for_unsupported_bits_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { g_vmcs_fields[VMCS_HOST_CR4] = 0; g_msrs[IA32_VMX_CR4_FIXED0_MSR] = 0; };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { g_msrs[IA32_VMX_CR4_FIXED0_MSR] = 1; };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("invalid cr4"));
    cfg.push_back(path);
}

static void
setup_check_host_cr3_for_unsupported_bits_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { g_vmcs_fields[VMCS_HOST_CR3] = 0xff00000000000000; };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("host cr3 too large"));
    cfg.push_back(path);

    path.setup = [&] { g_vmcs_fields[VMCS_HOST_CR3] = 0x1000; };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_host_ia32_sysenter_esp_canonical_address_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { g_vmcs_fields[VMCS_HOST_IA32_SYSENTER_ESP] = 0; };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { g_vmcs_fields[VMCS_HOST_IA32_SYSENTER_ESP] = 0x800000000000; };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("host sysenter esp must be canonical"));
    cfg.push_back(path);
}

static void
setup_check_host_ia32_sysenter_eip_canonical_address_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { g_vmcs_fields[VMCS_HOST_IA32_SYSENTER_EIP] = 0; };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { g_vmcs_fields[VMCS_HOST_IA32_SYSENTER_EIP] = 0x800000000000; };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("host sysenter eip must be canonical"));
    cfg.push_back(path);
}

static void
setup_check_host_verify_load_ia32_perf_global_ctrl_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { disable_exit_ctl(VM_EXIT_CONTROL_LOAD_IA32_PERF_GLOBAL_CTRL); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { enable_exit_ctl(VM_EXIT_CONTROL_LOAD_IA32_PERF_GLOBAL_CTRL); g_vmcs_fields[VMCS_HOST_IA32_PERF_GLOBAL_CTRL_FULL] = 0xc; };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("perf global ctrl msr reserved bits must be 0"));
    cfg.push_back(path);

    path.setup = [&] { g_vmcs_fields[VMCS_HOST_IA32_PERF_GLOBAL_CTRL_FULL] = 0; };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_host_verify_load_ia32_pat_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { disable_exit_ctl(VM_EXIT_CONTROL_LOAD_IA32_PAT); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { enable_exit_ctl(VM_EXIT_CONTROL_LOAD_IA32_PAT); g_vmcs_fields[VMCS_HOST_IA32_PAT_FULL] = 2ULL; };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("pat0 has an invalid memory type"));
    cfg.push_back(path);

    path.setup = [&] { g_vmcs_fields[VMCS_HOST_IA32_PAT_FULL] = 2ULL << 8; };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("pat1 has an invalid memory type"));
    cfg.push_back(path);

    path.setup = [&] { g_vmcs_fields[VMCS_HOST_IA32_PAT_FULL] = 2ULL << 16; };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("pat2 has an invalid memory type"));
    cfg.push_back(path);

    path.setup = [&] { g_vmcs_fields[VMCS_HOST_IA32_PAT_FULL] = 2ULL << 24; };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("pat3 has an invalid memory type"));
    cfg.push_back(path);

    path.setup = [&] { g_vmcs_fields[VMCS_HOST_IA32_PAT_FULL] = 2ULL << 32; };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("pat4 has an invalid memory type"));
    cfg.push_back(path);

    path.setup = [&] { g_vmcs_fields[VMCS_HOST_IA32_PAT_FULL] = 2ULL << 40; };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("pat5 has an invalid memory type"));
    cfg.push_back(path);

    path.setup = [&] { g_vmcs_fields[VMCS_HOST_IA32_PAT_FULL] = 2ULL << 48; };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("pat6 has an invalid memory type"));
    cfg.push_back(path);

    path.setup = [&] { g_vmcs_fields[VMCS_HOST_IA32_PAT_FULL] = 2ULL << 56; };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("pat7 has an invalid memory type"));
    cfg.push_back(path);

    path.setup = [&] { g_vmcs_fields[VMCS_HOST_IA32_PAT_FULL] = 0; };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_host_verify_load_ia32_efer_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { disable_exit_ctl(VM_EXIT_CONTROL_LOAD_IA32_EFER); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { enable_exit_ctl(VM_EXIT_CONTROL_LOAD_IA32_EFER); g_vmcs_fields[VMCS_HOST_IA32_EFER_FULL] = 0xe; };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("ia32 efer msr reserved buts must be 0 if load ia32 efer entry is enabled"));
    cfg.push_back(path);

    path.setup = [&] { disable_exit_ctl(VM_EXIT_CONTROL_HOST_ADDRESS_SPACE_SIZE); g_vmcs_fields[VMCS_HOST_IA32_EFER_FULL] = IA32_EFER_LMA; };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("host addr space is 0, but efer.lma is 1"));
    cfg.push_back(path);

    path.setup = [&] { enable_exit_ctl(VM_EXIT_CONTROL_HOST_ADDRESS_SPACE_SIZE); g_vmcs_fields[VMCS_HOST_IA32_EFER_FULL] = 0; };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("host addr space is 1, but efer.lma is 0"));
    cfg.push_back(path);

    path.setup = [&] { g_vmcs_fields[VMCS_HOST_IA32_EFER_FULL] = IA32_EFER_LMA; g_vmcs_fields[VMCS_HOST_CR0] = 0; };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { g_vmcs_fields[VMCS_HOST_CR0] = CR0_PG_PAGING; };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("efer.lme is 0, but efer.lma is 1"));
    cfg.push_back(path);

    path.setup = [&] { disable_exit_ctl(VM_EXIT_CONTROL_HOST_ADDRESS_SPACE_SIZE); g_vmcs_fields[VMCS_HOST_IA32_EFER_FULL] = IA32_EFER_LME; };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("efer.lme is 1, but efer.lma is 0"));
    cfg.push_back(path);

    path.setup = [&] { g_vmcs_fields[VMCS_HOST_IA32_EFER_FULL] = 0; };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_host_es_selector_rpl_ti_equal_zero_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { g_vmcs_fields[VMCS_HOST_ES_SELECTOR] = 0; };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { g_vmcs_fields[VMCS_HOST_ES_SELECTOR] = SELECTOR_RPL_FLAG; };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("host rpl / tr's es flag must be 0"));
    cfg.push_back(path);
}

static void
setup_check_host_cs_selector_rpl_ti_equal_zero_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { g_vmcs_fields[VMCS_HOST_CS_SELECTOR] = 0; };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { g_vmcs_fields[VMCS_HOST_CS_SELECTOR] = SELECTOR_RPL_FLAG; };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("host rpl / tr's cs flag must be 0"));
    cfg.push_back(path);
}

static void
setup_check_host_ss_selector_rpl_ti_equal_zero_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { g_vmcs_fields[VMCS_HOST_SS_SELECTOR] = 0; };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { g_vmcs_fields[VMCS_HOST_SS_SELECTOR] = SELECTOR_RPL_FLAG; };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("host rpl / tr's ss flag must be 0"));
    cfg.push_back(path);
}

static void
setup_check_host_ds_selector_rpl_ti_equal_zero_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { g_vmcs_fields[VMCS_HOST_DS_SELECTOR] = 0; };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { g_vmcs_fields[VMCS_HOST_DS_SELECTOR] = SELECTOR_RPL_FLAG; };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("host rpl / tr's ds flag must be 0"));
    cfg.push_back(path);
}

static void
setup_check_host_fs_selector_rpl_ti_equal_zero_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { g_vmcs_fields[VMCS_HOST_FS_SELECTOR] = 0;};
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { g_vmcs_fields[VMCS_HOST_FS_SELECTOR] = SELECTOR_RPL_FLAG; };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("host rpl / tr's fs flag must be 0"));
    cfg.push_back(path);
}

static void
setup_check_host_gs_selector_rpl_ti_equal_zero_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { g_vmcs_fields[VMCS_HOST_GS_SELECTOR] = 0; };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { g_vmcs_fields[VMCS_HOST_GS_SELECTOR] = SELECTOR_RPL_FLAG; };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("host rpl / tr's gs flag must be 0"));
    cfg.push_back(path);
}

static void
setup_check_host_tr_selector_rpl_ti_equal_zero_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { g_vmcs_fields[VMCS_HOST_TR_SELECTOR] = 0; };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { g_vmcs_fields[VMCS_HOST_TR_SELECTOR] = SELECTOR_RPL_FLAG; };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("host rpl / tr's tr flag must be 0"));
    cfg.push_back(path);
}

static void
setup_check_host_cs_not_equal_zero_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { g_vmcs_fields[VMCS_HOST_CS_SELECTOR] = 1; };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { g_vmcs_fields[VMCS_HOST_CS_SELECTOR] = 0; };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("host cs cannot equal 0"));
    cfg.push_back(path);
}

static void
setup_check_host_tr_not_equal_zero_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { g_vmcs_fields[VMCS_HOST_TR_SELECTOR] = 1; };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { g_vmcs_fields[VMCS_HOST_TR_SELECTOR] = 0; };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("host tr cannot equal 0"));
    cfg.push_back(path);
}

static void
setup_check_host_ss_not_equal_zero_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { enable_exit_ctl(VM_EXIT_CONTROL_HOST_ADDRESS_SPACE_SIZE); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { disable_exit_ctl(VM_EXIT_CONTROL_HOST_ADDRESS_SPACE_SIZE); g_vmcs_fields[VMCS_HOST_SS_SELECTOR] = 0; };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("host ss cannot equal 0"));
    cfg.push_back(path);

    path.setup = [&] { g_vmcs_fields[VMCS_HOST_SS_SELECTOR] = 1; };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_host_fs_canonical_base_address_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { g_vmcs_fields[VMCS_HOST_FS_BASE] = 1; };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { g_vmcs_fields[VMCS_HOST_FS_BASE] = 0x800000000000; };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("host fs base must be canonical"));
    cfg.push_back(path);
}

static void
setup_check_host_gs_canonical_base_address_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { g_vmcs_fields[VMCS_HOST_GS_BASE] = 1; };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { g_vmcs_fields[VMCS_HOST_GS_BASE] = 0x800000000000; };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("host gs base must be canonical"));
    cfg.push_back(path);
}

static void
setup_check_host_gdtr_canonical_base_address_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { g_vmcs_fields[VMCS_HOST_GDTR_BASE] = 1; };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { g_vmcs_fields[VMCS_HOST_GDTR_BASE] = 0x800000000000; };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("host gdtr base must be canonical"));
    cfg.push_back(path);
}

static void
setup_check_host_idtr_canonical_base_address_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { g_vmcs_fields[VMCS_HOST_IDTR_BASE] = 1; };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { g_vmcs_fields[VMCS_HOST_IDTR_BASE] = 0x800000000000; };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("host idtr base must be canonical"));
    cfg.push_back(path);
}

static void
setup_check_host_tr_canonical_base_address_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { g_vmcs_fields[VMCS_HOST_TR_BASE] = 1; };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { g_vmcs_fields[VMCS_HOST_TR_BASE] = 0x800000000000; };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("host tr base must be canonical"));
    cfg.push_back(path);
}

static void
setup_check_host_if_outside_ia32e_mode_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { g_msrs[IA32_EFER_MSR] = IA32_EFER_LMA; };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { g_msrs[IA32_EFER_MSR] = 0; enable_entry_ctl(VM_ENTRY_CONTROL_IA_32E_MODE_GUEST); };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("ia 32e mode must be 0 if efer.lma == 0"));
    cfg.push_back(path);

    path.setup = [&] { disable_entry_ctl(VM_ENTRY_CONTROL_IA_32E_MODE_GUEST); enable_exit_ctl(VM_EXIT_CONTROL_HOST_ADDRESS_SPACE_SIZE); };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("host addr space must be 0 if efer.lma == 0"));
    cfg.push_back(path);

    path.setup = [&] { disable_exit_ctl(VM_EXIT_CONTROL_HOST_ADDRESS_SPACE_SIZE); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_host_vmcs_host_address_space_size_is_set_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { g_msrs[IA32_EFER_MSR] = 0; };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { g_msrs[IA32_EFER_MSR] = IA32_EFER_LMA; disable_exit_ctl(VM_EXIT_CONTROL_HOST_ADDRESS_SPACE_SIZE); };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("host addr space must be 1 if efer.lma == 1"));
    cfg.push_back(path);

    path.setup = [&] { enable_exit_ctl(VM_EXIT_CONTROL_HOST_ADDRESS_SPACE_SIZE); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_host_host_address_space_disabled_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { enable_exit_ctl(VM_EXIT_CONTROL_HOST_ADDRESS_SPACE_SIZE); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { disable_exit_ctl(VM_EXIT_CONTROL_HOST_ADDRESS_SPACE_SIZE); enable_entry_ctl(VM_ENTRY_CONTROL_IA_32E_MODE_GUEST); };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("ia 32e mode must be disabled if host addr space is disabled"));
    cfg.push_back(path);

    path.setup = [&] { disable_entry_ctl(VM_ENTRY_CONTROL_IA_32E_MODE_GUEST); g_vmcs_fields[VMCS_HOST_CR4] = CR4_PCIDE_PCID_ENABLE_BIT; };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("cr4 pcide must be disabled if host addr space is disabled"));
    cfg.push_back(path);

    path.setup = [&] { g_vmcs_fields[VMCS_HOST_CR4] = 0; g_vmcs_fields[VMCS_HOST_RIP] = 0xf000000000; };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("rip bits 63:32 must be 0 if host addr space is disabled"));
    cfg.push_back(path);

    path.setup = [&] { g_vmcs_fields[VMCS_HOST_RIP] = 0; };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_host_host_address_space_enabled_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { disable_exit_ctl(VM_EXIT_CONTROL_HOST_ADDRESS_SPACE_SIZE); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { enable_exit_ctl(VM_EXIT_CONTROL_HOST_ADDRESS_SPACE_SIZE); g_vmcs_fields[VMCS_HOST_CR4] = 0; };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("cr4 pae must be enabled if host addr space is enabled"));
    cfg.push_back(path);

    path.setup = [&] { g_vmcs_fields[VMCS_HOST_CR4] = CR4_PAE_PHYSICAL_ADDRESS_EXTENSIONS; g_vmcs_fields[VMCS_HOST_RIP] = 0x800000000000; };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("host rip must be canonical"));
    cfg.push_back(path);

    path.setup = [&] { g_vmcs_fields[VMCS_HOST_RIP] = 0; };
    path.throws_exception = false;
    cfg.push_back(path);
}

void
vmcs_ut::test_check_host_cr0_for_unsupported_bits()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_host_cr0_for_unsupported_bits_paths(cfg);

    this->run_vmcs_test(cfg, &vmcs_intel_x64::check_host_cr0_for_unsupported_bits);
}

void
vmcs_ut::test_check_host_cr4_for_unsupported_bits()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_host_cr4_for_unsupported_bits_paths(cfg);

    this->run_vmcs_test(cfg, &vmcs_intel_x64::check_host_cr4_for_unsupported_bits);
}

void
vmcs_ut::test_check_host_cr3_for_unsupported_bits()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_host_cr3_for_unsupported_bits_paths(cfg);

    this->run_vmcs_test(cfg, &vmcs_intel_x64::check_host_cr3_for_unsupported_bits);
}

void
vmcs_ut::test_check_host_ia32_sysenter_esp_canonical_address()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_host_ia32_sysenter_esp_canonical_address_paths(cfg);

    this->run_vmcs_test(cfg, &vmcs_intel_x64::check_host_ia32_sysenter_esp_canonical_address);
}

void
vmcs_ut::test_check_host_ia32_sysenter_eip_canonical_address()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_host_ia32_sysenter_eip_canonical_address_paths(cfg);

    this->run_vmcs_test(cfg, &vmcs_intel_x64::check_host_ia32_sysenter_eip_canonical_address);
}

void
vmcs_ut::test_check_host_verify_load_ia32_perf_global_ctrl()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_host_verify_load_ia32_perf_global_ctrl_paths(cfg);

    this->run_vmcs_test(cfg, &vmcs_intel_x64::check_host_verify_load_ia32_perf_global_ctrl);
}

void
vmcs_ut::test_check_host_verify_load_ia32_pat()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_host_verify_load_ia32_pat_paths(cfg);

    this->run_vmcs_test(cfg, &vmcs_intel_x64::check_host_verify_load_ia32_pat);
}

void
vmcs_ut::test_check_host_verify_load_ia32_efer()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_host_verify_load_ia32_efer_paths(cfg);

    this->run_vmcs_test(cfg, &vmcs_intel_x64::check_host_verify_load_ia32_efer);
}

void
vmcs_ut::test_check_host_es_selector_rpl_ti_equal_zero()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_host_es_selector_rpl_ti_equal_zero_paths(cfg);

    this->run_vmcs_test(cfg, &vmcs_intel_x64::check_host_es_selector_rpl_ti_equal_zero);
}

void
vmcs_ut::test_check_host_cs_selector_rpl_ti_equal_zero()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_host_cs_selector_rpl_ti_equal_zero_paths(cfg);

    this->run_vmcs_test(cfg, &vmcs_intel_x64::check_host_cs_selector_rpl_ti_equal_zero);
}

void
vmcs_ut::test_check_host_ss_selector_rpl_ti_equal_zero()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_host_ss_selector_rpl_ti_equal_zero_paths(cfg);

    this->run_vmcs_test(cfg, &vmcs_intel_x64::check_host_ss_selector_rpl_ti_equal_zero);
}

void
vmcs_ut::test_check_host_ds_selector_rpl_ti_equal_zero()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_host_ds_selector_rpl_ti_equal_zero_paths(cfg);

    this->run_vmcs_test(cfg, &vmcs_intel_x64::check_host_ds_selector_rpl_ti_equal_zero);
}

void
vmcs_ut::test_check_host_fs_selector_rpl_ti_equal_zero()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_host_fs_selector_rpl_ti_equal_zero_paths(cfg);

    this->run_vmcs_test(cfg, &vmcs_intel_x64::check_host_fs_selector_rpl_ti_equal_zero);
}

void
vmcs_ut::test_check_host_gs_selector_rpl_ti_equal_zero()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_host_gs_selector_rpl_ti_equal_zero_paths(cfg);

    this->run_vmcs_test(cfg, &vmcs_intel_x64::check_host_gs_selector_rpl_ti_equal_zero);
}

void
vmcs_ut::test_check_host_tr_selector_rpl_ti_equal_zero()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_host_tr_selector_rpl_ti_equal_zero_paths(cfg);

    this->run_vmcs_test(cfg, &vmcs_intel_x64::check_host_tr_selector_rpl_ti_equal_zero);
}

void
vmcs_ut::test_check_host_cs_not_equal_zero()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_host_cs_not_equal_zero_paths(cfg);

    this->run_vmcs_test(cfg, &vmcs_intel_x64::check_host_cs_not_equal_zero);
}

void
vmcs_ut::test_check_host_tr_not_equal_zero()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_host_tr_not_equal_zero_paths(cfg);

    this->run_vmcs_test(cfg, &vmcs_intel_x64::check_host_tr_not_equal_zero);
}

void
vmcs_ut::test_check_host_ss_not_equal_zero()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_host_ss_not_equal_zero_paths(cfg);

    this->run_vmcs_test(cfg, &vmcs_intel_x64::check_host_ss_not_equal_zero);
}

void
vmcs_ut::test_check_host_fs_canonical_base_address()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_host_fs_canonical_base_address_paths(cfg);

    this->run_vmcs_test(cfg, &vmcs_intel_x64::check_host_fs_canonical_base_address);
}

void
vmcs_ut::test_check_host_gs_canonical_base_address()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_host_gs_canonical_base_address_paths(cfg);

    this->run_vmcs_test(cfg, &vmcs_intel_x64::check_host_gs_canonical_base_address);
}

void
vmcs_ut::test_check_host_gdtr_canonical_base_address()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_host_gdtr_canonical_base_address_paths(cfg);

    this->run_vmcs_test(cfg, &vmcs_intel_x64::check_host_gdtr_canonical_base_address);
}

void
vmcs_ut::test_check_host_idtr_canonical_base_address()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_host_idtr_canonical_base_address_paths(cfg);

    this->run_vmcs_test(cfg, &vmcs_intel_x64::check_host_idtr_canonical_base_address);
}

void
vmcs_ut::test_check_host_tr_canonical_base_address()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_host_tr_canonical_base_address_paths(cfg);

    this->run_vmcs_test(cfg, &vmcs_intel_x64::check_host_tr_canonical_base_address);
}

void
vmcs_ut::test_check_host_if_outside_ia32e_mode()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_host_if_outside_ia32e_mode_paths(cfg);

    this->run_vmcs_test(cfg, &vmcs_intel_x64::check_host_if_outside_ia32e_mode);
}

void
vmcs_ut::test_check_host_vmcs_host_address_space_size_is_set()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_host_vmcs_host_address_space_size_is_set_paths(cfg);

    this->run_vmcs_test(cfg, &vmcs_intel_x64::check_host_vmcs_host_address_space_size_is_set);
}

void
vmcs_ut::test_check_host_host_address_space_disabled()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_host_host_address_space_disabled_paths(cfg);

    this->run_vmcs_test(cfg, &vmcs_intel_x64::check_host_host_address_space_disabled);
}

void
vmcs_ut::test_check_host_host_address_space_enabled()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_host_host_address_space_enabled_paths(cfg);

    this->run_vmcs_test(cfg, &vmcs_intel_x64::check_host_host_address_space_enabled);
}
