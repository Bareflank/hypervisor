#ifndef VMM_X64_VCPU_SEAM_HPP
#define VMM_X64_VCPU_SEAM_HPP

#include <vmm/vcpu/x64/x64_vcpu.hpp>
#include <vmm/vcpu/x64/x64_vcpu_delegate.hpp>

namespace vmm
{

template<
    // Generic vcpu interfaces:
    class execute_type,
    class instruction_pointer_type,
    class vcpu_property_type,
    class virtual_register_type,
    // x64 vcpu interfaces:
    class cpuid_type,
    class cr0_type,
    class cr3_type,
    class cr4_type,
    class general_register_x64_type,
    class init_signal_type,
    class interrupt_type,
    class interrupt_window_type,
    class io_port_type,
    class monitor_trap_type,
    class nested_paging_type,
    class nmi_type,
    class nmi_window_type,
    class preemption_timer_type,
    class rdmsr_type,
    class sipi_signal_type,
    class vmcall_type,
    class vmexit_type,
    class vpid_type,
    class wrmsr_type,
    class xcr0_type
>
class x64_vcpu_seam :
    public x64_vcpu
{
public:

    // --------------------------- execute seam -------------------------------
    bsl::errc_type load() noexcept final
    { return m_execute.load(); }

    bsl::errc_type unload() noexcept final
    { return m_execute.unload(); }

    bsl::errc_type run() noexcept final
    { return m_execute.run(); }

    // ---------------------- instruction pointer seam -------------------------
    bsl::errc_type advance_instruction_pointer() noexcept final
    { return m_instruction_pointer.advance_instruction_pointer(); }

    // ------------------------- vcpu property seam ----------------------------
    vcpu_property::id_type get_id() noexcept final
    { return m_vcpu_property.get_id(); }

    bool is_bootstrap_vcpu() noexcept final
    { return m_vcpu_property.is_bootstrap_vcpu(); }

    bool is_root_vcpu() noexcept final
    { return m_vcpu_property.is_root_vcpu(); }

    // ----------------------------- cpuid seam --------------------------------
    void set_cpuid_vmexit_handler(x64_vcpu_delegate func) noexcept final
    { return m_cpuid.set_cpuid_vmexit_handler(func); }

    uint32_t get_cpuid_vmexit_leaf() noexcept final
    { return m_cpuid.get_cpuid_vmexit_leaf(); }

    uint32_t get_cpuid_vmexit_subleaf() noexcept final
    { return m_cpuid.get_cpuid_vmexit_subleaf(); }

    void execute_cpuid() noexcept final
    { return m_cpuid.execute_cpuid(); }

    void emulate_cpuid(uint32_t eax, uint32_t ebx, uint32_t ecx, uint32_t edx) noexcept final
    { return m_cpuid.emulate_cpuid(eax, ebx, ecx, edx); }

    // ------------------------------ cr0 seam ---------------------------------
    void enable_cr0_write_vmexit() noexcept final
    { return m_cr0.enable_cr0_write_vmexit(); }

    void disable_cr0_write_vmexit() noexcept final
    { return m_cr0.disable_cr0_write_vmexit(); }

    void set_cr0_write_vmexit_handler(x64_vcpu_delegate func) noexcept final
    { return m_cr0.set_cr0_write_vmexit_handler(func); }

    uint64_t get_cr0_write_vmexit_value() noexcept final
    { return m_cr0.get_cr0_write_vmexit_value(); }

    void execute_cr0_write() noexcept final
    { return m_cr0.execute_cr0_write(); }

    void emulate_cr0_write(uint64_t cr0_value) noexcept final
    { return m_cr0.emulate_cr0_write(cr0_value); }

    // ------------------------------ cr3 seam ---------------------------------
    void enable_cr3_read_vmexit() noexcept final
    { return m_cr3.enable_cr3_read_vmexit(); }

    void disable_cr3_read_vmexit() noexcept final
    { return m_cr3.disable_cr3_read_vmexit(); }

    void set_cr3_read_vmexit_handler(x64_vcpu_delegate func) noexcept final
    { return m_cr3.set_cr3_read_vmexit_handler(func); }

    void execute_cr3_read() noexcept final
    { return m_cr3.execute_cr3_read(); }

    void emulate_cr3_read(uint64_t cr3_value) noexcept final
    { return m_cr3.emulate_cr3_read(cr3_value); }

    void enable_cr3_write_vmexit() noexcept final
    { return m_cr3.enable_cr3_write_vmexit(); }

    void disable_cr3_write_vmexit() noexcept final
    { return m_cr3.disable_cr3_write_vmexit(); }

    void set_cr3_write_vmexit_handler(x64_vcpu_delegate func) noexcept final
    { return m_cr3.set_cr3_write_vmexit_handler(func); }

    uint64_t get_cr3_write_vmexit_value() noexcept final
    { return m_cr3.get_cr3_write_vmexit_value(); }

    void execute_cr3_write() noexcept final
    { return m_cr3.execute_cr3_write(); }

    void emulate_cr3_write(uint64_t cr3_value) noexcept final
    { return m_cr3.emulate_cr3_write(cr3_value); }

    // ------------------------------ cr4 seam ---------------------------------
    void enable_cr4_write_vmexit() noexcept final
    { return m_cr4.enable_cr4_write_vmexit(); }

    void disable_cr4_write_vmexit() noexcept final
    { return m_cr4.disable_cr4_write_vmexit(); }

    void set_cr4_write_vmexit_handler(x64_vcpu_delegate func) noexcept final
    { return m_cr4.set_cr4_write_vmexit_handler(func); }

    uint64_t get_cr4_write_vmexit_value() noexcept final
    { return m_cr4.get_cr4_write_vmexit_value(); }

    void execute_cr4_write() noexcept final
    { return m_cr4.execute_cr4_write(); }

    void emulate_cr4_write(uint64_t cr4_value) noexcept final
    { return m_cr4.emulate_cr4_write(cr4_value); }

    // ----------------------- general register seam ---------------------------
    uint64_t get_rax() noexcept
    { return m_general_register_x64.get_rax(); }

    void set_rax(uint64_t value) noexcept
    { return m_general_register_x64.set_rax(value); }

    uint64_t get_rbx() noexcept
    { return m_general_register_x64.get_rbx(); }

    void set_rbx(uint64_t value) noexcept
    { return m_general_register_x64.set_rbx(value); }

    uint64_t get_rcx() noexcept
    { return m_general_register_x64.get_rcx(); }

    void set_rcx(uint64_t value) noexcept
    { return m_general_register_x64.set_rcx(value); }

    uint64_t get_rdx() noexcept
    { return m_general_register_x64.get_rdx(); }

    void set_rdx(uint64_t value) noexcept
    { return m_general_register_x64.set_rdx(value); }

    uint64_t get_rbp() noexcept
    { return m_general_register_x64.get_rbp(); }

    void set_rbp(uint64_t value) noexcept
    { return m_general_register_x64.set_rbp(value); }

    uint64_t get_rsi() noexcept
    { return m_general_register_x64.get_rsi(); }

    void set_rsi(uint64_t value) noexcept
    { return m_general_register_x64.set_rsi(value); }

    uint64_t get_rdi() noexcept
    { return m_general_register_x64.get_rdi(); }

    void set_rdi(uint64_t value) noexcept
    { return m_general_register_x64.set_rdi(value); }

    uint64_t get_r8() noexcept
    { return m_general_register_x64.get_r8(); }

    void set_r8(uint64_t value) noexcept
    { return m_general_register_x64.set_r8(value); }

    uint64_t get_r9() noexcept
    { return m_general_register_x64.get_r9(); }

    void set_r9(uint64_t value) noexcept
    { return m_general_register_x64.set_r9(value); }

    uint64_t get_r10() noexcept
    { return m_general_register_x64.get_r10(); }

    void set_r10(uint64_t value) noexcept
    { return m_general_register_x64.set_r10(value); }

    uint64_t get_r11() noexcept
    { return m_general_register_x64.get_r11(); }

    void set_r11(uint64_t value) noexcept
    { return m_general_register_x64.set_r11(value); }

    uint64_t get_r12() noexcept
    { return m_general_register_x64.get_r12(); }

    void set_r12(uint64_t value) noexcept
    { return m_general_register_x64.set_r12(value); }

    uint64_t get_r13() noexcept
    { return m_general_register_x64.get_r13(); }

    void set_r13(uint64_t value) noexcept
    { return m_general_register_x64.set_r13(value); }

    uint64_t get_r14() noexcept
    { return m_general_register_x64.get_r14(); }

    void set_r14(uint64_t value) noexcept
    { return m_general_register_x64.set_r14(value); }

    uint64_t get_r15() noexcept
    { return m_general_register_x64.get_r15(); }

    void set_r15(uint64_t value) noexcept
    { return m_general_register_x64.set_r15(value); }

    uint64_t get_rip() noexcept
    { return m_general_register_x64.get_rip(); }

    void set_rip(uint64_t value) noexcept
    { return m_general_register_x64.set_rip(value); }

    uint64_t get_rsp() noexcept
    { return m_general_register_x64.get_rsp(); }

    void set_rsp(uint64_t value) noexcept
    { return m_general_register_x64.set_rsp(value); }

    // ------------------------- init signal seam ------------------------------
    void set_init_signal_vmexit_handler(x64_vcpu_delegate func) noexcept final
    { return m_init_signal.set_init_signal_vmexit_handler(func); }

    // ---------------------- interrupt seam --------------------------
    void enable_interrupt_vmexit() noexcept final
    { return m_interrupt.enable_interrupt_vmexit(); }

    void disable_interrupt_vmexit() noexcept final
    { return m_interrupt.disable_interrupt_vmexit(); }

    void set_interrupt_vmexit_handler(x64_vcpu_delegate func) noexcept final
    { return m_interrupt.set_interrupt_vmexit_handler(func); }

    void inject_interrupt(uint64_t vector) noexcept final
    { return m_interrupt.inject_interrupt(vector); }

    // ---------------------- interrupt window seam ----------------------------
    void enable_interrupt_window_vmexit() noexcept final
    { return m_interrupt_window.enable_interrupt_window_vmexit(); }

    void disable_interrupt_window_vmexit() noexcept final
    { return m_interrupt_window.disable_interrupt_window_vmexit(); }

    void set_interrupt_window_vmexit_handler(x64_vcpu_delegate func) noexcept final
    { return m_interrupt_window.set_interrupt_window_vmexit_handler(func); }

    // --------------------------- io port seam --------------------------------
    void enable_io_port_vmexit(uint16_t port_number) noexcept final
    { return m_io_port.enable_io_port_vmexit(port_number); }

    void enable_io_port_vmexit_range(uint16_t begin, uint16_t end) noexcept final
    { return m_io_port.enable_io_port_vmexit_range(begin, end); }

    void disable_io_port_vmexit(uint16_t port_number) noexcept final
    { return m_io_port.disable_io_port_vmexit(port_number); }

    void disable_io_port_vmexit_range(uint16_t begin, uint16_t end) noexcept final
    { return m_io_port.disable_io_port_vmexit_range(begin, end); }

    void set_io_port_vmexit_handler(x64_vcpu_delegate func) noexcept final
    { return m_io_port.set_io_port_vmexit_handler(func); }

    uint64_t get_io_port_vmexit_size() noexcept final
    { return m_io_port.get_io_port_vmexit_size(); }

    bool is_io_port_vmexit_in() noexcept final
    { return m_io_port.is_io_port_vmexit_in(); }

    bool is_io_port_vmexit_out() noexcept final
    { return m_io_port.is_io_port_vmexit_out(); }

    uint16_t get_io_port_vmexit_port_number() noexcept final
    { return m_io_port.get_io_port_vmexit_port_number(); }

    uint64_t get_io_port_vmexit_value() noexcept final
    { return m_io_port.get_io_port_vmexit_value(); }

    void execute_io_port_out() noexcept final
    { return m_io_port.execute_io_port_out(); }

    void emulate_io_port_out(uint64_t value) noexcept final
    { return m_io_port.emulate_io_port_out(value); }

    void execute_io_port_in() noexcept final
    { return m_io_port.execute_io_port_in(); }

    void emulate_io_port_in(uint64_t value) noexcept final
    { return m_io_port.emulate_io_port_in(value); }

    // ------------------------ monitor trap seam ------------------------------
    void enable_monitor_trap_vmexit() noexcept final
    { return m_monitor_trap.enable_monitor_trap_vmexit(); }

    void disable_monitor_trap_vmexit() noexcept final
    { return m_monitor_trap.disable_monitor_trap_vmexit(); }

    void set_monitor_trap_vmexit_handler(x64_vcpu_delegate func) noexcept final
    { return m_monitor_trap.set_monitor_trap_vmexit_handler(func); }

    // ------------------------- nested paging seam ----------------------------
    void enable_nested_paging() noexcept final
    { return m_nested_paging.enable_nested_paging(); }

    void disable_nested_paging() noexcept final
    { return m_nested_paging.disable_nested_paging(); }

    void set_nested_paging_base_address(uintptr_t phys_addr) noexcept final
    { return m_nested_paging.set_nested_paging_base_address(phys_addr); }

    void set_nested_paging_violation_vmexit_handler(x64_vcpu_delegate func) noexcept final
    { return m_nested_paging.set_nested_paging_violation_vmexit_handler(func); }

    void set_nested_paging_misconfiguration_vmexit_handler(x64_vcpu_delegate func) noexcept final
    { return m_nested_paging.set_nested_paging_misconfiguration_vmexit_handler(func); }

    bool is_nested_paging_vmexit_read() noexcept final
    { return m_nested_paging.is_nested_paging_vmexit_read(); }

    bool is_nested_paging_vmexit_write() noexcept final
    { return m_nested_paging.is_nested_paging_vmexit_write(); }

    bool is_nested_paging_vmexit_execute() noexcept final
    { return m_nested_paging.is_nested_paging_vmexit_execute(); }

    bool is_nested_paging_vmexit_violation() noexcept final
    { return m_nested_paging.is_nested_paging_vmexit_violation(); }

    bool is_nested_paging_vmexit_misconfiguration() noexcept final
    { return m_nested_paging.is_nested_paging_vmexit_misconfiguration(); }

    // ----------------------------- nmi seam ----------------------------------
    void enable_nmi_vmexit() noexcept final
    { return m_nmi.enable_nmi_vmexit(); }

    void disable_nmi_vmexit() noexcept final
    { return m_nmi.disable_nmi_vmexit(); }

    void set_nmi_vmexit_handler(x64_vcpu_delegate func) noexcept final
    { return m_nmi.set_nmi_vmexit_handler(func); }

    void inject_nmi() noexcept final
    { return m_nmi.inject_nmi(); }

    // -------------------------- nmi window seam ------------------------------
    void enable_nmi_window_vmexit() noexcept final
    { return m_nmi_window.enable_nmi_window_vmexit(); }

    void disable_nmi_window_vmexit() noexcept final
    { return m_nmi_window.disable_nmi_window_vmexit(); }

    void set_nmi_window_vmexit_handler(x64_vcpu_delegate func) noexcept final
    { return m_nmi_window.set_nmi_window_vmexit_handler(func); }

    // ----------------------- preemption timer seam ---------------------------
    void enable_preemption_timer_vmexit() noexcept final
    { return m_preemption_timer.enable_preemption_timer_vmexit(); }

    void disable_preemption_timer_vmexit() noexcept final
    { return m_preemption_timer.disable_preemption_timer_vmexit(); }

    void set_preemption_timer_vmexit_handler(x64_vcpu_delegate func) noexcept final
    { return m_preemption_timer.set_preemption_timer_vmexit_handler(func); }

    void set_preemption_timer(uint64_t value) noexcept final
    { return m_preemption_timer.set_preemption_timer(value); }

    // ----------------------------- rdmsr seam --------------------------------
    void enable_rdmsr_vmexit(uint32_t msr_address) noexcept final
    { return m_rdmsr.enable_rdmsr_vmexit(msr_address); }

    void enable_rdmsr_vmexit_range(uint32_t begin, uint32_t end) noexcept final
    { return m_rdmsr.enable_rdmsr_vmexit_range(begin, end); }

    void disable_rdmsr_vmexit(uint32_t msr_address) noexcept final
    { return m_rdmsr.disable_rdmsr_vmexit(msr_address); }

    void disable_rdmsr_vmexit_range(uint32_t begin, uint32_t end) noexcept final
    { return m_rdmsr.disable_rdmsr_vmexit_range(begin, end); }

    void set_rdmsr_vmexit_handler(x64_vcpu_delegate func) noexcept final
    { return m_rdmsr.set_rdmsr_vmexit_handler(func); }

    uint32_t get_rdmsr_vmexit_address() noexcept final
    { return m_rdmsr.get_rdmsr_vmexit_address(); }

    void execute_rdmsr() noexcept final
    { return m_rdmsr.execute_rdmsr(); }

    void emulate_rdmsr(uint64_t value) noexcept final
    { return m_rdmsr.emulate_rdmsr(value); }

    // ------------------------- sipi signal seam ------------------------------
    void set_sipi_signal_vmexit_handler(x64_vcpu_delegate func) noexcept final
    { return m_sipi_signal.set_sipi_signal_vmexit_handler(func); }

    // ----------------------------- vmcall seam -------------------------------
    void set_vmcall_vmexit_handler(x64_vcpu_delegate func) noexcept final
    { return m_vmcall.set_vmcall_vmexit_handler(func); }

    // ----------------------------- vmexit seam -------------------------------
    uint32_t get_vmexit_reason() noexcept final
    { return m_vmexit.get_vmexit_reason(); }

    uint32_t get_vmexit_qualification() noexcept final
    { return m_vmexit.get_vmexit_qualification(); }

    void set_vmexit_handler(x64_vcpu_delegate func) noexcept final
    { return m_vmexit.set_vmexit_handler(func); }

    void set_post_vmexit_handler(x64_vcpu_delegate func) noexcept final
    { return m_vmexit.set_post_vmexit_handler(func); }

    // ------------------------------ vpid seam --------------------------------
    void enable_vpid() noexcept final
    { return m_vpid.enable_vpid(); }

    // ----------------------------- wrmsr seam --------------------------------
    void enable_wrmsr_vmexit(uint32_t msr_address) noexcept final
    { return m_wrmsr.enable_wrmsr_vmexit(msr_address); }

    void enable_wrmsr_vmexit_range(uint32_t begin, uint32_t end) noexcept final
    { return m_wrmsr.enable_wrmsr_vmexit_range(begin, end); }

    void disable_wrmsr_vmexit(uint32_t msr_address) noexcept final
    { return m_wrmsr.disable_wrmsr_vmexit(msr_address); }

    void disable_wrmsr_vmexit_range(uint32_t begin, uint32_t end) noexcept final
    { return m_wrmsr.disable_wrmsr_vmexit_range(begin, end); }

    void set_wrmsr_vmexit_handler(x64_vcpu_delegate func) noexcept final
    { return m_wrmsr.set_wrmsr_vmexit_handler(func); }

    uint32_t get_wrmsr_vmexit_address() noexcept final
    { return m_wrmsr.get_wrmsr_vmexit_address(); }

    uint64_t get_wrmsr_vmexit_value() noexcept final
    { return m_wrmsr.get_wrmsr_vmexit_value(); }

    void execute_wrmsr() noexcept final
    { return m_wrmsr.execute_wrmsr(); }

    void emulate_wrmsr(uint64_t value) noexcept final
    { return m_wrmsr.emulate_wrmsr(value); }

    // ------------------------------ xcr0 seam --------------------------------
    void set_xcr0_write_vmexit_handler(x64_vcpu_delegate func)
    { return m_xcr0.set_xcr0_write_vmexit_handler(func); }

private:
    execute_type m_execute{};
    instruction_pointer_type m_instruction_pointer{};
    nested_paging_type m_nested_paging{};
    vcpu_property_type m_vcpu_property{};
    virtual_register_type m_virtual_register{};
    cpuid_type m_cpuid{};
    cr0_type m_cr0{};
    cr3_type m_cr3{};
    cr4_type m_cr4{};
    interrupt_type m_interrupt{};
    general_register_x64_type m_general_register_x64{};
    init_signal_type m_init_signal{};
    interrupt_window_type m_interrupt_window{};
    io_port_type m_io_port{};
    monitor_trap_type m_monitor_trap{};
    nmi_type m_nmi{};
    nmi_window_type m_nmi_window{};
    preemption_timer_type m_preemption_timer{};
    rdmsr_type m_rdmsr{};
    sipi_signal_type m_sipi_signal{};
    vmcall_type m_vmcall{};
    vmexit_type m_vmexit{};
    vpid_type m_vpid{};
    wrmsr_type m_wrmsr{};
    xcr0_type m_xcr0{};
};

}

#endif
