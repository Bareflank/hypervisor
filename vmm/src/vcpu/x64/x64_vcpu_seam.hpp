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
    bsl::errc_type instruction_pointer_advance() noexcept final
    { return m_instruction_pointer.instruction_pointer_advance(); }

    // ------------------------- vcpu property seam ----------------------------
    vcpu_property::id_type id_get() noexcept final
    { return m_vcpu_property.id_get(); }

    bool is_bootstrap_vcpu() noexcept final
    { return m_vcpu_property.is_bootstrap_vcpu(); }

    bool is_root_vcpu() noexcept final
    { return m_vcpu_property.is_root_vcpu(); }

    // ----------------------------- cpuid seam --------------------------------
    void cpuid_vmexit_handler_set(x64_vcpu_delegate func) noexcept final
    { return m_cpuid.cpuid_vmexit_handler_set(func); }

    uint32_t cpuid_vmexit_leaf_get() noexcept final
    { return m_cpuid.cpuid_vmexit_leaf_get(); }

    uint32_t cpuid_vmexit_subleaf_get() noexcept final
    { return m_cpuid.cpuid_vmexit_subleaf_get(); }

    void cpuid_execute() noexcept final
    { return m_cpuid.cpuid_execute(); }

    void cpuid_emulate(uint32_t eax, uint32_t ebx, uint32_t ecx, uint32_t edx) noexcept final
    { return m_cpuid.cpuid_emulate(eax, ebx, ecx, edx); }

    // ------------------------------ cr0 seam ---------------------------------
    void cr0_write_vmexit_enable() noexcept final
    { return m_cr0.cr0_write_vmexit_enable(); }

    void cr0_write_vmexit_disable() noexcept final
    { return m_cr0.cr0_write_vmexit_disable(); }

    void cr0_write_vmexit_handler_set(x64_vcpu_delegate func) noexcept final
    { return m_cr0.cr0_write_vmexit_handler_set(func); }

    uint64_t cr0_write_vmexit_value_get() noexcept final
    { return m_cr0.cr0_write_vmexit_value_get(); }

    void cr0_write_execute() noexcept final
    { return m_cr0.cr0_write_execute(); }

    void cr0_write_emulate(uint64_t cr0_value) noexcept final
    { return m_cr0.cr0_write_emulate(cr0_value); }

    // ------------------------------ cr3 seam ---------------------------------
    void cr3_read_vmexit_enable() noexcept final
    { return m_cr3.cr3_read_vmexit_enable(); }

    void cr3_read_vmexit_disable() noexcept final
    { return m_cr3.cr3_read_vmexit_disable(); }

    void cr3_read_vmexit_handler_set(x64_vcpu_delegate func) noexcept final
    { return m_cr3.cr3_read_vmexit_handler_set(func); }

    void cr3_read_execute() noexcept final
    { return m_cr3.cr3_read_execute(); }

    void cr3_read_emulate(uint64_t cr3_value) noexcept final
    { return m_cr3.cr3_read_emulate(cr3_value); }

    void cr3_write_vmexit_enable() noexcept final
    { return m_cr3.cr3_write_vmexit_enable(); }

    void cr3_write_vmexit_disable() noexcept final
    { return m_cr3.cr3_write_vmexit_disable(); }

    void cr3_write_vmexit_handler_set(x64_vcpu_delegate func) noexcept final
    { return m_cr3.cr3_write_vmexit_handler_set(func); }

    uint64_t cr3_write_vmexit_value_get() noexcept final
    { return m_cr3.cr3_write_vmexit_value_get(); }

    void cr3_write_execute() noexcept final
    { return m_cr3.cr3_write_execute(); }

    void cr3_write_emulate(uint64_t cr3_value) noexcept final
    { return m_cr3.cr3_write_emulate(cr3_value); }

    // ------------------------------ cr4 seam ---------------------------------
    void cr4_write_vmexit_enable() noexcept final
    { return m_cr4.cr4_write_vmexit_enable(); }

    void cr4_write_vmexit_disable() noexcept final
    { return m_cr4.cr4_write_vmexit_disable(); }

    void cr4_write_vmexit_handler_set(x64_vcpu_delegate func) noexcept final
    { return m_cr4.cr4_write_vmexit_handler_set(func); }

    uint64_t cr4_write_vmexit_value_get() noexcept final
    { return m_cr4.cr4_write_vmexit_value_get(); }

    void cr4_write_execute() noexcept final
    { return m_cr4.cr4_write_execute(); }

    void cr4_write_emulate(uint64_t cr4_value) noexcept final
    { return m_cr4.cr4_write_emulate(cr4_value); }

    // ----------------------- general register seam ---------------------------
    uint64_t rax_get() noexcept
    { return m_general_register_x64.rax_get(); }

    void rax_set(uint64_t value) noexcept
    { return m_general_register_x64.rax_set(value); }

    uint64_t rbx_get() noexcept
    { return m_general_register_x64.rbx_get(); }

    void rbx_set(uint64_t value) noexcept
    { return m_general_register_x64.rbx_set(value); }

    uint64_t rcx_get() noexcept
    { return m_general_register_x64.rcx_get(); }

    void rcx_set(uint64_t value) noexcept
    { return m_general_register_x64.rcx_set(value); }

    uint64_t rdx_get() noexcept
    { return m_general_register_x64.rdx_get(); }

    void rdx_set(uint64_t value) noexcept
    { return m_general_register_x64.rdx_set(value); }

    uint64_t rbp_get() noexcept
    { return m_general_register_x64.rbp_get(); }

    void rbp_set(uint64_t value) noexcept
    { return m_general_register_x64.rbp_set(value); }

    uint64_t rsi_get() noexcept
    { return m_general_register_x64.rsi_get(); }

    void rsi_set(uint64_t value) noexcept
    { return m_general_register_x64.rsi_set(value); }

    uint64_t rdi_get() noexcept
    { return m_general_register_x64.rdi_get(); }

    void rdi_set(uint64_t value) noexcept
    { return m_general_register_x64.rdi_set(value); }

    uint64_t r8_get() noexcept
    { return m_general_register_x64.r8_get(); }

    void r8_set(uint64_t value) noexcept
    { return m_general_register_x64.r8_set(value); }

    uint64_t r9_get() noexcept
    { return m_general_register_x64.r9_get(); }

    void r9_set(uint64_t value) noexcept
    { return m_general_register_x64.r9_set(value); }

    uint64_t r10_get() noexcept
    { return m_general_register_x64.r10_get(); }

    void r10_set(uint64_t value) noexcept
    { return m_general_register_x64.r10_set(value); }

    uint64_t r11_get() noexcept
    { return m_general_register_x64.r11_get(); }

    void r11_set(uint64_t value) noexcept
    { return m_general_register_x64.r11_set(value); }

    uint64_t r12_get() noexcept
    { return m_general_register_x64.r12_get(); }

    void r12_set(uint64_t value) noexcept
    { return m_general_register_x64.r12_set(value); }

    uint64_t r13_get() noexcept
    { return m_general_register_x64.r13_get(); }

    void r13_set(uint64_t value) noexcept
    { return m_general_register_x64.r13_set(value); }

    uint64_t r14_get() noexcept
    { return m_general_register_x64.r14_get(); }

    void r14_set(uint64_t value) noexcept
    { return m_general_register_x64.r14_set(value); }

    uint64_t r15_get() noexcept
    { return m_general_register_x64.r15_get(); }

    void r15_set(uint64_t value) noexcept
    { return m_general_register_x64.r15_set(value); }

    uint64_t rip_get() noexcept
    { return m_general_register_x64.rip_get(); }

    void rip_set(uint64_t value) noexcept
    { return m_general_register_x64.rip_set(value); }

    uint64_t rsp_get() noexcept
    { return m_general_register_x64.rsp_get(); }

    void rsp_set(uint64_t value) noexcept
    { return m_general_register_x64.rsp_set(value); }

    // ------------------------- init signal seam ------------------------------
    void init_signal_vmexit_handler_set(x64_vcpu_delegate func) noexcept final
    { return m_init_signal.init_signal_vmexit_handler_set(func); }

    // ---------------------- interrupt seam --------------------------
    void interrupt_vmexit_enable() noexcept final
    { return m_interrupt.interrupt_vmexit_enable(); }

    void interrupt_vmexit_disable() noexcept final
    { return m_interrupt.interrupt_vmexit_disable(); }

    void interrupt_vmexit_handler_set(x64_vcpu_delegate func) noexcept final
    { return m_interrupt.interrupt_vmexit_handler_set(func); }

    void interrupt_inject(uint64_t vector) noexcept final
    { return m_interrupt.interrupt_inject(vector); }

    // ---------------------- interrupt window seam ----------------------------
    void interrupt_window_vmexit_enable() noexcept final
    { return m_interrupt_window.interrupt_window_vmexit_enable(); }

    void interrupt_window_vmexit_disable() noexcept final
    { return m_interrupt_window.interrupt_window_vmexit_disable(); }

    void interrupt_window_vmexit_handler_set(x64_vcpu_delegate func) noexcept final
    { return m_interrupt_window.interrupt_window_vmexit_handler_set(func); }

    // --------------------------- io port seam --------------------------------
    void io_port_vmexit_enable(uint16_t port_number) noexcept final
    { return m_io_port.io_port_vmexit_enable(port_number); }

    void io_port_vmexit_range_enable(uint16_t begin, uint16_t end) noexcept final
    { return m_io_port.io_port_vmexit_range_enable(begin, end); }

    void io_port_vmexit_disable(uint16_t port_number) noexcept final
    { return m_io_port.io_port_vmexit_disable(port_number); }

    void io_port_vmexit_range_disable(uint16_t begin, uint16_t end) noexcept final
    { return m_io_port.io_port_vmexit_range_disable(begin, end); }

    void io_port_vmexit_handler_set(x64_vcpu_delegate func) noexcept final
    { return m_io_port.io_port_vmexit_handler_set(func); }

    uint64_t io_port_vmexit_size_get() noexcept final
    { return m_io_port.io_port_vmexit_size_get(); }

    bool io_port_vmexit_is_in() noexcept final
    { return m_io_port.io_port_vmexit_is_in(); }

    bool io_port_vmexit_is_out() noexcept final
    { return m_io_port.io_port_vmexit_is_out(); }

    uint16_t io_port_vmexit_port_number_get() noexcept final
    { return m_io_port.io_port_vmexit_port_number_get(); }

    uint64_t io_port_vmexit_value_get() noexcept final
    { return m_io_port.io_port_vmexit_value_get(); }

    void io_port_out_execute() noexcept final
    { return m_io_port.io_port_out_execute(); }

    void io_port_out_emulate(uint64_t value) noexcept final
    { return m_io_port.io_port_out_emulate(value); }

    void io_port_in_execute() noexcept final
    { return m_io_port.io_port_in_execute(); }

    void io_port_in_emulate(uint64_t value) noexcept final
    { return m_io_port.io_port_in_emulate(value); }

    // ------------------------ monitor trap seam ------------------------------
    void monitor_trap_vmexit_enable() noexcept final
    { return m_monitor_trap.monitor_trap_vmexit_enable(); }

    void monitor_trap_vmexit_disable() noexcept final
    { return m_monitor_trap.monitor_trap_vmexit_disable(); }

    void monitor_trap_vmexit_handler_set(x64_vcpu_delegate func) noexcept final
    { return m_monitor_trap.monitor_trap_vmexit_handler_set(func); }

    // ------------------------- nested paging seam ----------------------------
    void nested_paging_enable() noexcept final
    { return m_nested_paging.nested_paging_enable(); }

    void nested_paging_disable() noexcept final
    { return m_nested_paging.nested_paging_disable(); }

    void nested_paging_base_address_set(uintptr_t phys_addr) noexcept final
    { return m_nested_paging.nested_paging_base_address_set(phys_addr); }

    void nested_paging_violation_vmexit_handler_set(x64_vcpu_delegate func) noexcept final
    { return m_nested_paging.nested_paging_violation_vmexit_handler_set(func); }

    void nested_paging_misconfiguration_vmexit_handler_set(x64_vcpu_delegate func) noexcept final
    { return m_nested_paging.nested_paging_misconfiguration_vmexit_handler_set(func); }

    bool nested_paging_vmexit_is_read() noexcept final
    { return m_nested_paging.nested_paging_vmexit_is_read(); }

    bool nested_paging_vmexit_is_write() noexcept final
    { return m_nested_paging.nested_paging_vmexit_is_write(); }

    bool nested_paging_vmexit_is_execute() noexcept final
    { return m_nested_paging.nested_paging_vmexit_is_execute(); }

    bool nested_paging_vmexit_is_violation() noexcept final
    { return m_nested_paging.nested_paging_vmexit_is_violation(); }

    bool nested_paging_vmexit_is_misconfiguration() noexcept final
    { return m_nested_paging.nested_paging_vmexit_is_misconfiguration(); }

    // ----------------------------- nmi seam ----------------------------------
    void nmi_vmexit_enable() noexcept final
    { return m_nmi.nmi_vmexit_enable(); }

    void nmi_vmexit_disable() noexcept final
    { return m_nmi.nmi_vmexit_disable(); }

    void nmi_vmexit_handler_set(x64_vcpu_delegate func) noexcept final
    { return m_nmi.nmi_vmexit_handler_set(func); }

    void nmi_inject() noexcept final
    { return m_nmi.nmi_inject(); }

    // -------------------------- nmi window seam ------------------------------
    void nmi_window_vmexit_enable() noexcept final
    { return m_nmi_window.nmi_window_vmexit_enable(); }

    void nmi_window_vmexit_disable() noexcept final
    { return m_nmi_window.nmi_window_vmexit_disable(); }

    void nmi_window_vmexit_handler_set(x64_vcpu_delegate func) noexcept final
    { return m_nmi_window.nmi_window_vmexit_handler_set(func); }

    // ----------------------- preemption timer seam ---------------------------
    void preemption_timer_vmexit_enable() noexcept final
    { return m_preemption_timer.preemption_timer_vmexit_enable(); }

    void preemption_timer_vmexit_disable() noexcept final
    { return m_preemption_timer.preemption_timer_vmexit_disable(); }

    void preemption_timer_vmexit_handler_set(x64_vcpu_delegate func) noexcept final
    { return m_preemption_timer.preemption_timer_vmexit_handler_set(func); }

    void preemption_timer_set(uint64_t value) noexcept final
    { return m_preemption_timer.preemption_timer_set(value); }

    // ----------------------------- rdmsr seam --------------------------------
    void rdmsr_vmexit_enable(uint32_t msr_address) noexcept final
    { return m_rdmsr.rdmsr_vmexit_enable(msr_address); }

    void rdmsr_vmexit_range_enable(uint32_t begin, uint32_t end) noexcept final
    { return m_rdmsr.rdmsr_vmexit_range_enable(begin, end); }

    void rdmsr_vmexit_disable(uint32_t msr_address) noexcept final
    { return m_rdmsr.rdmsr_vmexit_disable(msr_address); }

    void rdmsr_vmexit_range_disable(uint32_t begin, uint32_t end) noexcept final
    { return m_rdmsr.rdmsr_vmexit_range_disable(begin, end); }

    void rdmsr_vmexit_handler_set(x64_vcpu_delegate func) noexcept final
    { return m_rdmsr.rdmsr_vmexit_handler_set(func); }

    uint32_t rdmsr_vmexit_address_get() noexcept final
    { return m_rdmsr.rdmsr_vmexit_address_get(); }

    void rdmsr_execute() noexcept final
    { return m_rdmsr.rdmsr_execute(); }

    void rdmsr_emulate(uint64_t value) noexcept final
    { return m_rdmsr.rdmsr_emulate(value); }

    // ------------------------- sipi signal seam ------------------------------
    void sipi_signal_vmexit_handler_set(x64_vcpu_delegate func) noexcept final
    { return m_sipi_signal.sipi_signal_vmexit_handler_set(func); }

    // ----------------------------- vmcall seam -------------------------------
    void vmcall_vmexit_handler_set(x64_vcpu_delegate func) noexcept final
    { return m_vmcall.vmcall_vmexit_handler_set(func); }

    // ----------------------------- vmexit seam -------------------------------
    uint32_t vmexit_reason_get() noexcept final
    { return m_vmexit.vmexit_reason_get(); }

    uint32_t vmexit_qualification_get() noexcept final
    { return m_vmexit.vmexit_qualification_get(); }

    void vmexit_handler_set(x64_vcpu_delegate func) noexcept final
    { return m_vmexit.vmexit_handler_set(func); }

    void post_vmexit_handler_set(x64_vcpu_delegate func) noexcept final
    { return m_vmexit.post_vmexit_handler_set(func); }

    // ------------------------------ vpid seam --------------------------------
    void vpid_enable() noexcept final
    { return m_vpid.vpid_enable(); }

    // ----------------------------- wrmsr seam --------------------------------
    void wrmsr_vmexit_enable(uint32_t msr_address) noexcept final
    { return m_wrmsr.wrmsr_vmexit_enable(msr_address); }

    void wrmsr_vmexit_range_enable(uint32_t begin, uint32_t end) noexcept final
    { return m_wrmsr.wrmsr_vmexit_range_enable(begin, end); }

    void wrmsr_vmexit_disable(uint32_t msr_address) noexcept final
    { return m_wrmsr.wrmsr_vmexit_disable(msr_address); }

    void wrmsr_vmexit_range_disable(uint32_t begin, uint32_t end) noexcept final
    { return m_wrmsr.wrmsr_vmexit_range_disable(begin, end); }

    void wrmsr_vmexit_handler_set(x64_vcpu_delegate func) noexcept final
    { return m_wrmsr.wrmsr_vmexit_handler_set(func); }

    uint32_t wrmsr_vmexit_address_get() noexcept final
    { return m_wrmsr.wrmsr_vmexit_address_get(); }

    uint64_t wrmsr_vmexit_value_get() noexcept final
    { return m_wrmsr.wrmsr_vmexit_value_get(); }

    void wrmsr_execute() noexcept final
    { return m_wrmsr.wrmsr_execute(); }

    void wrmsr_emulate(uint64_t value) noexcept final
    { return m_wrmsr.wrmsr_emulate(value); }

    // ------------------------------ xcr0 seam --------------------------------
    void xcr0_write_vmexit_handler_set(x64_vcpu_delegate func)
    { return m_xcr0.xcr0_write_vmexit_handler_set(func); }

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