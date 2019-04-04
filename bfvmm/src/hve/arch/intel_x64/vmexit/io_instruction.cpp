//
// Copyright (C) 2019 Assured Information Security, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

// TIDY_EXCLUSION=-performance-move-const-arg
//
// Reason:
//     Tidy complains that the std::move(d)'s used in the add_handler calls
//     have no effect. Removing std::move however results in a compiler error
//     saying the lvalue (d) can't bind to the rvalue.
//

#include <hve/arch/intel_x64/vcpu.h>

namespace bfvmm::intel_x64
{

io_instruction_handler::io_instruction_handler(
    gsl::not_null<vcpu *> vcpu
) :
    m_vcpu{vcpu},
    m_io_bitmap_a{vcpu->io_bitmap_a(), ::x64::pt::page_size},
    m_io_bitmap_b{vcpu->io_bitmap_b(), ::x64::pt::page_size}
{
    using namespace vmcs_n;

    vcpu->add_exit_handler_for_reason(
        exit_reason::basic_exit_reason::io_instruction,
    {&io_instruction_handler::handle, this}
    );
}

// -----------------------------------------------------------------------------
// Add Handler
// -----------------------------------------------------------------------------

void
io_instruction_handler::add_handler(
    vmcs_n::value_type port,
    const handler_delegate_t &in_d,
    const handler_delegate_t &out_d)
{
    m_in_handlers[port].push_front(std::move(in_d));
    m_out_handlers[port].push_front(std::move(out_d));
}

void
io_instruction_handler::emulate(vmcs_n::value_type port)
{ m_emulate[port] = true; }

void
io_instruction_handler::set_default_handler(
    const ::handler_delegate_t &d)
{ m_default_handler = d; }

// -----------------------------------------------------------------------------
// Enablers
// -----------------------------------------------------------------------------

void
io_instruction_handler::trap_on_access(vmcs_n::value_type port)
{
    if (port < 0x8000) {
        set_bit(m_io_bitmap_a, port);
        return;
    }

    if (port < 0x10000) {
        set_bit(m_io_bitmap_b, port - 0x8000);
        return;
    }

    throw std::runtime_error("invalid port: " + std::to_string(port));
}

void
io_instruction_handler::trap_on_all_accesses()
{
    gsl::memset(m_io_bitmap_a, 0xFF);
    gsl::memset(m_io_bitmap_b, 0xFF);
}

void
io_instruction_handler::pass_through_access(vmcs_n::value_type port)
{
    if (port < 0x8000) {
        clear_bit(m_io_bitmap_a, port);
        return;
    }

    if (port < 0x10000) {
        clear_bit(m_io_bitmap_b, port - 0x8000);
        return;
    }

    throw std::runtime_error("invalid port: " + std::to_string(port));
}

void
io_instruction_handler::pass_through_all_accesses()
{
    gsl::memset(m_io_bitmap_a, 0x0);
    gsl::memset(m_io_bitmap_b, 0x0);
}

// -----------------------------------------------------------------------------
// Handlers
// -----------------------------------------------------------------------------

bool
io_instruction_handler::handle(vcpu *vcpu)
{
    namespace io_instruction = vmcs_n::exit_qualification::io_instruction;
    auto eq = io_instruction::get();

    auto reps = 1ULL;
    if (io_instruction::rep_prefixed::is_enabled(eq)) {
        reps = vcpu->rcx() & 0x00000000FFFFFFFFULL;
    }

    struct info_t info = {
        0ULL,
        io_instruction::size_of_access::get(eq),
        0ULL,
        0ULL,
        false,
        false
    };

    switch (io_instruction::operand_encoding::get(eq)) {
        case io_instruction::operand_encoding::dx:
            info.port_number = vcpu->rdx() & 0x000000000000FFFFULL;
            break;

        default:
            info.port_number = io_instruction::port_number::get(eq);
            break;
    }

    if (io_instruction::string_instruction::is_enabled(eq)) {
        info.address = vmcs_n::guest_linear_address::get();
    }

    for (auto i = 0ULL; i < reps; i++) {
        switch (io_instruction::direction_of_access::get(eq)) {
            case io_instruction::direction_of_access::in:
                handle_in(vcpu, info);
                break;

            default:
                handle_out(vcpu, info);
                break;
        }

        info.address += info.size_of_access + 1ULL;
    }

    return true;
}

bool
io_instruction_handler::handle_in(vcpu *vcpu, info_t &info)
{
    const auto &hdlrs =
        m_in_handlers.find(info.port_number);

    if (GSL_LIKELY(hdlrs != m_in_handlers.end())) {

        if (!m_emulate[info.port_number]) {
            emulate_in(info);
        }

        for (const auto &d : hdlrs->second) {
            if (d(vcpu, info)) {

                if (!info.ignore_write) {
                    store_operand(vcpu, info);
                }

                if (!info.ignore_advance) {
                    return vcpu->advance();
                }

                return true;
            }
        }
    }

    if (m_default_handler) {
        bfdebug_nhex(0, "handle_in", info.port_number);
        return m_default_handler(vcpu);
    }

    return false;
}

bool
io_instruction_handler::handle_out(vcpu *vcpu, info_t &info)
{
    const auto &hdlrs =
        m_out_handlers.find(info.port_number);

    if (GSL_LIKELY(hdlrs != m_out_handlers.end())) {
        load_operand(vcpu, info);

        for (const auto &d : hdlrs->second) {
            if (d(vcpu, info)) {

                if (!info.ignore_write && !m_emulate[info.port_number]) {
                    emulate_out(info);
                }

                if (!info.ignore_advance) {
                    return vcpu->advance();
                }

                return true;
            }
        }
    }

    if (m_default_handler) {
        bfdebug_nhex(0, "handle_out", info.port_number);
        return m_default_handler(vcpu);
    }

    return false;
}

void
io_instruction_handler::emulate_in(info_t &info)
{
    namespace io_instruction = vmcs_n::exit_qualification::io_instruction;

    switch (info.size_of_access) {
        case io_instruction::size_of_access::one_byte:
            info.val = ::x64::portio::inb(gsl::narrow_cast<uint16_t>(info.port_number));
            break;

        case io_instruction::size_of_access::two_byte:
            info.val = ::x64::portio::inw(gsl::narrow_cast<uint16_t>(info.port_number));
            break;

        default:
            info.val = ::x64::portio::ind(gsl::narrow_cast<uint16_t>(info.port_number));
            break;
    }
}

void
io_instruction_handler::emulate_out(info_t &info)
{
    namespace io_instruction = vmcs_n::exit_qualification::io_instruction;

    switch (info.size_of_access) {
        case io_instruction::size_of_access::one_byte:
            ::x64::portio::outb(
                gsl::narrow_cast<uint16_t>(info.port_number),
                gsl::narrow_cast<uint8_t>(info.val)
            );
            break;

        case io_instruction::size_of_access::two_byte:
            ::x64::portio::outw(
                gsl::narrow_cast<uint16_t>(info.port_number),
                gsl::narrow_cast<uint16_t>(info.val)
            );
            break;

        default:
            ::x64::portio::outd(
                gsl::narrow_cast<uint16_t>(info.port_number),
                gsl::narrow_cast<uint32_t>(info.val)
            );
            break;
    }
}

void
io_instruction_handler::load_operand(
    vcpu *vcpu, info_t &info)
{
    namespace io_instruction = vmcs_n::exit_qualification::io_instruction;

    if (info.address != 0ULL) {
        switch (info.size_of_access) {
            case io_instruction::size_of_access::one_byte: {
                auto map =
                    m_vcpu->map_gva_4k<uint8_t>(
                        info.address,
                        info.size_of_access
                    );

                info.val = map.get()[0] & 0x00000000000000FFULL;
                break;
            }

            case io_instruction::size_of_access::two_byte: {
                auto map =
                    m_vcpu->map_gva_4k<uint16_t>(
                        info.address,
                        info.size_of_access
                    );

                info.val = map.get()[0] & 0x000000000000FFFFULL;
                break;
            }

            default: {
                auto map =
                    m_vcpu->map_gva_4k<uint32_t>(
                        info.address,
                        info.size_of_access
                    );

                info.val = map.get()[0] & 0x00000000FFFFFFFFULL;
                break;
            }
        }
    }
    else {
        switch (info.size_of_access) {
            case io_instruction::size_of_access::one_byte:
                info.val = vcpu->rax() & 0x00000000000000FFULL;
                break;

            case io_instruction::size_of_access::two_byte:
                info.val = vcpu->rax() & 0x000000000000FFFFULL;
                break;

            default:
                info.val = vcpu->rax() & 0x00000000FFFFFFFFULL;
                break;
        }
    }
}

void
io_instruction_handler::store_operand(
    vcpu *vcpu, info_t &info)
{
    namespace io_instruction = vmcs_n::exit_qualification::io_instruction;

    if (info.address != 0ULL) {
        switch (info.size_of_access) {
            case io_instruction::size_of_access::one_byte: {
                auto map =
                    m_vcpu->map_gva_4k<uint8_t>(
                        info.address,
                        info.size_of_access
                    );

                map.get()[0] = gsl::narrow_cast<uint8_t>(info.val);
                break;
            }

            case io_instruction::size_of_access::two_byte: {
                auto map =
                    m_vcpu->map_gva_4k<uint16_t>(
                        info.address,
                        info.size_of_access
                    );

                map.get()[0] = gsl::narrow_cast<uint16_t>(info.val);
                break;
            }

            default: {
                auto map =
                    m_vcpu->map_gva_4k<uint32_t>(
                        info.address,
                        info.size_of_access
                    );

                map.get()[0] = gsl::narrow_cast<uint32_t>(info.val);
                break;
            }
        }
    }
    else {
        switch (info.size_of_access) {
            case io_instruction::size_of_access::one_byte:
                vcpu->set_rax(
                    set_bits(vcpu->rax(), 0x00000000000000FFULL, info.val)
                );

                break;

            case io_instruction::size_of_access::two_byte:
                vcpu->set_rax(
                    set_bits(vcpu->rax(), 0x000000000000FFFFULL, info.val)
                );

                break;

            default:
                vcpu->set_rax(
                    set_bits(vcpu->rax(), 0x00000000FFFFFFFFULL, info.val)
                );

                break;
        }
    }
}

}
