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

// TIDY_EXCLUSION=-cppcoreguidelines-pro*
//
// Reason:
//     Although written in C++, this code needs to implement C specific logic
//     that by its very definition will not adhere to the core guidelines
//     similar to libc which is needed by all C++ implementations.
//

#include <log.h>
#include <misc.h>
#include <abort.h>
#include <dwarf4.h>
#include <eh_frame.h>

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

uint64_t
decode_pointer(char **addr, uint64_t encoding)
{
    uint64_t result = 0;

    if (encoding == DW_EH_PE_omit) {
        return 0;
    }

    // The following are defined in the DWARF Exception Header Encodings
    // section 10.5.1. For some reason, GCC adds a 0x80 to the upper 4 bits
    // that are not documented in the LSB. Thefore, only 3 of the upper 4 bits
    // are actually used.

    switch (encoding & 0x70) {
        case DW_EH_PE_absptr:
            break;

        case DW_EH_PE_pcrel:
            result += reinterpret_cast<uint64_t>(*addr);
            break;

        case DW_EH_PE_textrel:
            ABORT("DW_EH_PE_textrel pointer encodings not supported");
            break;

        case DW_EH_PE_datarel:
            ABORT("DW_EH_PE_datarel pointer encodings not supported");
            break;

        case DW_EH_PE_funcrel:
            ABORT("DW_EH_PE_funcrel pointer encodings not supported");
            break;

        case DW_EH_PE_aligned:
            ABORT("DW_EH_PE_aligned pointer encodings not supported");
            break;

        default:
            ABORT("unknown upper pointer encoding bits");
    }

    switch (encoding & 0x0F) {
        case DW_EH_PE_absptr:
            result += *reinterpret_cast<uintptr_t *>(*addr);
            *addr += sizeof(void *);
            break;

        case DW_EH_PE_uleb128:
            result += dwarf4::decode_uleb128(addr);
            break;

        case DW_EH_PE_udata2:
            result += *reinterpret_cast<uint16_t *>(*addr);
            *addr += sizeof(uint16_t);
            break;

        case DW_EH_PE_udata4:
            result += *reinterpret_cast<uint32_t *>(*addr);
            *addr += sizeof(uint32_t);
            break;

        case DW_EH_PE_udata8:
            result += *reinterpret_cast<uint64_t *>(*addr);
            *addr += sizeof(uint64_t);
            break;

        case DW_EH_PE_sleb128:
            result = add_offset(result, dwarf4::decode_sleb128(addr));
            break;

        case DW_EH_PE_sdata2:
            result = add_offset(result, *reinterpret_cast<int16_t *>(*addr));
            *addr += sizeof(int16_t);
            break;

        case DW_EH_PE_sdata4:
            result = add_offset(result, *reinterpret_cast<int32_t *>(*addr));
            *addr += sizeof(int32_t);
            break;

        case DW_EH_PE_sdata8:
            result = add_offset(result, *reinterpret_cast<int64_t *>(*addr));
            *addr += sizeof(int64_t);
            break;

        default:
            ABORT("unknown lower pointer encoding bits");
    }

    return result;
}

// -----------------------------------------------------------------------------
// CIE / FDE Common
// -----------------------------------------------------------------------------

common_entry::common_entry() :
    m_is_cie(false),
    m_entry_start(nullptr),
    m_entry_end(nullptr),
    m_payload_start(nullptr),
    m_payload_end(nullptr),
    m_eh_frame{nullptr, 0}
{
}

common_entry::common_entry(const eh_frame_t &eh_frame) :
    m_is_cie(false),
    m_entry_start(nullptr),
    m_entry_end(nullptr),
    m_payload_start(nullptr),
    m_payload_end(nullptr),
    m_eh_frame(eh_frame)
{
}

common_entry &common_entry::operator++()
{
    if (m_entry_start == nullptr) {
        return *this;
    }

    if (m_entry_end + 4 < reinterpret_cast<char *>(m_eh_frame.addr) + m_eh_frame.size) {
        parse(m_entry_end);
    }
    else {
        parse(nullptr);
    }

    return *this;
}

void
common_entry::non_virtual_parse(char *addr)
{
    auto len = 0ULL;

    if ((m_entry_start = addr) == nullptr) {
        goto failure;
    }

    if (m_entry_start < m_eh_frame.addr) {
        goto failure;
    }

    if (*reinterpret_cast<uint32_t *>(m_entry_start) != 0xFFFFFFFF) {
        len = *reinterpret_cast<uint32_t *>(m_entry_start + 0);
        m_payload_start = m_entry_start + 4;
    }
    else {
        len = *reinterpret_cast<uint64_t *>(m_entry_start + 4);
        m_payload_start = m_entry_start + 12;
    }

    if (len == 0) {
        goto failure;
    }

    m_payload_end = m_payload_start + len;
    m_entry_end = m_payload_end;

    if (m_entry_end > reinterpret_cast<char *>(m_eh_frame.addr) + m_eh_frame.size) {
        goto failure;
    }

    m_is_cie = (*reinterpret_cast<uint32_t *>(m_payload_start) == 0);
    return;

failure:

    m_is_cie = false;
    m_entry_start = nullptr;
    m_entry_end = nullptr;
    m_payload_start = nullptr;
    m_payload_end = nullptr;
}

// -----------------------------------------------------------------------------
// Common Information Entry Record (CIE)
// -----------------------------------------------------------------------------

ci_entry::ci_entry() :
    m_augmentation_string(nullptr),
    m_code_alignment(0),
    m_data_alignment(0),
    m_return_address_reg(0),
    m_pointer_encoding(0),
    m_lsda_encoding(0),
    m_personality_encoding(0),
    m_personality_function(0),
    m_initial_instructions(nullptr)
{
}

ci_entry::ci_entry(const eh_frame_t &eh_frame) :
    common_entry(eh_frame),

    m_augmentation_string(nullptr),
    m_code_alignment(0),
    m_data_alignment(0),
    m_return_address_reg(0),
    m_pointer_encoding(0),
    m_lsda_encoding(0),
    m_personality_encoding(0),
    m_personality_function(0),
    m_initial_instructions(nullptr)
{
    non_virtual_parse(reinterpret_cast<char *>(eh_frame.addr));
}

ci_entry::ci_entry(const eh_frame_t &eh_frame, void *addr) :
    common_entry(eh_frame),

    m_augmentation_string(nullptr),
    m_code_alignment(0),
    m_data_alignment(0),
    m_return_address_reg(0),
    m_pointer_encoding(0),
    m_lsda_encoding(0),
    m_personality_encoding(0),
    m_personality_function(0),
    m_initial_instructions(nullptr)
{
    non_virtual_parse(reinterpret_cast<char *>(addr));
}

void
ci_entry::parse(char *addr)
{
    non_virtual_parse(addr);
}

void
ci_entry::non_virtual_parse(char *addr)
{
    common_entry::non_virtual_parse(addr);

    if (!*this) {
        return;
    }

    if (!is_cie()) {
        return;
    }

    auto p = payload_start();

    p += sizeof(uint32_t);
    p += sizeof(uint8_t);

    m_augmentation_string = p;

    while (*p++ != 0)
    { }

    m_code_alignment = dwarf4::decode_uleb128(&p);
    m_data_alignment = dwarf4::decode_sleb128(&p);
    m_return_address_reg = dwarf4::decode_uleb128(&p);

    if (m_augmentation_string[0] == 'z') {
        auto len = dwarf4::decode_uleb128(&p);

        for (auto i = 1U; i <= len && m_augmentation_string[i] != 0; i++) {
            switch (m_augmentation_string[i]) {
                case 'L':
                    m_lsda_encoding = *reinterpret_cast<uint8_t *>(p++);
                    break;

                case 'P':
                    m_personality_encoding = *reinterpret_cast<uint8_t *>(p++);
                    m_personality_function =
                        decode_pointer(&p, m_personality_encoding);
                    break;

                case 'R':
                    m_pointer_encoding = *reinterpret_cast<uint8_t *>(p++);
                    break;

                default:
                    ABORT("unknown augmentation string character");
            }
        }
    }

    m_initial_instructions = p;
}

// -----------------------------------------------------------------------------
// Frame Description Entry Record (FDE)
// -----------------------------------------------------------------------------

fd_entry::fd_entry() :
    m_pc_begin(0),
    m_pc_range(0),
    m_lsda(0),
    m_instructions(nullptr)
{
}

fd_entry::fd_entry(const eh_frame_t &eh_frame) :
    common_entry(eh_frame),

    m_pc_begin(0),
    m_pc_range(0),
    m_lsda(0),
    m_instructions(nullptr)
{
    non_virtual_parse(reinterpret_cast<char *>(eh_frame.addr));
}

fd_entry::fd_entry(const eh_frame_t &eh_frame, void *addr) :
    common_entry(eh_frame),

    m_pc_begin(0),
    m_pc_range(0),
    m_lsda(0),
    m_instructions(nullptr)
{
    non_virtual_parse(reinterpret_cast<char *>(addr));
}

void
fd_entry::parse(char *addr)
{
    non_virtual_parse(addr);
}

void
fd_entry::non_virtual_parse(char *addr)
{
    common_entry::non_virtual_parse(addr);

    if (!*this) {
        return;
    }

    if (!is_fde()) {
        return;
    }

    auto p = payload_start();
    auto p_cie = reinterpret_cast<char *>(reinterpret_cast<uint64_t>(p) - *reinterpret_cast<uint32_t *>(p));

    m_cie = ci_entry(eh_frame(), p_cie);
    p += sizeof(uint32_t);

    m_pc_begin = decode_pointer(&p, m_cie.pointer_encoding());
    m_pc_range = decode_pointer(&p, m_cie.pointer_encoding() & 0xF);

    if (m_cie.augmentation_string(0) == 'z') {
        auto len = dwarf4::decode_uleb128(&p);

        for (auto i = 1U; m_cie.augmentation_string(i) != 0 && i <= len; i++) {
            switch (m_cie.augmentation_string(i)) {
                case 'L':
                    m_lsda = decode_pointer(&p, m_cie.lsda_encoding());
                    break;

                case 'P':
                    break;

                case 'R':
                    break;

                default:
                    ABORT("unknown augmentation string character");
            }
        }
    }

    m_instructions = p;
}

// -----------------------------------------------------------------------------
// Exception Handler Framework (eh_frame)
// -----------------------------------------------------------------------------

fd_entry
eh_frame::find_fde(register_state *state)
{
    auto eh_frame_list = get_eh_frame_list();

    for (auto m = 0U; m < MAX_NUM_MODULES; m++) {
        for (auto fde = fd_entry(eh_frame_list[m]); fde; ++fde) {
            if (fde.is_cie()) {
                continue;
            }

            if (fde.is_in_range(state->get_ip())) {
                return fde;
            }
        }
    }

    log("ERROR: An exception was thrown, but the unwinder was unable to "
        "locate a stack frame for RIP = %p. Possible reasons include\n",
        reinterpret_cast<void *>(state->get_ip()));
    log("  - Throwing from a destructor\n");
    log("  - Throwing from a function labeled noexcept\n");
    log("  - Bug in the unwinder\n");
    log("\n\nAborting!!!\n\n")

    state->dump();

    return fd_entry();
}
