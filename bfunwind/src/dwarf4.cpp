//
// Bareflank Unwind Library
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

#include <log.h>
#include <abort.h>
#include <dwarf4.h>

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

template<typename T> T static get(char **p)
{ auto v = *(T *)(*p); (*p) += sizeof(T); return v;}

#define if_opcode(a,b) \
    if (opcode == a) \
    { \
        log("  %s: ", #a); \
        b \
        return; \
    }

// -----------------------------------------------------------------------------
// Call Frame Information (CFI) Register
// -----------------------------------------------------------------------------

class cfi_register
{
public:
    cfi_register() :
        m_index(0),
        m_rule(rule_undefined),
        m_value(0)
    {}

    cfi_register(uint64_t index, register_rules rule, uint64_t value) :
        m_index(index),
        m_rule(rule),
        m_value(value)
    {}

    uint64_t index() const
    { return m_index; }

    register_rules rule() const
    { return m_rule; }

    uint64_t value() const
    { return m_value; }

    void set_index(uint64_t index)
    { m_index = index; }

    void set_rule(register_rules rule)
    { m_rule = rule; }

    void set_value(uint64_t value)
    { m_value = value; }

private:
    uint64_t m_index;
    register_rules m_rule;
    uint64_t m_value;
};

// -----------------------------------------------------------------------------
// Call Frame Information (CFI) Canonical Frame Address (CFA)
// -----------------------------------------------------------------------------

class cfi_cfa
{
public:
    cfi_cfa() :
        m_reg_index(0),
        m_offset(0)
    {}

    cfi_cfa(uint64_t reg_index, int64_t offset) :
        m_reg_index(reg_index),
        m_offset(offset)
    {}

    uint64_t reg_index() const
    { return m_reg_index; }

    int64_t offset() const
    { return m_offset; }

    void set_reg_index(uint64_t reg_index)
    { m_reg_index = reg_index; }

    void set_offset(int64_t offset)
    { m_offset = offset; }

private:
    uint64_t m_reg_index;
    int64_t m_offset;
};

// -----------------------------------------------------------------------------
// Call Frame Information (CFI) Table Row
// -----------------------------------------------------------------------------

class cfi_table_row
{
public:
    cfi_table_row()
    {
        for (auto i = 0; i < MAX_NUM_REGISTERS; i++)
            m_registers[i].set_index(i);
    }

    const cfi_cfa &cfa() const
    { return m_cfa; }

    const cfi_register &reg(uint64_t index) const
    {
        if (index >= MAX_NUM_REGISTERS)
            ABORT("index out of bounds. increase MAX_NUM_REGISTERS");

        return m_registers[index];
    }

    void set_cfa(const cfi_cfa &cfa)
    { m_cfa = cfa; }

    void set_reg(const cfi_register &reg)
    {
        if (reg.index() >= MAX_NUM_REGISTERS)
            ABORT("index out of bounds. increase MAX_NUM_REGISTERS");

        m_registers[reg.index()] = reg;
    }

    void set_reg(uint64_t index, register_rules rule)
    {
        if (index >= MAX_NUM_REGISTERS)
            ABORT("index out of bounds. increase MAX_NUM_REGISTERS");

        m_registers[index].set_rule(rule);
    }

    void set_reg(uint64_t index, uint64_t value)
    {
        if (index >= MAX_NUM_REGISTERS)
            ABORT("index out of bounds. increase MAX_NUM_REGISTERS");

        m_registers[index].set_value(value);
    }

private:
    cfi_cfa m_cfa;
    cfi_register m_registers[MAX_NUM_REGISTERS];
};

// -----------------------------------------------------------------------------
// Unwind Helpers
// -----------------------------------------------------------------------------

static uint64_t
private_decode_cfa(const cfi_table_row &row, register_state *state)
{
    const auto &cfa = row.cfa();

    if (cfa.reg_index() != 0)
        return state->get(cfa.reg_index()) + cfa.offset();

    ABORT("malformed cfa");
    return 0;
}

static uint64_t
private_decode_reg(const cfi_register &reg, uint64_t cfa, register_state *state)
{
    uint64_t value;

    log("getting r%ld (%s) ", reg.index(), state->name(reg.index()));

    switch (reg.rule())
    {
        case rule_undefined:
            ABORT("unable to get register value for unused register");

        case rule_same_value:
            log("from r%ld\n", reg.index());
            value = state->get(reg.index());
            break;

        case rule_offsetn:
            log("from cfa(0x%08lx) + n(%ld)\n", cfa, (int64_t)reg.index());
            value = ((uint64_t *)(cfa + (int64_t)reg.value()))[0];
            break;

        case rule_val_offsetn:
            log("from val cfa(0x%08lx) + n(%ld)\n", cfa, (int64_t)reg.index());
            value = cfa + (int64_t)reg.value();
            break;

        case rule_register:
            log("from r%ld\n", reg.value());
            value = state->get(reg.value());
            break;

        case rule_expression:
            ABORT("DWARF4 expressions currently not supported");

        case rule_val_expression:
            ABORT("DWARF4 expressions currently not supported");

        default:
            ABORT("unknown rule. cfi table is malformed");
    }

    log("    - value: 0x%08lx\n", value);

    return value;
}

void
private_parse_instruction(cfi_table_row *row,
                          const ci_entry &cie,
                          char **p,
                          uint64_t *l1,
                          uint64_t *l2,
                          uint64_t pc_begin,
                          register_state *state)
{
    (void) pc_begin;
    (void) state;

    uint8_t opcode = *(uint8_t *)(*p) & 0xC0;
    uint8_t operand = *(uint8_t *)(*p) & 0x3F;

    if (opcode == 0)
        opcode = operand;

    (*p)++;

    if_opcode(DW_CFA_advance_loc,
    {
        auto loc = (uint64_t)operand * cie.code_alignment();
        if ((*l2 += loc) > *l1)
        {
            log("search complete\n");
            return;
        }
        log("%ld to 0x%lx\n", loc, pc_begin + *l2);
    })

    if_opcode(DW_CFA_offset,
    {
        auto value = (int64_t)dwarf4::decode_uleb128(p) * cie.data_alignment();
        row->set_reg(cfi_register(operand, rule_offsetn, value));
        log("r%d (%s) at cfa + n(%ld)\n", operand, state->name(operand), value);
    })

    if_opcode(DW_CFA_restore,
    {
        ABORT("register restoration currently not supported");
    })

    if_opcode(DW_CFA_nop,
    {
        log("\n");
    })

    if_opcode(DW_CFA_set_loc,
    {
        *l2 = decode_pointer(p, cie.pointer_encoding());
        if (*l2 > *l1)
        {
            log("search complete\n");
            return;
        }
        log("%ld to 0x%lx\n", *l2, pc_begin + *l2);
    })

    if_opcode(DW_CFA_advance_loc1,
    {
        auto loc = get<uint8_t>(p) * cie.code_alignment();
        if ((*l2 += loc) > *l1)
        {
            log("search complete\n");
            return;
        }
        log("%ld to 0x%lx\n", loc, pc_begin + *l2);
    })

    if_opcode(DW_CFA_advance_loc2,
    {
        auto loc = get<uint16_t>(p) * cie.code_alignment();
        if ((*l2 += loc) > *l1)
        {
            log("search complete\n");
            return;
        }
        log("%ld to 0x%lx\n", loc, pc_begin + *l2);
    })

    if_opcode(DW_CFA_advance_loc4,
    {
        auto loc = get<uint32_t>(p) * cie.code_alignment();
        if ((*l2 += loc) > *l1)
        {
            log("search complete\n");
            return;
        }
        log("%ld to 0x%lx\n", loc, pc_begin + *l2);
    })

    if_opcode(DW_CFA_offset_extended,
    {
        auto reg = dwarf4::decode_uleb128(p);
        auto value = (int64_t)dwarf4::decode_uleb128(p) * cie.data_alignment();
        row->set_reg(cfi_register(reg, rule_offsetn, value));
        log("r%ld (%s) at cfa + n(%ld)\n", reg, state->name(reg), value);
    })

    if_opcode(DW_CFA_restore_extended,
    {
        ABORT("register restoration currently not supported");
    })

    if_opcode(DW_CFA_undefined,
    {
        auto reg = dwarf4::decode_uleb128(p);
        row->set_reg(reg, rule_undefined);
        log("r%ld (%s)\n", reg, state->name(reg));
    })

    if_opcode(DW_CFA_same_value,
    {
        auto reg = dwarf4::decode_uleb128(p);
        row->set_reg(reg, rule_same_value);
        log("r%ld (%s)\n", reg, state->name(reg));
    })

    if_opcode(DW_CFA_register,
    {
        auto reg1 = dwarf4::decode_uleb128(p);
        auto reg2 = dwarf4::decode_uleb128(p);
        row->set_reg(reg1, row->reg(reg2).rule());
        log("r%ld (%s) to r%ld (%s)\n", reg2, state->name(reg2),
        reg1, state->name(reg1));
    })

    if_opcode(DW_CFA_remember_state,
    {
        ABORT("unsupported in .eh_frame. this should not happen");
    })

    if_opcode(DW_CFA_restore_state,
    {
        ABORT("unsupported in .eh_frame. this should not happen");
    })

    if_opcode(DW_CFA_def_cfa,
    {
        auto cfa = row->cfa();
        cfa.set_reg_index(dwarf4::decode_uleb128(p));
        cfa.set_offset(dwarf4::decode_uleb128(p));
        row->set_cfa(cfa);
        log("r%ld (%s) ofs %ld\n", cfa.reg_index(),
        state->name(cfa.reg_index()),
        cfa.offset());
    })

    if_opcode(DW_CFA_def_cfa_register,
    {
        auto cfa = row->cfa();
        cfa.set_reg_index(dwarf4::decode_uleb128(p));
        row->set_cfa(cfa);
        log("r%ld (%s)\n", cfa.reg_index(), state->name(cfa.reg_index()));
    })

    if_opcode(DW_CFA_def_cfa_offset,
    {
        auto cfa = row->cfa();
        cfa.set_offset(dwarf4::decode_uleb128(p));
        row->set_cfa(cfa);
        log("%ld\n", cfa.offset());
    })

    if_opcode(DW_CFA_def_cfa_expression,
    {
        ABORT("DWARF4 expressions currently not supported");
    })

    if_opcode(DW_CFA_expression,
    {
        ABORT("DWARF4 expressions currently not supported");
    })

    if_opcode(DW_CFA_offset_extended_sf,
    {
        auto reg = dwarf4::decode_uleb128(p);
        auto value = dwarf4::decode_sleb128(p) * cie.data_alignment();
        row->set_reg(cfi_register(reg, rule_offsetn, value));
        log("r%ld (%s) at cfa + n(%ld)\n", reg, state->name(reg), value);
    })

    if_opcode(DW_CFA_def_cfa_sf,
    {
        auto cfa = row->cfa();
        cfa.set_reg_index(dwarf4::decode_uleb128(p));
        cfa.set_offset(dwarf4::decode_sleb128(p) * cie.data_alignment());
        row->set_cfa(cfa);
        log("r%ld (%s) ofs %ld\n", cfa.reg_index(),
        state->name(cfa.reg_index()),
        cfa.offset());
    })

    if_opcode(DW_CFA_def_cfa_offset_sf,
    {
        auto cfa = row->cfa();
        cfa.set_offset(dwarf4::decode_sleb128(p) * cie.data_alignment());
        row->set_cfa(cfa);
        log("%ld\n", cfa.offset());
    })

    if_opcode(DW_CFA_val_offset,
    {
        auto reg = dwarf4::decode_uleb128(p);
        auto value = (int64_t)dwarf4::decode_uleb128(p) * cie.data_alignment();
        row->set_reg(cfi_register(reg, rule_val_offsetn, value));
        log("r%ld (%s) at cfa + n(%ld)\n", reg, state->name(reg), value);
    })

    if_opcode(DW_CFA_val_offset_sf,
    {
        auto reg = dwarf4::decode_uleb128(p);
        auto value = dwarf4::decode_sleb128(p) * cie.data_alignment();
        row->set_reg(cfi_register(reg, rule_val_offsetn, value));
        log("r%ld (%s) at cfa + n(%ld)\n", reg, state->name(reg), value);
    })

    if_opcode(DW_CFA_val_expression,
    {
        ABORT("DWARF4 expressions currently not supported");
    })

    if_opcode(DW_CFA_GNU_args_size,
    {
        ABORT("GNU extension DW_CFA_GNU_args_size is currently not supported");
    })

    if_opcode(DW_CFA_GNU_negative_offset_extended,
    {
        auto reg = dwarf4::decode_uleb128(p);
        auto value = (int64_t)dwarf4::decode_uleb128(p) * cie.data_alignment();
        row->set_reg(cfi_register(reg, rule_offsetn, -value));
        log("r%ld (%s) at cfa + n(%ld)\n", reg, state->name(reg), value);
    })

    ABORT("unknown cfi opcode");
}

static void
private_parse_instructions(cfi_table_row *row,
                           const ci_entry &cie,
                           const fd_entry &fde,
                           register_state *state,
                           bool is_cie)
{
    uint64_t pc_begin = is_cie ? 0 : fde.pc_begin();
    uint64_t l1 = is_cie ? 0ULL : state->get_ip() - fde.pc_begin();
    uint64_t l2 = 0ULL;

    char *p = is_cie ? cie.initial_instructions() : fde.instructions();
    char *end = is_cie ? cie.entry_end() : fde.entry_end();

    while (p < end && l1 >= l2)
        private_parse_instruction(row, cie, &p, &l1, &l2, pc_begin, state);
}

cfi_table_row
private_decode_cfi(const fd_entry &fde, register_state *state)
{
    auto row = cfi_table_row();
    const auto &cie = fde.cie();

#ifndef DISABLE_LOGGING
    auto eh_frame = fde.eh_frame();
    auto cie_offset1 = (uint64_t)cie.entry_start() - (uint64_t)eh_frame.addr;
    auto cie_size = (uint64_t)(cie.entry_end() - cie.entry_start());

    log("%08lx ", cie_offset1);
    log("%08lx ", cie_size);
    log("%08lx ", 0UL);
    log("CIE\n");
#endif

    private_parse_instructions(&row, cie, fde, state, true);
    log("\n");

#ifndef DISABLE_LOGGING
    auto fde_offset1 = (uint64_t)fde.entry_start() - (uint64_t)eh_frame.addr;
    auto fde_offset2 = (uint64_t)fde.payload_start() - (uint64_t)eh_frame.addr;
    auto fde_size = (uint64_t)(fde.entry_end() - fde.entry_start());
    auto pc_begin = fde.pc_begin();
    auto pc_end = fde.pc_begin() + fde.pc_range();

    log("%08lx ", fde_offset1);
    log("%08lx ", fde_size);
    log("%08lx ", fde_offset2);
    log("FDE ");
    log("cie=%08lx ", cie_offset1);
    log("pc=%08lx..%08lx", pc_begin, pc_end);
    log("\n");
#endif

    private_parse_instructions(&row, cie, fde, state, false);
    log("\n");

    return row;
}

// -----------------------------------------------------------------------------
// DWARF 4 Implementation
// -----------------------------------------------------------------------------

int64_t
dwarf4::decode_sleb128(char **addr)
{
    uint8_t byte = 0;
    int64_t shift = 0;
    int64_t result = 0;

    while (1)
    {
        byte = *((uint8_t *)(*addr)++);
        result |= ((byte & 0x7f) << shift);
        shift += 7;
        if ((byte & 0x80) == 0)
            break;
    }

    if ((byte & 0x40) != 0)
        result |= (-1LL) << shift;

    return result;
}

uint64_t
dwarf4::decode_uleb128(char **addr)
{
    uint8_t byte = 0;
    uint64_t shift = 0;
    uint64_t result = 0;

    while (1)
    {
        byte = *((uint8_t *)(*addr)++);
        result |= ((byte & 0x7f) << shift);
        shift += 7;
        if ((byte & 0x80) == 0)
            break;
    }

    return result;
}

void
dwarf4::unwind(const fd_entry &fde, register_state *state)
{
    log("-------------\n");
    log("- Unwinding -\n");
    log("-------------\n");
    log("\n");

    auto row = private_decode_cfi(fde, state);
    auto cfa = private_decode_cfa(row, state);

    for (auto i = 0U; i < state->max_num_registers(); i++)
    {
        auto reg = row.reg(i);

        if (reg.rule() == rule_undefined)
            continue;

        state->set(i, private_decode_reg(reg, cfa, state));
    }

    state->commit(cfa);
}
