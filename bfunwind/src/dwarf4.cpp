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

#define if_cfa(a,b) \
    if (opcode == a) \
    { \
        log("  %s: ", #a); \
        b \
        return; \
    }

#define if_opcode(a,b) \
    if (opcode == a) \
    { \
        log("    - %s: ", #a); \
        b \
        continue; \
    }

#define REMEMBER_STACK_SIZE 10
#define EXPRESSION_STACK_SIZE 100

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

    enum cfi_cfa_type
    {
        cfa_register = 1,
        cfa_expression = 2,
    };

public:
    cfi_cfa() :
        m_value(0),
        m_offset(0),
        m_type(cfa_register)
    {}

    uint64_t value() const
    { return m_value; }

    int64_t offset() const
    { return m_offset; }

    cfi_cfa_type type() const
    { return m_type; }

    void set_value(uint64_t value)
    { m_value = value; }

    void set_offset(int64_t offset)
    { m_offset = offset; }

    void set_type(cfi_cfa_type type)
    { m_type = type; }

private:
    uint64_t m_value;
    int64_t m_offset;
    cfi_cfa_type m_type;
};

// -----------------------------------------------------------------------------
// Call Frame Information (CFI) Table Row
// -----------------------------------------------------------------------------

class cfi_table_row
{
public:
    cfi_table_row() :
        m_arg_size(0)
    {
        for (auto i = 0; i < MAX_NUM_REGISTERS; i++)
            m_registers[i].set_index(i);
    }

    const cfi_cfa &cfa() const
    { return m_cfa; }

    uint64_t arg_size() const
    { return m_arg_size; }

    const cfi_register &reg(uint64_t index) const
    {
        if (index >= MAX_NUM_REGISTERS)
            ABORT("index out of bounds. increase MAX_NUM_REGISTERS");

        return m_registers[index];
    }

    void set_cfa(const cfi_cfa &cfa)
    { m_cfa = cfa; }

    void set_arg_size(uint64_t arg_size)
    { m_arg_size = arg_size; }

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
    uint64_t m_arg_size;
    cfi_register m_registers[MAX_NUM_REGISTERS];
};

// -----------------------------------------------------------------------------
// Unwind Helpers
// -----------------------------------------------------------------------------

// TODO: In the future, the stack should be implemented using a custom C++
//       class that guards [] to prevent the stack variable from being
//       accessed out of bounds

static uint64_t
private_parse_expression(char *p,
                         uint64_t initialStackValue,
                         register_state *state)
{
    uint64_t i = 0;
    uint64_t stack[EXPRESSION_STACK_SIZE];

    stack[i] = initialStackValue;

    char *end = p + dwarf4::decode_uleb128(&p);

    while (p <= end)
    {
        uint8_t opcode = *(uint8_t *)(p);
        p++;

        if (i >= EXPRESSION_STACK_SIZE - 1)
            ABORT("out of DWARF expression stack space");

        if_opcode(DW_OP_addr,
        {
            stack[++i] = *(uint64_t *)(p);
            p += sizeof(uint64_t);
            log("stack[%ld]: %p\n", i, (void *)stack[i]);
        })

        if_opcode(DW_OP_deref,
        {
            stack[i] = *(uint64_t *)(stack[i]);
            log("stack[%ld]: %p\n", i, (void *)stack[i]);
        })

        if_opcode(DW_OP_const1u,
        {
            stack[++i] = *(uint8_t *)(p);
            p += sizeof(uint8_t);
            log("stack[%ld]: %p\n", i, (void *)stack[i]);
        })

        if_opcode(DW_OP_const1s,
        {
            stack[++i] = *(int8_t *)(p);
            p += sizeof(int8_t);
            log("stack[%ld]: %p\n", i, (void *)stack[i]);
        })

        if_opcode(DW_OP_const2u,
        {
            stack[++i] = *(uint16_t *)(p);
            p += sizeof(uint16_t);
            log("stack[%ld]: %p\n", i, (void *)stack[i]);
        })

        if_opcode(DW_OP_const2s,
        {
            stack[++i] = *(int16_t *)(p);
            p += sizeof(int16_t);
            log("stack[%ld]: %p\n", i, (void *)stack[i]);
        })

        if_opcode(DW_OP_const4u,
        {
            stack[++i] = *(uint32_t *)(p);
            p += sizeof(uint32_t);
            log("stack[%ld]: %p\n", i, (void *)stack[i]);
        })

        if_opcode(DW_OP_const4s,
        {
            stack[++i] = *(int32_t *)(p);
            p += sizeof(int32_t);
            log("stack[%ld]: %p\n", i, (void *)stack[i]);
        })

        if_opcode(DW_OP_const8u,
        {
            stack[++i] = *(uint64_t *)(p);
            p += sizeof(uint64_t);
            log("stack[%ld]: %p\n", i, (void *)stack[i]);
        })

        if_opcode(DW_OP_const8s,
        {
            stack[++i] = *(int64_t *)(p);
            p += sizeof(int64_t);
            log("stack[%ld]: %p\n", i, (void *)stack[i]);
        })

        if_opcode(DW_OP_constu,
        {
            stack[++i] = dwarf4::decode_uleb128(&p);
            log("stack[%ld]: %p\n", i, (void *)stack[i]);
        })

        if_opcode(DW_OP_consts,
        {
            stack[++i] = dwarf4::decode_sleb128(&p);
            log("stack[%ld]: %p\n", i, (void *)stack[i]);
        })

        if_opcode(DW_OP_dup,
        {
            auto value = stack[i];
            stack[++i] = value;
            log("stack[%ld]: %p\n", i, (void *)stack[i]);
        })

        if_opcode(DW_OP_drop,
        {
            if (i == 0)
                ABORT("DW_OP_drop out-of-bounds");

            i--;
            log("\n");
        })

        if_opcode(DW_OP_over,
        {
            if (i == 0)
                ABORT("DW_OP_over out-of-bounds");

            auto value = stack[i - 1];
            stack[++i] = value;
            log("stack[%ld]: %p\n", i, (void *)stack[i]);
        })

        if_opcode(DW_OP_pick,
        {
            auto index = *(uint8_t *)(p);
            p += sizeof(uint8_t);

            if (index > i)
                ABORT("DW_OP_pick out-of-bounds");

            auto value = stack[i - index];
            stack[++i] = value;
            log("stack[%ld]: %p, index: %d\n", i, (void *)stack[i], index);
        })

        if_opcode(DW_OP_swap,
        {
            if (i == 0)
                ABORT("DW_OP_swap out-of-bounds");

            auto value = stack[i];
            stack[i] = stack[i - 1];
            stack[i - 1] = value;
            log("stack[%ld]: %p\n", i, (void *)stack[i]);
        })

        if_opcode(DW_OP_rot,
        {
            if (i <= 1)
                ABORT("DW_OP_swap out-of-bounds");

            auto value = stack[i];
            stack[i] = stack[i - 1];
            stack[i - 1] = stack[i - 2];
            stack[i - 2] = value;
            log("stack[%ld]: %p\n", i, (void *)stack[i]);
        })

        if_opcode(DW_OP_xderef,
        {
            if (i == 0)
                ABORT("DW_OP_xderef out-of-bounds");

            auto value = stack[i--];
            stack[i] = *(uint64_t *)value;
            log("stack[%ld]: %p\n", i, (void *)stack[i]);
        })

        if_opcode(DW_OP_abs,
        {
            auto value = (int64_t)stack[i];
            if (value < 0)
                stack[i] = (uint64_t) - value;
            log("stack[%ld]: %p\n", i, (void *)stack[i]);
        })

        if_opcode(DW_OP_and,
        {
            if (i == 0)
                ABORT("DW_OP_and out-of-bounds");

            auto value = stack[i--];
            stack[i] &= value;
            log("stack[%ld]: %p\n", i, (void *)stack[i]);
        })

        if_opcode(DW_OP_div,
        {
            ABORT("DW_OP_div not supported");
        })

        if_opcode(DW_OP_minus,
        {
            if (i == 0)
                ABORT("DW_OP_minus out-of-bounds");

            auto value = stack[i--];
            stack[i] -= value;
            log("stack[%ld]: %p\n", i, (void *)stack[i]);
        })

        if_opcode(DW_OP_mod,
        {
            ABORT("DW_OP_mod not supported");
        })

        if_opcode(DW_OP_mul,
        {
            if (i == 0)
                ABORT("DW_OP_minus out-of-bounds");

            auto value = stack[i--];
            stack[i] *= value;
            log("stack[%ld]: %p\n", i, (void *)stack[i]);
        })

        if_opcode(DW_OP_neg,
        {
            stack[i] = (uint64_t)(0 - (int64_t)stack[i]);
            log("stack[%ld]: %p\n", i, (void *)stack[i]);
        })

        if_opcode(DW_OP_not,
        {
            stack[i] = ~stack[i];
            log("stack[%ld]: %p\n", i, (void *)stack[i]);
        })

        if_opcode(DW_OP_or,
        {
            if (i == 0)
                ABORT("DW_OP_or out-of-bounds");

            auto value = stack[i--];
            stack[i] |= value;
            log("stack[%ld]: %p\n", i, (void *)stack[i]);
        })

        if_opcode(DW_OP_plus,
        {
            if (i == 0)
                ABORT("DW_OP_plus out-of-bounds");

            auto value = stack[i--];
            stack[i] += value;
            log("stack[%ld]: %p\n", i, (void *)stack[i]);
        })

        if_opcode(DW_OP_plus_uconst,
        {
            stack[i] += dwarf4::decode_uleb128(&p);
            log("stack[%ld]: %p\n", i, (void *)stack[i]);
        })

        if_opcode(DW_OP_shl,
        {
            if (i == 0)
                ABORT("DW_OP_shl out-of-bounds");

            auto value = stack[i--];
            stack[i] = stack[i] << value;
            log("stack[%ld]: %p\n", i, (void *)stack[i]);
        })

        if_opcode(DW_OP_shr,
        {
            if (i == 0)
                ABORT("DW_OP_shr out-of-bounds");

            auto value = stack[i--];
            stack[i] = stack[i] >> value;
            log("stack[%ld]: %p\n", i, (void *)stack[i]);
        })

        if_opcode(DW_OP_shra,
        {
            if (i == 0)
                ABORT("DW_OP_shra out-of-bounds");

            auto value1 = stack[i--];
            auto value2 = (int64_t)stack[i];
            stack[i] = (uint64_t)(value2 >> value1);
            log("stack[%ld]: %p\n", i, (void *)stack[i]);
        })

        if_opcode(DW_OP_xor,
        {
            if (i == 0)
                ABORT("DW_OP_xor out-of-bounds");

            auto value = stack[i--];
            stack[i] ^= value;
            log("stack[%ld]: %p\n", i, (void *)stack[i]);
        })

        if_opcode(DW_OP_skip,
        {
            int16_t value = *(int16_t *)p;
            p += 2;
            p += value;
            log("stack[%ld]: %p\n", i, (void *)stack[i]);
        })

        if_opcode(DW_OP_bra,
        {
            if (i == 0)
                ABORT("DW_OP_bra out-of-bounds");

            int16_t value = *(int16_t *)p;
            p += 2;
            if (stack[i--])
                p += value;
            log("stack[%ld]: %p\n", i, (void *)stack[i]);
        })

        if_opcode(DW_OP_eq,
        {
            if (i == 0)
                ABORT("DW_OP_eq out-of-bounds");

            auto value = stack[i--];
            stack[i] = (stack[i] == value);
            log("stack[%ld]: %p\n", i, (void *)stack[i]);
        })

        if_opcode(DW_OP_ge,
        {
            if (i == 0)
                ABORT("DW_OP_ge out-of-bounds");

            auto value = stack[i--];
            stack[i] = (stack[i] >= value);
            log("stack[%ld]: %p\n", i, (void *)stack[i]);
        })

        if_opcode(DW_OP_gt,
        {
            if (i == 0)
                ABORT("DW_OP_gt out-of-bounds");

            auto value = stack[i--];
            stack[i] = (stack[i] > value);
            log("stack[%ld]: %p\n", i, (void *)stack[i]);
        })

        if_opcode(DW_OP_le,
        {
            if (i == 0)
                ABORT("DW_OP_le out-of-bounds");

            auto value = stack[i--];
            stack[i] = (stack[i] <= value);
            log("stack[%ld]: %p\n", i, (void *)stack[i]);
        })

        if_opcode(DW_OP_lt,
        {
            if (i == 0)
                ABORT("DW_OP_lt out-of-bounds");

            auto value = stack[i--];
            stack[i] = (stack[i] < value);
            log("stack[%ld]: %p\n", i, (void *)stack[i]);
        })

        if_opcode(DW_OP_ne,
        {
            if (i == 0)
                ABORT("DW_OP_ne out-of-bounds");

            auto value = stack[i--];
            stack[i] = (stack[i] != value);
            log("stack[%ld]: %p\n", i, (void *)stack[i]);
        })

        if_opcode(DW_OP_lit0,
        {
            stack[++i] = 0;
            log("stack[%ld]: %p\n", i, (void *)stack[i]);
        })

        if_opcode(DW_OP_lit1,
        {
            stack[++i] = 1;
            log("stack[%ld]: %p\n", i, (void *)stack[i]);
        })

        if_opcode(DW_OP_lit2,
        {
            stack[++i] = 2;
            log("stack[%ld]: %p\n", i, (void *)stack[i]);
        })

        if_opcode(DW_OP_lit3,
        {
            stack[++i] = 3;
            log("stack[%ld]: %p\n", i, (void *)stack[i]);
        })

        if_opcode(DW_OP_lit4,
        {
            stack[++i] = 4;
            log("stack[%ld]: %p\n", i, (void *)stack[i]);
        })

        if_opcode(DW_OP_lit5,
        {
            stack[++i] = 5;
            log("stack[%ld]: %p\n", i, (void *)stack[i]);
        })

        if_opcode(DW_OP_lit6,
        {
            stack[++i] = 6;
            log("stack[%ld]: %p\n", i, (void *)stack[i]);
        })

        if_opcode(DW_OP_lit7,
        {
            stack[++i] = 7;
            log("stack[%ld]: %p\n", i, (void *)stack[i]);
        })

        if_opcode(DW_OP_lit8,
        {
            stack[++i] = 8;
            log("stack[%ld]: %p\n", i, (void *)stack[i]);
        })

        if_opcode(DW_OP_lit9,
        {
            stack[++i] = 9;
            log("stack[%ld]: %p\n", i, (void *)stack[i]);
        })

        if_opcode(DW_OP_lit10,
        {
            stack[++i] = 10;
            log("stack[%ld]: %p\n", i, (void *)stack[i]);
        })

        if_opcode(DW_OP_lit11,
        {
            stack[++i] = 11;
            log("stack[%ld]: %p\n", i, (void *)stack[i]);
        })

        if_opcode(DW_OP_lit12,
        {
            stack[++i] = 12;
            log("stack[%ld]: %p\n", i, (void *)stack[i]);
        })

        if_opcode(DW_OP_lit13,
        {
            stack[++i] = 13;
            log("stack[%ld]: %p\n", i, (void *)stack[i]);
        })

        if_opcode(DW_OP_lit14,
        {
            stack[++i] = 14;
            log("stack[%ld]: %p\n", i, (void *)stack[i]);
        })

        if_opcode(DW_OP_lit15,
        {
            stack[++i] = 15;
            log("stack[%ld]: %p\n", i, (void *)stack[i]);
        })

        if_opcode(DW_OP_lit16,
        {
            stack[++i] = 16;
            log("stack[%ld]: %p\n", i, (void *)stack[i]);
        })

        if_opcode(DW_OP_lit17,
        {
            stack[++i] = 17;
            log("stack[%ld]: %p\n", i, (void *)stack[i]);
        })

        if_opcode(DW_OP_lit18,
        {
            stack[++i] = 18;
            log("stack[%ld]: %p\n", i, (void *)stack[i]);
        })

        if_opcode(DW_OP_lit19,
        {
            stack[++i] = 19;
            log("stack[%ld]: %p\n", i, (void *)stack[i]);
        })

        if_opcode(DW_OP_lit20,
        {
            stack[++i] = 20;
            log("stack[%ld]: %p\n", i, (void *)stack[i]);
        })

        if_opcode(DW_OP_lit21,
        {
            stack[++i] = 21;
            log("stack[%ld]: %p\n", i, (void *)stack[i]);
        })

        if_opcode(DW_OP_lit22,
        {
            stack[++i] = 22;
            log("stack[%ld]: %p\n", i, (void *)stack[i]);
        })

        if_opcode(DW_OP_lit23,
        {
            stack[++i] = 23;
            log("stack[%ld]: %p\n", i, (void *)stack[i]);
        })

        if_opcode(DW_OP_lit24,
        {
            stack[++i] = 24;
            log("stack[%ld]: %p\n", i, (void *)stack[i]);
        })

        if_opcode(DW_OP_lit25,
        {
            stack[++i] = 25;
            log("stack[%ld]: %p\n", i, (void *)stack[i]);
        })

        if_opcode(DW_OP_lit26,
        {
            stack[++i] = 26;
            log("stack[%ld]: %p\n", i, (void *)stack[i]);
        })

        if_opcode(DW_OP_lit27,
        {
            stack[++i] = 27;
            log("stack[%ld]: %p\n", i, (void *)stack[i]);
        })

        if_opcode(DW_OP_lit28,
        {
            stack[++i] = 28;
            log("stack[%ld]: %p\n", i, (void *)stack[i]);
        })

        if_opcode(DW_OP_lit29,
        {
            stack[++i] = 29;
            log("stack[%ld]: %p\n", i, (void *)stack[i]);
        })

        if_opcode(DW_OP_lit30,
        {
            stack[++i] = 30;
            log("stack[%ld]: %p\n", i, (void *)stack[i]);
        })

        if_opcode(DW_OP_lit31,
        {
            stack[++i] = 31;
            log("stack[%ld]: %p\n", i, (void *)stack[i]);
        })

        if_opcode(DW_OP_reg0,
        {
            stack[++i] = state->get(0);
            log("stack[%ld]: %p\n", i, (void *)stack[i]);
        })

        if_opcode(DW_OP_reg1,
        {
            stack[++i] = state->get(1);
            log("stack[%ld]: %p\n", i, (void *)stack[i]);
        })

        if_opcode(DW_OP_reg2,
        {
            stack[++i] = state->get(2);
            log("stack[%ld]: %p\n", i, (void *)stack[i]);
        })

        if_opcode(DW_OP_reg3,
        {
            stack[++i] = state->get(3);
            log("stack[%ld]: %p\n", i, (void *)stack[i]);
        })

        if_opcode(DW_OP_reg4,
        {
            stack[++i] = state->get(4);
            log("stack[%ld]: %p\n", i, (void *)stack[i]);
        })

        if_opcode(DW_OP_reg5,
        {
            stack[++i] = state->get(5);
            log("stack[%ld]: %p\n", i, (void *)stack[i]);
        })

        if_opcode(DW_OP_reg6,
        {
            stack[++i] = state->get(6);
            log("stack[%ld]: %p\n", i, (void *)stack[i]);
        })

        if_opcode(DW_OP_reg7,
        {
            stack[++i] = state->get(7);
            log("stack[%ld]: %p\n", i, (void *)stack[i]);
        })

        if_opcode(DW_OP_reg8,
        {
            stack[++i] = state->get(8);
            log("stack[%ld]: %p\n", i, (void *)stack[i]);
        })

        if_opcode(DW_OP_reg9,
        {
            stack[++i] = state->get(9);
            log("stack[%ld]: %p\n", i, (void *)stack[i]);
        })

        if_opcode(DW_OP_reg10,
        {
            stack[++i] = state->get(10);
            log("stack[%ld]: %p\n", i, (void *)stack[i]);
        })

        if_opcode(DW_OP_reg11,
        {
            stack[++i] = state->get(11);
            log("stack[%ld]: %p\n", i, (void *)stack[i]);
        })

        if_opcode(DW_OP_reg12,
        {
            stack[++i] = state->get(12);
            log("stack[%ld]: %p\n", i, (void *)stack[i]);
        })

        if_opcode(DW_OP_reg13,
        {
            stack[++i] = state->get(13);
            log("stack[%ld]: %p\n", i, (void *)stack[i]);
        })

        if_opcode(DW_OP_reg14,
        {
            stack[++i] = state->get(14);
            log("stack[%ld]: %p\n", i, (void *)stack[i]);
        })

        if_opcode(DW_OP_reg15,
        {
            stack[++i] = state->get(15);
            log("stack[%ld]: %p\n", i, (void *)stack[i]);
        })

        if_opcode(DW_OP_reg16,
        {
            stack[++i] = state->get(16);
            log("stack[%ld]: %p\n", i, (void *)stack[i]);
        })

        if_opcode(DW_OP_reg17,
        {
            stack[++i] = state->get(17);
            log("stack[%ld]: %p\n", i, (void *)stack[i]);
        })

        if_opcode(DW_OP_reg18,
        {
            stack[++i] = state->get(18);
            log("stack[%ld]: %p\n", i, (void *)stack[i]);
        })

        if_opcode(DW_OP_reg19,
        {
            stack[++i] = state->get(19);
            log("stack[%ld]: %p\n", i, (void *)stack[i]);
        })

        if_opcode(DW_OP_reg20,
        {
            stack[++i] = state->get(20);
            log("stack[%ld]: %p\n", i, (void *)stack[i]);
        })

        if_opcode(DW_OP_reg21,
        {
            stack[++i] = state->get(21);
            log("stack[%ld]: %p\n", i, (void *)stack[i]);
        })

        if_opcode(DW_OP_reg22,
        {
            stack[++i] = state->get(22);
            log("stack[%ld]: %p\n", i, (void *)stack[i]);
        })

        if_opcode(DW_OP_reg23,
        {
            stack[++i] = state->get(23);
            log("stack[%ld]: %p\n", i, (void *)stack[i]);
        })

        if_opcode(DW_OP_reg24,
        {
            stack[++i] = state->get(24);
            log("stack[%ld]: %p\n", i, (void *)stack[i]);
        })

        if_opcode(DW_OP_reg25,
        {
            stack[++i] = state->get(25);
            log("stack[%ld]: %p\n", i, (void *)stack[i]);
        })

        if_opcode(DW_OP_reg26,
        {
            stack[++i] = state->get(26);
            log("stack[%ld]: %p\n", i, (void *)stack[i]);
        })

        if_opcode(DW_OP_reg27,
        {
            stack[++i] = state->get(27);
            log("stack[%ld]: %p\n", i, (void *)stack[i]);
        })

        if_opcode(DW_OP_reg28,
        {
            stack[++i] = state->get(28);
            log("stack[%ld]: %p\n", i, (void *)stack[i]);
        })

        if_opcode(DW_OP_reg29,
        {
            stack[++i] = state->get(29);
            log("stack[%ld]: %p\n", i, (void *)stack[i]);
        })

        if_opcode(DW_OP_reg30,
        {
            stack[++i] = state->get(30);
            log("stack[%ld]: %p\n", i, (void *)stack[i]);
        })

        if_opcode(DW_OP_reg31,
        {
            stack[++i] = state->get(31);
            log("stack[%ld]: %p\n", i, (void *)stack[i]);
        })

        if_opcode(DW_OP_breg0,
        {
            auto reg = state->get(0);
            auto offset = dwarf4::decode_sleb128(&p);

            stack[++i] = reg + offset;

            log("r%d (%s) %p, offset: %ld\n", 0, state->name(0), (void *)reg,
            offset);
        })

        if_opcode(DW_OP_breg1,
        {
            auto reg = state->get(1);
            auto offset = dwarf4::decode_sleb128(&p);

            stack[++i] = reg + offset;

            log("r%d (%s) %p, offset: %ld\n", 1, state->name(1), (void *)reg,
            offset);
        })

        if_opcode(DW_OP_breg2,
        {
            auto reg = state->get(2);
            auto offset = dwarf4::decode_sleb128(&p);

            stack[++i] = reg + offset;

            log("r%d (%s) %p, offset: %ld\n", 2, state->name(2), (void *)reg,
            offset);
        })

        if_opcode(DW_OP_breg3,
        {
            auto reg = state->get(3);
            auto offset = dwarf4::decode_sleb128(&p);

            stack[++i] = reg + offset;

            log("r%d (%s) %p, offset: %ld\n", 3, state->name(3), (void *)reg,
            offset);
        })

        if_opcode(DW_OP_breg4,
        {
            auto reg = state->get(4);
            auto offset = dwarf4::decode_sleb128(&p);

            stack[++i] = reg + offset;

            log("r%d (%s) %p, offset: %ld\n", 4, state->name(4), (void *)reg,
            offset);
        })

        if_opcode(DW_OP_breg5,
        {
            auto reg = state->get(5);
            auto offset = dwarf4::decode_sleb128(&p);

            stack[++i] = reg + offset;

            log("r%d (%s) %p, offset: %ld\n", 5, state->name(5), (void *)reg,
            offset);
        })

        if_opcode(DW_OP_breg6,
        {
            auto reg = state->get(6);
            auto offset = dwarf4::decode_sleb128(&p);

            stack[++i] = reg + offset;

            log("r%d (%s) %p, offset: %ld\n", 6, state->name(6), (void *)reg,
            offset);
        })

        if_opcode(DW_OP_breg7,
        {
            auto reg = state->get(7);
            auto offset = dwarf4::decode_sleb128(&p);

            stack[++i] = reg + offset;

            log("r%d (%s) %p, offset: %ld\n", 7, state->name(7), (void *)reg,
            offset);
        })

        if_opcode(DW_OP_breg8,
        {
            auto reg = state->get(8);
            auto offset = dwarf4::decode_sleb128(&p);

            stack[++i] = reg + offset;

            log("r%d (%s) %p, offset: %ld\n", 8, state->name(8), (void *)reg,
            offset);
        })

        if_opcode(DW_OP_breg9,
        {
            auto reg = state->get(9);
            auto offset = dwarf4::decode_sleb128(&p);

            stack[++i] = reg + offset;

            log("r%d (%s) %p, offset: %ld\n", 9, state->name(9), (void *)reg,
            offset);
        })

        if_opcode(DW_OP_breg10,
        {
            auto reg = state->get(10);
            auto offset = dwarf4::decode_sleb128(&p);

            stack[++i] = reg + offset;

            log("r%d (%s) %p, offset: %ld\n", 10, state->name(10), (void *)reg,
            offset);
        })

        if_opcode(DW_OP_breg11,
        {
            auto reg = state->get(11);
            auto offset = dwarf4::decode_sleb128(&p);

            stack[++i] = reg + offset;

            log("r%d (%s) %p, offset: %ld\n", 11, state->name(11), (void *)reg,
            offset);
        })

        if_opcode(DW_OP_breg12,
        {
            auto reg = state->get(12);
            auto offset = dwarf4::decode_sleb128(&p);

            stack[++i] = reg + offset;

            log("r%d (%s) %p, offset: %ld\n", 12, state->name(12), (void *)reg,
            offset);
        })

        if_opcode(DW_OP_breg13,
        {
            auto reg = state->get(13);
            auto offset = dwarf4::decode_sleb128(&p);

            stack[++i] = reg + offset;

            log("r%d (%s) %p, offset: %ld\n", 13, state->name(13), (void *)reg,
            offset);
        })

        if_opcode(DW_OP_breg14,
        {
            auto reg = state->get(14);
            auto offset = dwarf4::decode_sleb128(&p);

            stack[++i] = reg + offset;

            log("r%d (%s) %p, offset: %ld\n", 14, state->name(14), (void *)reg,
            offset);
        })

        if_opcode(DW_OP_breg15,
        {
            auto reg = state->get(15);
            auto offset = dwarf4::decode_sleb128(&p);

            stack[++i] = reg + offset;

            log("r%d (%s) %p, offset: %ld\n", 15, state->name(15), (void *)reg,
            offset);
        })

        if_opcode(DW_OP_breg16,
        {
            auto reg = state->get(16);
            auto offset = dwarf4::decode_sleb128(&p);

            stack[++i] = reg + offset;

            log("r%d (%s) %p, offset: %ld\n", 16, state->name(16), (void *)reg,
            offset);
        })

        if_opcode(DW_OP_breg17,
        {
            auto reg = state->get(17);
            auto offset = dwarf4::decode_sleb128(&p);

            stack[++i] = reg + offset;

            log("r%d (%s) %p, offset: %ld\n", 17, state->name(17), (void *)reg,
            offset);
        })

        if_opcode(DW_OP_breg18,
        {
            auto reg = state->get(18);
            auto offset = dwarf4::decode_sleb128(&p);

            stack[++i] = reg + offset;

            log("r%d (%s) %p, offset: %ld\n", 18, state->name(18), (void *)reg,
            offset);
        })

        if_opcode(DW_OP_breg19,
        {
            auto reg = state->get(19);
            auto offset = dwarf4::decode_sleb128(&p);

            stack[++i] = reg + offset;

            log("r%d (%s) %p, offset: %ld\n", 19, state->name(19), (void *)reg,
            offset);
        })

        if_opcode(DW_OP_breg20,
        {
            auto reg = state->get(20);
            auto offset = dwarf4::decode_sleb128(&p);

            stack[++i] = reg + offset;

            log("r%d (%s) %p, offset: %ld\n", 20, state->name(20), (void *)reg,
            offset);
        })

        if_opcode(DW_OP_breg21,
        {
            auto reg = state->get(21);
            auto offset = dwarf4::decode_sleb128(&p);

            stack[++i] = reg + offset;

            log("r%d (%s) %p, offset: %ld\n", 21, state->name(21), (void *)reg,
            offset);
        })

        if_opcode(DW_OP_breg22,
        {
            auto reg = state->get(22);
            auto offset = dwarf4::decode_sleb128(&p);

            stack[++i] = reg + offset;

            log("r%d (%s) %p, offset: %ld\n", 22, state->name(22), (void *)reg,
            offset);
        })

        if_opcode(DW_OP_breg23,
        {
            auto reg = state->get(23);
            auto offset = dwarf4::decode_sleb128(&p);

            stack[++i] = reg + offset;

            log("r%d (%s) %p, offset: %ld\n", 23, state->name(23), (void *)reg,
            offset);
        })

        if_opcode(DW_OP_breg24,
        {
            auto reg = state->get(24);
            auto offset = dwarf4::decode_sleb128(&p);

            stack[++i] = reg + offset;

            log("r%d (%s) %p, offset: %ld\n", 24, state->name(24), (void *)reg,
            offset);
        })

        if_opcode(DW_OP_breg25,
        {
            auto reg = state->get(25);
            auto offset = dwarf4::decode_sleb128(&p);

            stack[++i] = reg + offset;

            log("r%d (%s) %p, offset: %ld\n", 25, state->name(25), (void *)reg,
            offset);
        })

        if_opcode(DW_OP_breg26,
        {
            auto reg = state->get(26);
            auto offset = dwarf4::decode_sleb128(&p);

            stack[++i] = reg + offset;

            log("r%d (%s) %p, offset: %ld\n", 26, state->name(26), (void *)reg,
            offset);
        })

        if_opcode(DW_OP_breg27,
        {
            auto reg = state->get(27);
            auto offset = dwarf4::decode_sleb128(&p);

            stack[++i] = reg + offset;

            log("r%d (%s) %p, offset: %ld\n", 27, state->name(27), (void *)reg,
            offset);
        })

        if_opcode(DW_OP_breg28,
        {
            auto reg = state->get(28);
            auto offset = dwarf4::decode_sleb128(&p);

            stack[++i] = reg + offset;

            log("r%d (%s) %p, offset: %ld\n", 28, state->name(28), (void *)reg,
            offset);
        })

        if_opcode(DW_OP_breg29,
        {
            auto reg = state->get(29);
            auto offset = dwarf4::decode_sleb128(&p);

            stack[++i] = reg + offset;

            log("r%d (%s) %p, offset: %ld\n", 29, state->name(29), (void *)reg,
            offset);
        })

        if_opcode(DW_OP_breg30,
        {
            auto reg = state->get(30);
            auto offset = dwarf4::decode_sleb128(&p);

            stack[++i] = reg + offset;

            log("r%d (%s) %p, offset: %ld\n", 30, state->name(30), (void *)reg,
            offset);
        })

        if_opcode(DW_OP_breg31,
        {
            auto reg = state->get(31);
            auto offset = dwarf4::decode_sleb128(&p);

            stack[++i] = reg + offset;

            log("r%d (%s) %p, offset: %ld\n", 31, state->name(31), (void *)reg,
            offset);
        })

        if_opcode(DW_OP_regx,
        {
            stack[++i] = state->get(dwarf4::decode_uleb128(&p));
            log("stack[%ld]: %p\n", i, (void *)stack[i]);
        })

        if_opcode(DW_OP_fbreg,
        {
            ABORT("DW_OP_fbreg not supported");
        })

        if_opcode(DW_OP_bregx,
        {
            stack[++i] = state->get(dwarf4::decode_uleb128(&p));
            stack[i] += dwarf4::decode_sleb128(&p);
            log("stack[%ld]: %p\n", i, (void *)stack[i]);
        })

        if_opcode(DW_OP_piece,
        {
            ABORT("DW_OP_piece not supported");
        })

        if_opcode(DW_OP_deref_size,
        {
            switch (*(uint8_t *)p++)
            {
                case 1:
                    stack[i] = *(uint8_t *)stack[i];
                    break;

                case 2:
                    stack[i] = *(uint16_t *)stack[i];
                    break;

                case 4:
                    stack[i] = *(uint32_t *)stack[i];
                    break;

                case 8:
                    stack[i] = *(uint64_t *)stack[i];
                    break;

                default:
                    ABORT("DW_OP_deref_size: invalid size");
            }
            log("stack[%ld]: %p\n", i, (void *)stack[i]);
        })

        if_opcode(DW_OP_xderef_size,
        {
            ABORT("DW_OP_xderef_size not supported");
        })

        if_opcode(DW_OP_nop,
        {
            ABORT("DW_OP_nop not supported");
        })

        if_opcode(DW_OP_push_object_addres,
        {
            ABORT("DW_OP_push_object_addres not supported");
        })

        if_opcode(DW_OP_call2,
        {
            ABORT("DW_OP_call2 not supported");
        })

        if_opcode(DW_OP_call4,
        {
            ABORT("DW_OP_call4 not supported");
        })

        if_opcode(DW_OP_call_ref,
        {
            ABORT("DW_OP_call_ref not supported");
        })

        if_opcode(DW_OP_form_tls_address,
        {
            ABORT("DW_OP_form_tls_address not supported");
        })

        if_opcode(DW_OP_call_frame_cfa,
        {
            ABORT("DW_OP_call_frame_cfa not supported");
        })

        if_opcode(DW_OP_bit_piece,
        {
            ABORT("DW_OP_bit_piece not supported");
        })

        if_opcode(DW_OP_implicit_value,
        {
            ABORT("DW_OP_implicit_value not supported");
        })

        if_opcode(DW_OP_stack_value,
        {
            ABORT("DW_OP_stack_value not supported");
        })

        if_opcode(DW_OP_lo_user,
        {
            ABORT("DW_OP_lo_user not supported");
        })

        if_opcode(DW_OP_hi_user,
        {
            ABORT("DW_OP_hi_user not supported");
        })

        ABORT("unknown cfi opcode");
    }

    return stack[i];
}

static uint64_t
private_decode_cfa(const cfi_table_row &row, register_state *state)
{
    uint64_t value = 0;
    const auto &cfa = row.cfa();

    log("getting cfa ");

    switch (cfa.type())
    {
        case cfi_cfa::cfa_register:
            log("cfa_register\n");
            value = state->get(cfa.value()) + cfa.offset();
            break;

        case cfi_cfa::cfa_expression:
            log("cfa_expression\n");
            value = private_parse_expression((char *)cfa.value(), 0, state);
            break;
    }

    log("    - value: 0x%08lx\n", value);

    return value;
}

static uint64_t
private_decode_reg(const cfi_register &reg, uint64_t cfa, register_state *state)
{
    uint64_t value = 0;

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
            log("from cfa(0x%08lx) + n(%ld)\n", cfa, (int64_t)reg.value());
            value = ((uint64_t *)(cfa + (int64_t)reg.value()))[0];
            break;

        case rule_val_offsetn:
            log("from val cfa(0x%08lx) + n(%ld)\n", cfa, (int64_t)reg.value());
            value = cfa + (int64_t)reg.value();
            break;

        case rule_register:
            log("from r%ld\n", reg.value());
            value = state->get(reg.value());
            break;

        case rule_expression:
            log("rule_expression\n");
            value = *(uint64_t *)private_parse_expression((char *)reg.value(), cfa, state);
            break;

        case rule_val_expression:
            log("rule_val_expression\n");
            value = private_parse_expression((char *)reg.value(), cfa, state);
            break;

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
                          register_state *state,
                          uint64_t &rememberIndex,
                          cfi_table_row *rememberStack,
                          cfi_table_row *initialRow)
{
    (void) pc_begin;
    (void) state;

    uint8_t opcode = *(uint8_t *)(*p) & 0xC0;
    uint8_t operand = *(uint8_t *)(*p) & 0x3F;

    if (opcode == 0)
        opcode = operand;

    (*p)++;

    if_cfa(DW_CFA_advance_loc,
    {
        auto loc = (uint64_t)operand * cie.code_alignment();
        if ((*l2 += loc) > *l1)
        {
            log("search complete\n");
            return;
        }
        log("%ld to 0x%lx\n", loc, pc_begin + *l2);
    })

    if_cfa(DW_CFA_offset,
    {
        auto value = (int64_t)dwarf4::decode_uleb128(p) * cie.data_alignment();
        row->set_reg(cfi_register(operand, rule_offsetn, value));
        log("r%d (%s) at cfa + n(%ld)\n", operand, state->name(operand), value);
    })

    if_cfa(DW_CFA_restore,
    {
        row->set_reg(initialRow->reg(operand));
        log("r%d (%s)\n", operand, state->name(operand));
    })

    if_cfa(DW_CFA_nop,
    {
        log("\n");
    })

    if_cfa(DW_CFA_set_loc,
    {
        *l2 = decode_pointer(p, cie.pointer_encoding());
        if (*l2 > *l1)
        {
            log("search complete\n");
            return;
        }
        log("%ld to 0x%lx\n", *l2, pc_begin + *l2);
    })

    if_cfa(DW_CFA_advance_loc1,
    {
        auto loc = get<uint8_t>(p) * cie.code_alignment();
        if ((*l2 += loc) > *l1)
        {
            log("search complete\n");
            return;
        }
        log("%ld to 0x%lx\n", loc, pc_begin + *l2);
    })

    if_cfa(DW_CFA_advance_loc2,
    {
        auto loc = get<uint16_t>(p) * cie.code_alignment();
        if ((*l2 += loc) > *l1)
        {
            log("search complete\n");
            return;
        }
        log("%ld to 0x%lx\n", loc, pc_begin + *l2);
    })

    if_cfa(DW_CFA_advance_loc4,
    {
        auto loc = get<uint32_t>(p) * cie.code_alignment();
        if ((*l2 += loc) > *l1)
        {
            log("search complete\n");
            return;
        }
        log("%ld to 0x%lx\n", loc, pc_begin + *l2);
    })

    if_cfa(DW_CFA_offset_extended,
    {
        auto reg = dwarf4::decode_uleb128(p);
        auto value = (int64_t)dwarf4::decode_uleb128(p) * cie.data_alignment();
        row->set_reg(cfi_register(reg, rule_offsetn, value));
        log("r%ld (%s) at cfa + n(%ld)\n", reg, state->name(reg), value);
    })

    if_cfa(DW_CFA_restore_extended,
    {
        auto reg = dwarf4::decode_uleb128(p);
        row->set_reg(initialRow->reg(reg));
        log("r%d (%s)\n", reg, state->name(reg));
    })

    if_cfa(DW_CFA_undefined,
    {
        auto reg = dwarf4::decode_uleb128(p);
        row->set_reg(reg, rule_undefined);
        log("r%ld (%s)\n", reg, state->name(reg));
    })

    if_cfa(DW_CFA_same_value,
    {
        auto reg = dwarf4::decode_uleb128(p);
        row->set_reg(reg, rule_same_value);
        log("r%ld (%s)\n", reg, state->name(reg));
    })

    if_cfa(DW_CFA_register,
    {
        auto reg1 = dwarf4::decode_uleb128(p);
        auto reg2 = dwarf4::decode_uleb128(p);
        row->set_reg(reg1, row->reg(reg2).rule());
        log("r%ld (%s) to r%ld (%s)\n", reg2, state->name(reg2),
        reg1, state->name(reg1));
    })

    if_cfa(DW_CFA_remember_state,
    {
        if (rememberIndex >= REMEMBER_STACK_SIZE)
            ABORT("remember stack is full. unable to continue unwind");

        rememberStack[rememberIndex++] = *row;
        log("index %ld\n", rememberIndex);
    })

    if_cfa(DW_CFA_restore_state,
    {
        if (rememberIndex == 0)
            ABORT("remember stack is empty. unable to continue unwind");

        *row = rememberStack[--rememberIndex];
        log("index %ld\n", rememberIndex);
    })

    if_cfa(DW_CFA_def_cfa,
    {
        auto cfa = row->cfa();
        cfa.set_value(dwarf4::decode_uleb128(p));
        cfa.set_offset(dwarf4::decode_uleb128(p));
        row->set_cfa(cfa);
        log("r%ld (%s) ofs %ld\n", cfa.value(),
        state->name(cfa.value()),
        cfa.offset());
    })

    if_cfa(DW_CFA_def_cfa_register,
    {
        auto cfa = row->cfa();
        cfa.set_value(dwarf4::decode_uleb128(p));
        row->set_cfa(cfa);
        log("r%ld (%s)\n", cfa.value(), state->name(cfa.value()));
    })

    if_cfa(DW_CFA_def_cfa_offset,
    {
        auto cfa = row->cfa();
        cfa.set_offset(dwarf4::decode_uleb128(p));
        row->set_cfa(cfa);
        log("%ld\n", cfa.offset());
    })

    if_cfa(DW_CFA_def_cfa_expression,
    {
        auto cfa = row->cfa();
        cfa.set_value((uint64_t)*p);
        cfa.set_type(cfi_cfa::cfa_expression);
        row->set_cfa(cfa);
        *p += dwarf4::decode_uleb128(p);
        log("cfa %p\n", *p);
    })

    if_cfa(DW_CFA_expression,
    {
        auto reg = dwarf4::decode_uleb128(p);
        auto value = (uint64_t) * p;
        row->set_reg(cfi_register(reg, rule_expression, value));
        *p += dwarf4::decode_uleb128(p);
        log("r%ld (%s) expression cfa %p\n", reg, state->name(reg), *p);
    })

    if_cfa(DW_CFA_offset_extended_sf,
    {
        auto reg = dwarf4::decode_uleb128(p);
        auto value = dwarf4::decode_sleb128(p) * cie.data_alignment();
        row->set_reg(cfi_register(reg, rule_offsetn, value));
        log("r%ld (%s) at cfa + n(%ld)\n", reg, state->name(reg), value);
    })

    if_cfa(DW_CFA_def_cfa_sf,
    {
        auto cfa = row->cfa();
        cfa.set_value(dwarf4::decode_uleb128(p));
        cfa.set_offset(dwarf4::decode_sleb128(p) * cie.data_alignment());
        row->set_cfa(cfa);
        log("r%ld (%s) ofs %ld\n", cfa.value(),
        state->name(cfa.value()),
        cfa.offset());
    })

    if_cfa(DW_CFA_def_cfa_offset_sf,
    {
        auto cfa = row->cfa();
        cfa.set_offset(dwarf4::decode_sleb128(p) * cie.data_alignment());
        row->set_cfa(cfa);
        log("%ld\n", cfa.offset());
    })

    if_cfa(DW_CFA_val_offset,
    {
        auto reg = dwarf4::decode_uleb128(p);
        auto value = (int64_t)dwarf4::decode_uleb128(p) * cie.data_alignment();
        row->set_reg(cfi_register(reg, rule_val_offsetn, value));
        log("r%ld (%s) at cfa + n(%ld)\n", reg, state->name(reg), value);
    })

    if_cfa(DW_CFA_val_offset_sf,
    {
        auto reg = dwarf4::decode_uleb128(p);
        auto value = dwarf4::decode_sleb128(p) * cie.data_alignment();
        row->set_reg(cfi_register(reg, rule_val_offsetn, value));
        log("r%ld (%s) at cfa + n(%ld)\n", reg, state->name(reg), value);
    })

    if_cfa(DW_CFA_val_expression,
    {
        auto reg = dwarf4::decode_uleb128(p);
        auto value = (uint64_t) * p;
        row->set_reg(cfi_register(reg, rule_val_expression, value));
        *p += dwarf4::decode_uleb128(p);
        log("r%ld (%s) expression cfa %p\n", reg, state->name(reg), *p);
    })

    if_cfa(DW_CFA_GNU_args_size,
    {
        auto arg_size = dwarf4::decode_uleb128(p);
        row->set_arg_size(arg_size);
        log("arg size %ld\n", arg_size);
    })

    if_cfa(DW_CFA_GNU_negative_offset_extended,
    {
        auto reg = dwarf4::decode_uleb128(p);
        auto value = (int64_t)dwarf4::decode_uleb128(p) * cie.data_alignment();
        row->set_reg(cfi_register(reg, rule_offsetn, -value));
        log("r%ld (%s) at cfa + n(%ld)\n", reg, state->name(reg), value);
    })

    ABORT("unknown cfi cfa");
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

    uint64_t rememberIndex = 0;
    cfi_table_row rememberStack[REMEMBER_STACK_SIZE] = {};

    auto initialRow = *row;

    while (p < end && l1 >= l2)
        private_parse_instruction(row, cie, &p, &l1, &l2, pc_begin, state,
                                  rememberIndex, rememberStack, &initialRow);
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
    int64_t byte = 0;
    int64_t shift = 0;
    int64_t result = 0;

    while (true)
    {
        byte = *((uint8_t *)(*addr)++);
        result |= ((byte & 0x7f) << shift);
        shift += 7;
        if ((byte & 0x80) == 0)
            break;
    }

    if ((shift < 0x40) && (byte & 0x40) != 0)
        result |= -(1LL << shift);

    return result;
}

uint64_t
dwarf4::decode_uleb128(char **addr)
{
    uint64_t byte = 0;
    uint64_t shift = 0;
    uint64_t result = 0;

    while (true)
    {
        byte = *((uint8_t *)(*addr)++);
        result |= ((byte & 0x7f) << shift);
        shift += 7;
        if ((byte & 0x80) == 0)
            break;
    }

    return result;
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmaybe-uninitialized"

void
dwarf4::unwind(const fd_entry &fde, register_state *state)
{
    log("-------------\n");
    log("- Unwinding -\n");
    log("-------------\n");
    log("\n");

    if (state == 0)
        return;

    auto row = private_decode_cfi(fde, state);
    auto cfa = private_decode_cfa(row, state);

    for (auto i = 0U; i < state->max_num_registers(); i++)
    {
        auto reg = row.reg(i);

        if (reg.rule() == rule_undefined)
            continue;

        state->set(i, private_decode_reg(reg, cfa, state));
    }

    state->commit(cfa + row.arg_size());
}

#pragma GCC diagnostic pop
