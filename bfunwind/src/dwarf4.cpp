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

#include <misc.h>
#include <abort.h>
#include <dwarf4.h>

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

template<typename T> T static get(char **p)
{ auto v = *reinterpret_cast<T *>(*p); (*p) += sizeof(T); return v;}

// TODO: We should attempt to convert these to lambda functions in the
//       future as clang-tidy is getting upset about "b" not being enclosed
//       in a (). Converting these to functions that take a lambda should
//       remove the need for a macro. To do this, a couple of things will
//       need to be done:
//       - An opcode -> str function will be needed as we currently leverage
//         the macro to stringify the opcodes
//       - The embedded return / continue will need to be removed, which will
//         help with reability in some ways, but hurt in others.
//       - Remove the exception from clang-tidy once this is addressed.

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
        for (auto i = 0U; i < MAX_NUM_REGISTERS; i++)
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
        uint8_t opcode = *reinterpret_cast<uint8_t *>(p);
        p++;

        if (i >= EXPRESSION_STACK_SIZE - 1)
            ABORT("out of DWARF expression stack space");

        switch (opcode)
        {
            case DW_OP_addr:
            {
                stack[++i] = *reinterpret_cast<uint64_t *>(p);
                p += sizeof(uint64_t);
                break;
            }

            case DW_OP_deref:
            {
                if (stack[i] == 0)
                    ABORT("DW_OP_deref: attempted to dereference nullptr");

                stack[i] = *reinterpret_cast<uint64_t *>(stack[i]);
                break;
            }

            case DW_OP_const1u:
            {
                stack[++i] = static_cast<uint64_t>(*reinterpret_cast<uint8_t *>(p));
                p += sizeof(uint8_t);
                break;
            }

            case DW_OP_const1s:
            {
                stack[++i] = static_cast<uint64_t>(*reinterpret_cast<int8_t *>(p));
                p += sizeof(int8_t);
                break;
            }

            case DW_OP_const2u:
            {
                stack[++i] = static_cast<uint64_t>(*reinterpret_cast<uint16_t *>(p));
                p += sizeof(uint16_t);
                break;
            }

            case DW_OP_const2s:
            {
                stack[++i] = static_cast<uint64_t>(*reinterpret_cast<int16_t *>(p));
                p += sizeof(int16_t);
                break;
            }

            case DW_OP_const4u:
            {
                stack[++i] = static_cast<uint64_t>(*reinterpret_cast<uint32_t *>(p));
                p += sizeof(uint32_t);
                break;
            }

            case DW_OP_const4s:
            {
                stack[++i] = static_cast<uint64_t>(*reinterpret_cast<int32_t *>(p));
                p += sizeof(int32_t);
                break;
            }

            case DW_OP_const8u:
            {
                stack[++i] = *reinterpret_cast<uint64_t *>(p);
                p += sizeof(uint64_t);
                break;
            }

            case DW_OP_const8s:
            {
                stack[++i] = static_cast<uint64_t>(*reinterpret_cast<int64_t *>(p));
                p += sizeof(int64_t);
                break;
            }

            case DW_OP_constu:
            {
                stack[++i] = dwarf4::decode_uleb128(&p);
                break;
            }

            case DW_OP_consts:
            {
                stack[++i] = static_cast<uint64_t>(dwarf4::decode_sleb128(&p));
                break;
            }

            case DW_OP_dup:
            {
                auto value = stack[i];
                stack[++i] = value;
                break;
            }

            case DW_OP_drop:
            {
                if (i == 0)
                    ABORT("DW_OP_drop out-of-bounds");
                i--;
                break;
            }

            case DW_OP_over:
            {
                if (i == 0)
                    ABORT("DW_OP_over out-of-bounds");
                auto value = stack[i - 1];
                stack[++i] = value;
                break;
            }

            case DW_OP_pick:
            {
                auto index = *reinterpret_cast<uint8_t *>(p);
                p += sizeof(uint8_t);

                if (index > i)
                    ABORT("DW_OP_pick out-of-bounds");

                auto value = stack[i - index];
                stack[++i] = value;
                break;
            }

            case DW_OP_swap:
            {
                if (i == 0)
                    ABORT("DW_OP_swap out-of-bounds");

                auto value = stack[i];
                stack[i] = stack[i - 1];
                stack[i - 1] = value;
                break;
            }

            case DW_OP_rot:
            {
                if (i <= 1)
                    ABORT("DW_OP_swap out-of-bounds");

                auto value = stack[i];
                stack[i] = stack[i - 1];
                stack[i - 1] = stack[i - 2];
                stack[i - 2] = value;
                break;
            }

            case DW_OP_xderef:
            {
                if (i == 0)
                    ABORT("DW_OP_xderef out-of-bounds");

                auto value = stack[i--];

                if (value == 0)
                    ABORT("DW_OP_deref: attempted to dereference nullptr");

                stack[i] = *reinterpret_cast<uint64_t *>(value);
                break;
            }

            case DW_OP_abs:
            {
                auto value = static_cast<int64_t>(stack[i]);
                if (value < 0)
                    stack[i] = static_cast<uint64_t>(-value);
                break;
            }

            case DW_OP_and:
            {
                if (i == 0)
                    ABORT("DW_OP_and out-of-bounds");

                auto value = stack[i--];
                stack[i] &= value;
                break;
            }

            case DW_OP_minus:
            {
                if (i == 0)
                    ABORT("DW_OP_minus out-of-bounds");

                auto value = stack[i--];
                stack[i] -= value;
                break;
            }

            case DW_OP_mul:
            {
                if (i == 0)
                    ABORT("DW_OP_minus out-of-bounds");

                auto value = stack[i--];
                stack[i] *= value;
                break;
            }

            case DW_OP_neg:
            {
                stack[i] = static_cast<uint64_t>(0 - static_cast<int64_t>(stack[i]));
                break;
            }

            case DW_OP_not:
            {
                stack[i] = ~stack[i];
                break;
            }

            case DW_OP_or:
            {
                if (i == 0)
                    ABORT("DW_OP_or out-of-bounds");

                auto value = stack[i--];
                stack[i] |= value;
                break;
            }

            case DW_OP_plus:
            {
                if (i == 0)
                    ABORT("DW_OP_plus out-of-bounds");

                auto value = stack[i--];
                stack[i] += value;
                break;
            }

            case DW_OP_plus_uconst:
            {
                stack[i] += dwarf4::decode_uleb128(&p);
                break;
            }

            case DW_OP_shl:
            {
                if (i == 0)
                    ABORT("DW_OP_shl out-of-bounds");

                auto value = stack[i--];
                stack[i] = stack[i] << value;
                break;
            }

            case DW_OP_shr:
            {
                if (i == 0)
                    ABORT("DW_OP_shr out-of-bounds");

                auto value = stack[i--];
                stack[i] = stack[i] >> value;
                break;
            }

            case DW_OP_shra:
            {
                if (i == 0)
                    ABORT("DW_OP_shra out-of-bounds");

                auto value1 = stack[i--];
                auto value2 = static_cast<int64_t>(stack[i]);
                stack[i] = static_cast<uint64_t>(value2 >> value1);
                break;
            }

            case DW_OP_xor:
            {
                if (i == 0)
                    ABORT("DW_OP_xor out-of-bounds");

                auto value = stack[i--];
                stack[i] ^= value;
                break;
            }

            case DW_OP_skip:
            {
                auto value = *reinterpret_cast<int16_t *>(p);
                p += 2;
                p += value;
                break;
            }

            case DW_OP_bra:
            {
                if (i == 0)
                    ABORT("DW_OP_bra out-of-bounds");

                auto value = *reinterpret_cast<int16_t *>(p);
                p += 2;
                if (stack[i--] != 0)
                    p += value;
                break;
            }

            case DW_OP_eq:
            {
                if (i == 0)
                    ABORT("DW_OP_eq out-of-bounds");

                auto value = stack[i--];
                stack[i] = (stack[i] == value) ? 1 : 0;
                break;
            }

            case DW_OP_ge:
            {
                if (i == 0)
                    ABORT("DW_OP_ge out-of-bounds");

                auto value = stack[i--];
                stack[i] = (stack[i] >= value) ? 1 : 0;
                break;
            }

            case DW_OP_gt:
            {
                if (i == 0)
                    ABORT("DW_OP_gt out-of-bounds");

                auto value = stack[i--];
                stack[i] = (stack[i] > value) ? 1 : 0;
                break;
            }

            case DW_OP_le:
            {
                if (i == 0)
                    ABORT("DW_OP_le out-of-bounds");

                auto value = stack[i--];
                stack[i] = (stack[i] <= value) ? 1 : 0;
                break;
            }

            case DW_OP_lt:
            {
                if (i == 0)
                    ABORT("DW_OP_lt out-of-bounds");

                auto value = stack[i--];
                stack[i] = (stack[i] < value) ? 1 : 0;
                break;
            }

            case DW_OP_ne:
            {
                if (i == 0)
                    ABORT("DW_OP_ne out-of-bounds");

                auto value = stack[i--];
                stack[i] = (stack[i] != value) ? 1 : 0;
                break;
            }

            case DW_OP_lit0:
            {
                stack[++i] = 0;
                break;
            }

            case DW_OP_lit1:
            {
                stack[++i] = 1;
                break;
            }

            case DW_OP_lit2:
            {
                stack[++i] = 2;
                break;
            }

            case DW_OP_lit3:
            {
                stack[++i] = 3;
                break;
            }

            case DW_OP_lit4:
            {
                stack[++i] = 4;
                break;
            }

            case DW_OP_lit5:
            {
                stack[++i] = 5;
                break;
            }

            case DW_OP_lit6:
            {
                stack[++i] = 6;
                break;
            }

            case DW_OP_lit7:
            {
                stack[++i] = 7;
                break;
            }

            case DW_OP_lit8:
            {
                stack[++i] = 8;
                break;
            }

            case DW_OP_lit9:
            {
                stack[++i] = 9;
                break;
            }

            case DW_OP_lit10:
            {
                stack[++i] = 10;
                break;
            }

            case DW_OP_lit11:
            {
                stack[++i] = 11;
                break;
            }

            case DW_OP_lit12:
            {
                stack[++i] = 12;
                break;
            }

            case DW_OP_lit13:
            {
                stack[++i] = 13;
                break;
            }

            case DW_OP_lit14:
            {
                stack[++i] = 14;
                break;
            }

            case DW_OP_lit15:
            {
                stack[++i] = 15;
                break;
            }

            case DW_OP_lit16:
            {
                stack[++i] = 16;
                break;
            }

            case DW_OP_lit17:
            {
                stack[++i] = 17;
                break;
            }

            case DW_OP_lit18:
            {
                stack[++i] = 18;
                break;
            }

            case DW_OP_lit19:
            {
                stack[++i] = 19;
                break;
            }

            case DW_OP_lit20:
            {
                stack[++i] = 20;
                break;
            }

            case DW_OP_lit21:
            {
                stack[++i] = 21;
                break;
            }

            case DW_OP_lit22:
            {
                stack[++i] = 22;
                break;
            }

            case DW_OP_lit23:
            {
                stack[++i] = 23;
                break;
            }

            case DW_OP_lit24:
            {
                stack[++i] = 24;
                break;
            }

            case DW_OP_lit25:
            {
                stack[++i] = 25;
                break;
            }

            case DW_OP_lit26:
            {
                stack[++i] = 26;
                break;
            }

            case DW_OP_lit27:
            {
                stack[++i] = 27;
                break;
            }

            case DW_OP_lit28:
            {
                stack[++i] = 28;
                break;
            }

            case DW_OP_lit29:
            {
                stack[++i] = 29;
                break;
            }

            case DW_OP_lit30:
            {
                stack[++i] = 30;
                break;
            }

            case DW_OP_lit31:
            {
                stack[++i] = 31;
                break;
            }

            case DW_OP_reg0:
            {
                stack[++i] = state->get(0);
                break;
            }

            case DW_OP_reg1:
            {
                stack[++i] = state->get(1);
                break;
            }

            case DW_OP_reg2:
            {
                stack[++i] = state->get(2);
                break;
            }

            case DW_OP_reg3:
            {
                stack[++i] = state->get(3);
                break;
            }

            case DW_OP_reg4:
            {
                stack[++i] = state->get(4);
                break;
            }

            case DW_OP_reg5:
            {
                stack[++i] = state->get(5);
                break;
            }

            case DW_OP_reg6:
            {
                stack[++i] = state->get(6);
                break;
            }

            case DW_OP_reg7:
            {
                stack[++i] = state->get(7);
                break;
            }

            case DW_OP_reg8:
            {
                stack[++i] = state->get(8);
                break;
            }

            case DW_OP_reg9:
            {
                stack[++i] = state->get(9);
                break;
            }

            case DW_OP_reg10:
            {
                stack[++i] = state->get(10);
                break;
            }

            case DW_OP_reg11:
            {
                stack[++i] = state->get(11);
                break;
            }

            case DW_OP_reg12:
            {
                stack[++i] = state->get(12);
                break;
            }

            case DW_OP_reg13:
            {
                stack[++i] = state->get(13);
                break;
            }

            case DW_OP_reg14:
            {
                stack[++i] = state->get(14);
                break;
            }

            case DW_OP_reg15:
            {
                stack[++i] = state->get(15);
                break;
            }

            case DW_OP_reg16:
            {
                stack[++i] = state->get(16);
                break;
            }

            case DW_OP_reg17:
            {
                stack[++i] = state->get(17);
                break;
            }

            case DW_OP_reg18:
            {
                stack[++i] = state->get(18);
                break;
            }

            case DW_OP_reg19:
            {
                stack[++i] = state->get(19);
                break;
            }

            case DW_OP_reg20:
            {
                stack[++i] = state->get(20);
                break;
            }

            case DW_OP_reg21:
            {
                stack[++i] = state->get(21);
                break;
            }

            case DW_OP_reg22:
            {
                stack[++i] = state->get(22);
                break;
            }

            case DW_OP_reg23:
            {
                stack[++i] = state->get(23);
                break;
            }

            case DW_OP_reg24:
            {
                stack[++i] = state->get(24);
                break;
            }

            case DW_OP_reg25:
            {
                stack[++i] = state->get(25);
                break;
            }

            case DW_OP_reg26:
            {
                stack[++i] = state->get(26);
                break;
            }

            case DW_OP_reg27:
            {
                stack[++i] = state->get(27);
                break;
            }

            case DW_OP_reg28:
            {
                stack[++i] = state->get(28);
                break;
            }

            case DW_OP_reg29:
            {
                stack[++i] = state->get(29);
                break;
            }

            case DW_OP_reg30:
            {
                stack[++i] = state->get(30);
                break;
            }

            case DW_OP_reg31:
            {
                stack[++i] = state->get(31);
                break;
            }

            case DW_OP_breg0:
            {
                auto reg = state->get(0);
                auto offset = dwarf4::decode_sleb128(&p);
                stack[++i] = add_offset(reg, offset);
                break;
            }

            case DW_OP_breg1:
            {
                auto reg = state->get(1);
                auto offset = dwarf4::decode_sleb128(&p);
                stack[++i] = add_offset(reg, offset);
                break;
            }

            case DW_OP_breg2:
            {
                auto reg = state->get(2);
                auto offset = dwarf4::decode_sleb128(&p);
                stack[++i] = add_offset(reg, offset);
                break;
            }

            case DW_OP_breg3:
            {
                auto reg = state->get(3);
                auto offset = dwarf4::decode_sleb128(&p);
                stack[++i] = add_offset(reg, offset);
                break;
            }

            case DW_OP_breg4:
            {
                auto reg = state->get(4);
                auto offset = dwarf4::decode_sleb128(&p);
                stack[++i] = add_offset(reg, offset);
                break;
            }

            case DW_OP_breg5:
            {
                auto reg = state->get(5);
                auto offset = dwarf4::decode_sleb128(&p);
                stack[++i] = add_offset(reg, offset);
                break;
            }

            case DW_OP_breg6:
            {
                auto reg = state->get(6);
                auto offset = dwarf4::decode_sleb128(&p);
                stack[++i] = add_offset(reg, offset);
                break;
            }

            case DW_OP_breg7:
            {
                auto reg = state->get(7);
                auto offset = dwarf4::decode_sleb128(&p);
                stack[++i] = add_offset(reg, offset);
                break;
            }

            case DW_OP_breg8:
            {
                auto reg = state->get(8);
                auto offset = dwarf4::decode_sleb128(&p);
                stack[++i] = add_offset(reg, offset);
                break;
            }

            case DW_OP_breg9:
            {
                auto reg = state->get(9);
                auto offset = dwarf4::decode_sleb128(&p);
                stack[++i] = add_offset(reg, offset);
                break;
            }

            case DW_OP_breg10:
            {
                auto reg = state->get(10);
                auto offset = dwarf4::decode_sleb128(&p);
                stack[++i] = add_offset(reg, offset);
                break;
            }

            case DW_OP_breg11:
            {
                auto reg = state->get(11);
                auto offset = dwarf4::decode_sleb128(&p);
                stack[++i] = add_offset(reg, offset);
                break;
            }

            case DW_OP_breg12:
            {
                auto reg = state->get(12);
                auto offset = dwarf4::decode_sleb128(&p);
                stack[++i] = add_offset(reg, offset);
                break;
            }

            case DW_OP_breg13:
            {
                auto reg = state->get(13);
                auto offset = dwarf4::decode_sleb128(&p);
                stack[++i] = add_offset(reg, offset);
                break;
            }

            case DW_OP_breg14:
            {
                auto reg = state->get(14);
                auto offset = dwarf4::decode_sleb128(&p);
                stack[++i] = add_offset(reg, offset);
                break;
            }

            case DW_OP_breg15:
            {
                auto reg = state->get(15);
                auto offset = dwarf4::decode_sleb128(&p);
                stack[++i] = add_offset(reg, offset);
                break;
            }

            case DW_OP_breg16:
            {
                auto reg = state->get(16);
                auto offset = dwarf4::decode_sleb128(&p);
                stack[++i] = add_offset(reg, offset);
                break;
            }

            case DW_OP_breg17:
            {
                auto reg = state->get(17);
                auto offset = dwarf4::decode_sleb128(&p);
                stack[++i] = add_offset(reg, offset);
                break;
            }

            case DW_OP_breg18:
            {
                auto reg = state->get(18);
                auto offset = dwarf4::decode_sleb128(&p);
                stack[++i] = add_offset(reg, offset);
                break;
            }

            case DW_OP_breg19:
            {
                auto reg = state->get(19);
                auto offset = dwarf4::decode_sleb128(&p);
                stack[++i] = add_offset(reg, offset);
                break;
            }

            case DW_OP_breg20:
            {
                auto reg = state->get(20);
                auto offset = dwarf4::decode_sleb128(&p);
                stack[++i] = add_offset(reg, offset);
                break;
            }

            case DW_OP_breg21:
            {
                auto reg = state->get(21);
                auto offset = dwarf4::decode_sleb128(&p);
                stack[++i] = add_offset(reg, offset);
                break;
            }

            case DW_OP_breg22:
            {
                auto reg = state->get(22);
                auto offset = dwarf4::decode_sleb128(&p);
                stack[++i] = add_offset(reg, offset);
                break;
            }

            case DW_OP_breg23:
            {
                auto reg = state->get(23);
                auto offset = dwarf4::decode_sleb128(&p);
                stack[++i] = add_offset(reg, offset);
                break;
            }

            case DW_OP_breg24:
            {
                auto reg = state->get(24);
                auto offset = dwarf4::decode_sleb128(&p);
                stack[++i] = add_offset(reg, offset);
                break;
            }

            case DW_OP_breg25:
            {
                auto reg = state->get(25);
                auto offset = dwarf4::decode_sleb128(&p);
                stack[++i] = add_offset(reg, offset);
                break;
            }

            case DW_OP_breg26:
            {
                auto reg = state->get(26);
                auto offset = dwarf4::decode_sleb128(&p);
                stack[++i] = add_offset(reg, offset);
                break;
            }

            case DW_OP_breg27:
            {
                auto reg = state->get(27);
                auto offset = dwarf4::decode_sleb128(&p);
                stack[++i] = add_offset(reg, offset);
                break;
            }

            case DW_OP_breg28:
            {
                auto reg = state->get(28);
                auto offset = dwarf4::decode_sleb128(&p);
                stack[++i] = add_offset(reg, offset);
                break;
            }

            case DW_OP_breg29:
            {
                auto reg = state->get(29);
                auto offset = dwarf4::decode_sleb128(&p);
                stack[++i] = add_offset(reg, offset);
                break;
            }

            case DW_OP_breg30:
            {
                auto reg = state->get(30);
                auto offset = dwarf4::decode_sleb128(&p);
                stack[++i] = add_offset(reg, offset);
                break;
            }

            case DW_OP_breg31:
            {
                auto reg = state->get(31);
                auto offset = dwarf4::decode_sleb128(&p);
                stack[++i] = add_offset(reg, offset);
                break;
            }

            case DW_OP_regx:
            {
                stack[++i] = state->get(dwarf4::decode_uleb128(&p));
                break;
            }

            case DW_OP_bregx:
            {
                stack[++i] = state->get(dwarf4::decode_uleb128(&p));
                stack[i] = add_offset(stack[i], dwarf4::decode_sleb128(&p));
                break;
            }

            case DW_OP_deref_size:
            {
                if (stack[i] == 0)
                    ABORT("DW_OP_deref: attempted to dereference nullptr");

                switch (*reinterpret_cast<uint8_t *>(p++))
                {
                    case 1:
                        stack[i] = *reinterpret_cast<uint8_t *>(stack[i]);
                        break;

                    case 2:
                        stack[i] = *reinterpret_cast<uint16_t *>(stack[i]);
                        break;

                    case 4:
                        stack[i] = *reinterpret_cast<uint32_t *>(stack[i]);
                        break;

                    case 8:
                        stack[i] = *reinterpret_cast<uint64_t *>(stack[i]);
                        break;

                    default:
                        ABORT("DW_OP_deref_size: invalid size");
                }

                break;
            }

            default:
                ABORT("DWARF expression opcode not supported");
        }
    }

    return stack[i];
}

static uint64_t
private_decode_cfa(const cfi_table_row &row, register_state *state)
{
    uint64_t value = 0;
    const auto &cfa = row.cfa();

    switch (cfa.type())
    {
        case cfi_cfa::cfa_register:
            value = add_offset(state->get(cfa.value()), cfa.offset());
            break;

        case cfi_cfa::cfa_expression:
            value = private_parse_expression(reinterpret_cast<char *>(cfa.value()), 0, state);
            break;
    }

    return value;
}

static uint64_t
private_decode_reg(const cfi_register &reg, uint64_t cfa, register_state *state)
{
    uint64_t value = 0;

    switch (reg.rule())
    {
        case rule_undefined:
            ABORT("unable to get register value for unused register");
            break;

        case rule_same_value:
            value = state->get(reg.index());
            break;

        case rule_offsetn:
            value = *reinterpret_cast<uint64_t *>(add_offset(cfa, static_cast<int64_t>(reg.value())));
            break;

        case rule_val_offsetn:
            value = add_offset(cfa, static_cast<int64_t>(reg.value()));
            break;

        case rule_register:
            value = state->get(reg.value());
            break;

        case rule_expression:
            value = private_parse_expression(reinterpret_cast<char *>(reg.value()), cfa, state);
            value = *reinterpret_cast<uint64_t *>(value);
            break;

        case rule_val_expression:
            value = private_parse_expression(reinterpret_cast<char *>(reg.value()), cfa, state);
            break;

        default:
            ABORT("unknown rule. cfi table is malformed");
    }

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
    (void) l1;
    (void) pc_begin;
    (void) state;

    uint8_t opcode = *reinterpret_cast<uint8_t *>(*p) & 0xC0;
    uint8_t operand = *reinterpret_cast<uint8_t *>(*p) & 0x3F;

    if (opcode == 0)
        opcode = operand;

    (*p)++;

    switch (opcode)
    {
        case DW_CFA_advance_loc:
        {
            *l2 += static_cast<uint64_t>(operand) * cie.code_alignment();
            break;
        }

        case DW_CFA_offset:
        {
            auto value = static_cast<int64_t>(dwarf4::decode_uleb128(p)) * cie.data_alignment();
            row->set_reg(cfi_register(operand, rule_offsetn, static_cast<uint64_t>(value)));
            break;
        }

        case DW_CFA_restore:
        {
            row->set_reg(initialRow->reg(operand));
            break;
        }

        case DW_CFA_nop:
        {
            break;
        }

        case DW_CFA_set_loc:
        {
            *l2 = decode_pointer(p, cie.pointer_encoding());
            break;
        }

        case DW_CFA_advance_loc1:
        {
            *l2 += get<uint8_t>(p) * cie.code_alignment();
            break;
        }

        case DW_CFA_advance_loc2:
        {
            *l2 += get<uint16_t>(p) * cie.code_alignment();
            break;
        }

        case DW_CFA_advance_loc4:
        {
            *l2 += get<uint32_t>(p) * cie.code_alignment();
            break;
        }

        case DW_CFA_offset_extended:
        {
            auto reg = dwarf4::decode_uleb128(p);
            auto value = static_cast<int64_t>(dwarf4::decode_uleb128(p)) * cie.data_alignment();
            row->set_reg(cfi_register(reg, rule_offsetn, static_cast<uint64_t>(value)));
            break;
        }

        case DW_CFA_restore_extended:
        {
            auto reg = dwarf4::decode_uleb128(p);
            row->set_reg(initialRow->reg(reg));
            break;
        }

        case DW_CFA_undefined:
        {
            auto reg = dwarf4::decode_uleb128(p);
            row->set_reg(reg, rule_undefined);
            break;
        }

        case DW_CFA_same_value:
        {
            auto reg = dwarf4::decode_uleb128(p);
            row->set_reg(reg, rule_same_value);
            break;
        }

        case DW_CFA_register:
        {
            auto reg1 = dwarf4::decode_uleb128(p);
            auto reg2 = dwarf4::decode_uleb128(p);
            row->set_reg(reg1, row->reg(reg2).rule());
            break;
        }

        case DW_CFA_remember_state:
        {
            if (rememberIndex >= REMEMBER_STACK_SIZE)
                ABORT("remember stack is full. unable to continue unwind");

            rememberStack[rememberIndex++] = *row;
            break;
        }

        case DW_CFA_restore_state:
        {
            if (rememberIndex == 0)
                ABORT("remember stack is empty. unable to continue unwind");

            *row = rememberStack[--rememberIndex];
            break;
        }

        case DW_CFA_def_cfa:
        {
            auto cfa = row->cfa();
            cfa.set_value(dwarf4::decode_uleb128(p));
            cfa.set_offset(static_cast<int64_t>(dwarf4::decode_uleb128(p)));
            row->set_cfa(cfa);
            break;
        }

        case DW_CFA_def_cfa_register:
        {
            auto cfa = row->cfa();
            cfa.set_value(dwarf4::decode_uleb128(p));
            row->set_cfa(cfa);
            break;
        }

        case DW_CFA_def_cfa_offset:
        {
            auto cfa = row->cfa();
            cfa.set_offset(static_cast<int64_t>(dwarf4::decode_uleb128(p)));
            row->set_cfa(cfa);
            break;
        }

        case DW_CFA_def_cfa_expression:
        {
            auto cfa = row->cfa();
            cfa.set_value(reinterpret_cast<uint64_t>(*p));
            cfa.set_type(cfi_cfa::cfa_expression);
            row->set_cfa(cfa);
            *p += dwarf4::decode_uleb128(p);
            break;
        }

        case DW_CFA_expression:
        {
            auto reg = dwarf4::decode_uleb128(p);
            auto value = reinterpret_cast<uint64_t>(*p);
            row->set_reg(cfi_register(reg, rule_expression, value));
            *p += dwarf4::decode_uleb128(p);
            break;
        }

        case DW_CFA_offset_extended_sf:
        {
            auto reg = dwarf4::decode_uleb128(p);
            auto value = dwarf4::decode_sleb128(p) * cie.data_alignment();
            row->set_reg(cfi_register(reg, rule_offsetn, static_cast<uint64_t>(value)));
            break;
        }

        case DW_CFA_def_cfa_sf:
        {
            auto cfa = row->cfa();
            cfa.set_value(dwarf4::decode_uleb128(p));
            cfa.set_offset(dwarf4::decode_sleb128(p) * cie.data_alignment());
            row->set_cfa(cfa);
            break;
        }

        case DW_CFA_def_cfa_offset_sf:
        {
            auto cfa = row->cfa();
            cfa.set_offset(dwarf4::decode_sleb128(p) * cie.data_alignment());
            row->set_cfa(cfa);
            break;
        }

        case DW_CFA_val_offset:
        {
            auto reg = dwarf4::decode_uleb128(p);
            auto value = static_cast<int64_t>(dwarf4::decode_uleb128(p)) * cie.data_alignment();
            row->set_reg(cfi_register(reg, rule_val_offsetn, static_cast<uint64_t>(value)));
            break;
        }

        case DW_CFA_val_offset_sf:
        {
            auto reg = dwarf4::decode_uleb128(p);
            auto value = dwarf4::decode_sleb128(p) * cie.data_alignment();
            row->set_reg(cfi_register(reg, rule_val_offsetn, static_cast<uint64_t>(value)));
            break;
        }

        case DW_CFA_val_expression:
        {
            auto reg = dwarf4::decode_uleb128(p);
            auto value = reinterpret_cast<uint64_t>(*p);
            row->set_reg(cfi_register(reg, rule_val_expression, value));
            *p += dwarf4::decode_uleb128(p);
            break;
        }

        case DW_CFA_GNU_args_size:
        {
            auto arg_size = dwarf4::decode_uleb128(p);
            row->set_arg_size(arg_size);
            break;
        }

        case DW_CFA_GNU_negative_offset_extended:
        {
            auto reg = dwarf4::decode_uleb128(p);
            auto value = static_cast<int64_t>(dwarf4::decode_uleb128(p)) * cie.data_alignment();
            row->set_reg(cfi_register(reg, rule_offsetn, static_cast<uint64_t>(-value)));
            break;
        }

        default:
            ABORT("unknown cfi cfa");
    }
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

    uint64_t rememberIndex = 0ULL;
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

    private_parse_instructions(&row, cie, fde, state, true);
    private_parse_instructions(&row, cie, fde, state, false);

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
        byte = *(reinterpret_cast<uint8_t *>((*addr)++));
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
        byte = *(reinterpret_cast<uint8_t *>((*addr)++));
        result |= ((byte & 0x7f) << shift);
        shift += 7;
        if ((byte & 0x80) == 0)
            break;
    }

    return result;
}

#ifndef __clang__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmaybe-uninitialized"
#endif

void
dwarf4::unwind(const fd_entry &fde, register_state *state)
{
    if (state == nullptr)
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

#ifndef __clang__
#pragma GCC diagnostic pop
#endif
