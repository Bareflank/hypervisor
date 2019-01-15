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

#ifndef REGISTERS_INTEL_X64_H
#define REGISTERS_INTEL_X64_H

#include <log.h>
#include <abort.h>
#include <registers.h>

#if (MAX_NUM_REGISTERS < 17)
#error MAX_NUM_REGISTERS was set too low
#endif

// -----------------------------------------------------------------------------
// Load / Store Registers
// -----------------------------------------------------------------------------

#pragma pack(push, 1)

struct registers_intel_x64_t {
    uint64_t rax;
    uint64_t rdx;
    uint64_t rcx;
    uint64_t rbx;
    uint64_t rdi;
    uint64_t rsi;
    uint64_t rbp;
    uint64_t rsp;
    uint64_t r08;
    uint64_t r09;
    uint64_t r10;
    uint64_t r11;
    uint64_t r12;
    uint64_t r13;
    uint64_t r14;
    uint64_t r15;
    uint64_t rip;
};

#pragma pack(pop)

/// __store_registers_intel_x64
///
/// Stores the state of the registers into a structure
///
/// @param state the register state to store state too
/// @return always returns 0
///
extern "C"
void __store_registers_intel_x64(registers_intel_x64_t *state);

/// __load_registers_intel_x64
///
/// Restores the state of the registers from a structure
///
/// @param state the register state to store state too
/// @return always returns 0
///
extern "C"
void __load_registers_intel_x64(registers_intel_x64_t *state);

// -----------------------------------------------------------------------------
// Register State
// -----------------------------------------------------------------------------
//
// Defines the register state for x86_64. The only unexpected thing here is
// the System V 64bit ABI defines the register order as rax, rdx, rcx, rbx, and
// not rax, rbx, rcx, rdx. This makes a really big difference because the
// reg(1) used by the personality function is stored in rdx as a result.
//
// See register.h for more information
//

class register_state_intel_x64 : public register_state
{
public:
    register_state_intel_x64(const registers_intel_x64_t &registers) :
        m_registers(registers),
        m_tmp_registers(registers)

    { }

    ~register_state_intel_x64() override = default;

    register_state_intel_x64(register_state_intel_x64 &&) noexcept = default;
    register_state_intel_x64(const register_state_intel_x64 &) = default;

    register_state_intel_x64 &operator=(register_state_intel_x64 &&) noexcept = default;
    register_state_intel_x64 &operator=(const register_state_intel_x64 &) = default;

    uint64_t get_ip() const override
    { return m_registers.rip; }

    register_state &set_ip(uint64_t value) override
    {
        m_tmp_registers.rip = value;
        return *this;
    }

    uint64_t get(uint64_t index) const override
    {
        if (index >= max_num_registers()) {
            ABORT("register index out of bounds");
        }

        return reinterpret_cast<const uint64_t *>(&m_registers)[index];
    }

    register_state &set(uint64_t index, uint64_t value) override
    {
        if (index >= max_num_registers()) {
            ABORT("register index out of bounds");
        }

        reinterpret_cast<uint64_t *>(&m_tmp_registers)[index] = value;

        return *this;
    }

    void commit() override
    { m_registers = m_tmp_registers; }

    void commit(uint64_t cfa) override
    {
        m_tmp_registers.rsp = cfa;
        commit();
    }

    void resume() override
    { __load_registers_intel_x64(&m_registers); }

    uint64_t max_num_registers() const override
    { return 17; }

    const char *name(uint64_t index) const override
    {
        if (index >= max_num_registers()) {
            ABORT("register index out of bounds");
        }

        switch (index) {
            case 0x00: return "rax";
            case 0x01: return "rdx";
            case 0x02: return "rcx";
            case 0x03: return "rbx";
            case 0x04: return "rdi";
            case 0x05: return "rsi";
            case 0x06: return "rbp";
            case 0x07: return "rsp";
            case 0x08: return "r08";
            case 0x09: return "r09";
            case 0x0A: return "r10";
            case 0x0B: return "r11";
            case 0x0C: return "r12";
            case 0x0D: return "r13";
            case 0x0E: return "r14";
            case 0x0F: return "r15";
            case 0x10: return "rip";
            default: return "";
        }
    }

    void dump() const override
    {
        log("Register State:\n")
        log("  rax: 0x%08lx\n", m_registers.rax);
        log("  rdx: 0x%08lx\n", m_registers.rdx);
        log("  rcx: 0x%08lx\n", m_registers.rcx);
        log("  rbx: 0x%08lx\n", m_registers.rbx);
        log("  rdi: 0x%08lx\n", m_registers.rdi);
        log("  rsi: 0x%08lx\n", m_registers.rsi);
        log("  rbp: 0x%08lx\n", m_registers.rbp);
        log("  rsp: 0x%08lx\n", m_registers.rsp);
        log("  r08: 0x%08lx\n", m_registers.r08);
        log("  r09: 0x%08lx\n", m_registers.r09);
        log("  r10: 0x%08lx\n", m_registers.r10);
        log("  r11: 0x%08lx\n", m_registers.r11);
        log("  r12: 0x%08lx\n", m_registers.r12);
        log("  r13: 0x%08lx\n", m_registers.r13);
        log("  r14: 0x%08lx\n", m_registers.r14);
        log("  r15: 0x%08lx\n", m_registers.r15);
        log("  rip: 0x%08lx\n", m_registers.rip);
        log("\n")
    }

private:
    registers_intel_x64_t m_registers;
    registers_intel_x64_t m_tmp_registers;
};

#endif
