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

#ifndef EH_FRAME_H
#define EH_FRAME_H

#include <stdint.h>
#include <bfconstants.h>
#include <bfehframelist.h>

#include <registers_intel_x64.h>

class common_entry;
class ci_entry;
class fd_entry;

// -----------------------------------------------------------------------------
// Overview
// -----------------------------------------------------------------------------
//
// Exception Handling Framework (eh_frame) is based on the DWARF specification.
// This implementation uses the DWARF 4 specification, but the actual format
// is defined here (as there are some differences):
//
// https://refspecs.linuxfoundation.org/LSB_5.0.0/LSB-Core-generic/LSB-Core-generic.pdf
//
// In addition to the above specification, Ian Lance Taylor has a great
// explanation of this section on his blog:
//
// http://www.airs.com/blog/archives/460
// http://www.airs.com/blog/archives/462
// http://www.airs.com/blog/archives/464
//
// and there is another good explanation of this information here:
//
// http://www.deadp0rk.com/2013/09/22/base_abi/
//
// Notes:
//
// - This implementation is not optimized for performance. Exception handling
//   in bareflank should not be used for flow control, but rather for error
//   handling (which should not happen often)
//
// - The specification is written for 32bit and 64bit. This implementation
//   only supports 64bit.
//
// - readelf can be used to parse the .eh_frame section, and provide all of
//   the information that this code should be capable of parsing. Use the
//   --debug-dump=frames flag with a binary or shared module.
//
// - If you see a function that takes a char **addr, it will use the addr and
//   then advance the addr based on the operation performed. This is because
//   the way this spec is written, decoding everything is done in a linear
//   fashion, and each operation is compressed, so you don't know how much to
//   advance the pointer until you decode the operation.
//
// In addition to this implementation, there are two other implementations that
// could provide useful information:
//
// http://www.nongnu.org/libunwind/
// https://github.com/llvm-mirror/libunwind
//

// -----------------------------------------------------------------------------
// DWARF Extensions (section 10.5)
// -----------------------------------------------------------------------------
//
// The Exception Handler Framework in our version of the LSB uses the DWARF 4
// spec, but does so by applying the following extensions
//

// -----------------------------------------------------------------------------
// DWARF Exception Header Encoding (section 10.5.1)
// -----------------------------------------------------------------------------
//
// An EH encoding is a byte, with the lower 4 bits describing the format of the
// pointer, and the upper 4 bits describing how the pointer should be applied.
//

// Data Format
#define DW_EH_PE_absptr     0x00
#define DW_EH_PE_uleb128    0x01
#define DW_EH_PE_udata2     0x02
#define DW_EH_PE_udata4     0x03
#define DW_EH_PE_udata8     0x04
#define DW_EH_PE_sleb128    0x09
#define DW_EH_PE_sdata2     0x0A
#define DW_EH_PE_sdata4     0x0B
#define DW_EH_PE_sdata8     0x0C

// Data Application
#define DW_EH_PE_pcrel      0x10
#define DW_EH_PE_textrel    0x20
#define DW_EH_PE_datarel    0x30
#define DW_EH_PE_funcrel    0x40
#define DW_EH_PE_aligned    0x50

// Special
#define DW_EH_PE_omit       0xFF

/// Decode Pointer
///
/// Decodes a pointer located at addr, given the provided encoding scheme.
/// The whole reason this function exists is that for most pointers in an
/// executable, not all of the address bits are needed. For example, on a 64bit
/// system, most executables are well under 1GB, and thus, the vast majority
/// of address bits are not needed to relay an address. To save space, pointers
/// are encoded, and this function provides the decoding logic.
///
/// Note that for 64bit, you are only likely to PC relative addressing. This
/// is because in 64bit, all of the code is relocatable.
///
/// @param addr the location of the encoded pointer. Note that this takes a
///     double pointer. This is because the total size of the pointer is
///     not know until it is decoded. Therefore, this function not only decodes
///     but it also advances the address based on the size of the pointer.
/// @param encoding the scheme by which the pointer is encoded.
/// @return the resulting pointer
///
uint64_t decode_pointer(char **addr, uint64_t encoding);

// -----------------------------------------------------------------------------
// DWARF Call Frame Instruction (CFI) Extensions (section 10.5.2)
// -----------------------------------------------------------------------------
//
// These extend the call frame instructions that are defined in the DWARF 4
// specification.
//

#define DW_CFA_GNU_args_size                    0x2E
#define DW_CFA_GNU_negative_offset_extended     0x2F

// -----------------------------------------------------------------------------
// .eh_frame Section (section 10.6.1)
// -----------------------------------------------------------------------------
//
// The .eh_frame section is located in each compiled unit (binary or shared
// module). It contains one or more Call Frame Information structures (not
// to be confusd with the Call Frame Instructions which are defined in the
// DWARF portion of this code). The CFI structures have the following format:
//
//          CFI
// ---------------------
// - CIE               -
// - FDE               -
// - FDE               -
// ---------------------
// - CIE               -
// - FDE               -
// - ...               -
// ---------------------
//
// The size of the .eh_frame section dictates the number of CIEs in the CFI,
// which means that both the starting address of the .eh_frame section, and
// it's size must be available. The best way to view the difference between
// the CIE and the FDE is, the FDE contains the information needed to unwind
// the stack for a given program counter (PC), and the CIE contains the
// information for an FDE that just do happens to be shared with other FDEs.
// For this reason, when looking for the FDE associated with your PC, you
// basically scan looking for FDEs, and just ignore an entry if it happens to
// be a CIE instead of an FDE. Once you find the FDE you care about, you can
// use the CIE offset stored in the FDE to find the CIE associated with that
// FDE. It probably would have made sense for GCC to place the all of the CIEs
// at the end of the list to make scanning easier, but that's not the case.
//
// Both the CIE and the FDE's have some fields that are encoded using both
// signed and unsigned LEB128 format. What this means is the value could be
// 8bits, or even 64bits, it all depends on how many bits are needed to encode
// the value, which provides a means to compress the information in each CIE
// and FDE. For example, a length field my contain the value 0x40, which only
// takes up a byte. The length could also be 0x4000000. The problem is, in a
// lot of cases, len might end up being small most of the time, but because
// it could be larger, 64bits would need to be allocated every time. To
// prevent this, LEB128 breaks up the number in a way that allows it to be
// encoded in a compressed form, thus taking up less space. In our code, when
// you see a LEB128, we store the decoded values as 64bits. There is a really
// good explanation of this here:
//
// https://en.wikipedia.org/wiki/LEB128

/// Exception Header Framework
///
/// This is a pretty simple class. The entire .eh_frame ELF section exists
/// to provide a list of FDEs that describe a specific call frame for
/// unwinding. This class provides a means to lookup an FDE for any PC that
/// the code might be executing from.
///
class eh_frame
{
public:
    static fd_entry find_fde(register_state *state);
};

/// Common Entry
///
/// Both the CIE and the FDE share the length field. The length field can have
/// two different sizes, so this class provides a simple way to describe the
/// CIE/FDE itself (entry start / end), the portion of the CIE/FDE that does
/// not include the length field (the payload), as well as some other
/// functions for convenience.
///
class common_entry
{
public:

    /// Default Constructor
    ///
    /// Creates an invalid CIE/FDE
    ///
    common_entry();

    /// Constructor
    ///
    /// Creates an invalid CIE/FDE, but stores the location of the beginning
    /// of the .eh_frame section.
    ///
    explicit common_entry(const eh_frame_t &eh_frame);

    /// Destructor
    ///
    virtual ~common_entry() = default;

    /// Default Move Constructor
    ///
    common_entry(common_entry &&) noexcept = default;

    /// Default Copy Constructor
    ///
    common_entry(const common_entry &) = default;

    /// Default Move Assignment Operator
    ///
    common_entry &operator=(common_entry &&) noexcept = default;

    /// Default Copy Assignment Operator
    ///
    common_entry &operator=(const common_entry &) = default;

    /// Next CIE/FDE
    ///
    /// Moves to the next CIE/FDE in the list. If the CIE/FDE is invalid, this
    /// function does nothing. If is possible that this function could result
    /// in an invalid CIE/FDE, which can be used in a for loop to determine
    /// when the end of the list has been approached.
    ///
    /// @return next CIE/FDE
    ///
    common_entry &operator++();

    /// Valid
    ///
    /// @return returns true if the CIE/FDE is valid
    ///
    operator bool() const
    { return m_entry_start != nullptr; }

    /// Is CIE
    ///
    /// @return returns true if this is a CIE
    ///
    bool is_cie() const
    { return m_is_cie; }

    /// Is FDE
    ///
    /// @return returns true is this is an FDE
    ///
    bool is_fde() const
    { return !m_is_cie; }

    /// Entry Start
    ///
    /// @return returns the start of the CIE/FDE in memory
    ///
    char *entry_start() const
    { return m_entry_start; }

    /// Entry End
    ///
    /// @return returns the end of the CIE/FDE in memory
    ///
    char *entry_end() const
    { return m_entry_end; }

    /// Payload Start
    ///
    /// @return returns the start of the CIE/FDE's payload in memory, which
    /// is the portion of the CIE/FDE that does not contain the length field
    ///
    char *payload_start() const
    { return m_payload_start; }

    /// Payload End
    ///
    /// @return returns the end of the CIE/FDE's payload in memory, which
    /// is the portion of the CIE/FDE that does not contain the length field.
    /// Note that this should be the same as entry_end
    ///
    char *payload_end() const
    { return m_payload_end; }

    /// EH Framework
    ///
    /// @return returns the .eh_frame associated with this CIE/FDE
    ///
    eh_frame_t eh_frame() const
    { return m_eh_frame; }

protected:
    virtual void parse(char *addr) = 0;
    void non_virtual_parse(char *addr);

protected:
    bool m_is_cie;

    char *m_entry_start;
    char *m_entry_end;

    char *m_payload_start;
    char *m_payload_end;

    eh_frame_t m_eh_frame;
};

// -----------------------------------------------------------------------------
// Common Information Entry (CIE) Format (section 10.6.1.1)
// -----------------------------------------------------------------------------
//

/// Common Information Entry
///
/// The goal of the CIE is to provide a set of DWARF instructions that are the
/// same for all FDEs (at least this is how it is documented). What this really
/// means is each CIE defines a different function prolog that the compiler
/// has, and there are not many of them. The CIE also contains other information
/// that is shared by all of the FDEs, like the personality function, and the
/// location of the LSDA, and the different encoding types.
///
/// When parsing the .eh_frame section, it's best to actually skip over the CIEs
/// and only look for FDEs. Once you have the FDE you want, you can use the
/// pointer in the FDE to locate the CIE associated with that FDE.
///
class ci_entry : public common_entry
{
public:

    /// Default Constructor
    ///
    /// Creates an invalid CIE
    ///
    ci_entry();

    /// Constructor
    ///
    /// Creates an invalid CIE, but stores the location of the beginning
    /// of the .eh_frame section.
    ///
    explicit ci_entry(const eh_frame_t &eh_frame);

    /// Constructor
    ///
    /// Creates a valid CIE if the addr that is provided points to a valid
    /// CIE in the .eh_frame provided
    ///
    explicit ci_entry(const eh_frame_t &eh_frame, void *addr);

    /// Destructor
    ///
    ~ci_entry() override = default;

    /// Default Move Constructor
    ///
    ci_entry(ci_entry &&) noexcept = default;

    /// Default Copy Constructor
    ///
    ci_entry(const ci_entry &) = default;

    /// Default Move Assignment Operator
    ///
    ci_entry &operator=(ci_entry &&) noexcept = default;

    /// Default Copy Assignment Operator
    ///
    ci_entry &operator=(const ci_entry &) = default;

    /// Augmentation String
    ///
    /// Each CIE can provide different types of information, and to provide a
    /// means to compress this information, the DWARF spec defines which
    /// fields each CIE/FDE actually provides using the augmentation string.
    /// Each character in the string defines what the next thing in the
    /// augmentation data portion of the CIE/FDE is. For more information on
    /// this, please see the specification.
    ///
    /// @return pointer to the augmentation string
    ///
    char augmentation_string(uint64_t index) const
    { return m_augmentation_string[index]; }

    /// Code Alignment
    ///
    /// @return returns how the code is aligned. On x86_64, this is usually
    /// just 1, which means it's pointless.
    ///
    uint64_t code_alignment() const
    { return m_code_alignment; }

    /// Data Alignment
    ///
    /// @return returns how the data is aligned. On x86_64, this is usually
    /// -8 bytes, which means that each register is 8 bytes, growing down
    /// from the CFA
    ///
    int64_t data_alignment() const
    { return m_data_alignment; }

    /// Return Address Register
    ///
    /// @return returns the instruction pointer register index. The System
    /// V 64bit ABI defines this as 16 (rip)
    ///
    uint64_t return_address_reg() const
    { return m_return_address_reg; }

    /// Pointer Encoding
    ///
    /// @return returns how each pointer is encoded. This is defined by
    /// the eh_frame spec (not the DWARF spec) and is usually a PC relative
    /// encoding, as x86_64 code is relocatable.
    ///
    uint64_t pointer_encoding() const
    { return m_pointer_encoding; }

    /// LSDA Encoding
    ///
    /// @return returns how the LSDA is encoded
    ///
    uint64_t lsda_encoding() const
    { return m_lsda_encoding; }

    /// Personality Encoding
    ///
    /// @return returns how the personality function's pointer is encoded.
    ///
    uint64_t personality_encoding() const
    { return m_personality_encoding; }

    /// Personality Function
    ///
    /// @return returns a pointer to the personality function. The personality
    /// function tells the unwinder when to stop searching for the catch
    /// blocks
    ///
    uint64_t personality_function() const
    { return m_personality_function; }

    /// Initial Instructions
    ///
    /// @return returns a pointer to the initial DWARF instructions that
    /// usually define the function prologs that the compiler creates
    ///
    char *initial_instructions() const
    { return m_initial_instructions; }

protected:
    void parse(char *addr) override;
    void non_virtual_parse(char *addr);

public:
    const char *m_augmentation_string;
    uint64_t m_code_alignment;
    int64_t m_data_alignment;
    uint64_t m_return_address_reg;
    uint64_t m_pointer_encoding;
    uint64_t m_lsda_encoding;
    uint64_t m_personality_encoding;
    uint64_t m_personality_function;
    char *m_initial_instructions;
};

// -----------------------------------------------------------------------------
// Frame Description Entry (FDE) (section 10.6.1.2)
// -----------------------------------------------------------------------------

/// Frame Description Entry
///
/// The FDE provides all of the instructions for restoring the state of the
/// registers when unwinding the stack. There is one FDE for each call frame
/// that is created by the compiler (which is usually a function, but can
/// include more than just functions in practice).
///
class fd_entry : public common_entry
{
public:

    /// Default Constructor
    ///
    /// Creates an invalid FDE
    ///
    fd_entry();

    /// Constructor
    ///
    /// Creates an invalid FDE, but stores the location of the beginning
    /// of the .eh_frame section.
    ///
    explicit fd_entry(const eh_frame_t &eh_frame);

    /// Constructor
    ///
    /// Creates a valid FDE if the addr that is provided points to a valid
    /// FDE in the .eh_frame provided
    ///
    explicit fd_entry(const eh_frame_t &eh_frame, void *addr);

    /// Destructor
    ///
    ~fd_entry() override = default;

    /// Default Move Constructor
    ///
    fd_entry(fd_entry &&) noexcept = default;

    /// Default Copy Constructor
    ///
    fd_entry(const fd_entry &) = default;

    /// Default Move Assignment Operator
    ///
    fd_entry &operator=(fd_entry &&) noexcept = default;

    /// Default Copy Assignment Operator
    ///
    fd_entry &operator=(const fd_entry &) = default;

    /// Is PC In Range
    ///
    /// Note: the range for the PC is not 0 indexed (fails if you attempt
    /// to code this as >= && < instead of > && <=). The test case is a
    /// function that does nothing but throws. The compiler will emit code
    /// without an epilogue, and the range will include the address of the
    /// next instruction which is the start of another function.
    ///
    /// @param pc the program counter (on x86_64 this is rip) to test
    /// @return returns true if this FDE contains the instructions for the
    ///     PC provided.
    ///
    bool is_in_range(uint64_t pc) const
    { return (pc > m_pc_begin) && (pc <= m_pc_begin + m_pc_range); }

    /// PC Begin
    ///
    /// @return returns the beginning of the FDE's range
    ///
    uint64_t pc_begin() const
    { return m_pc_begin; }

    /// PC Range
    ///
    /// @return returns the range of the FDE
    ///
    uint64_t pc_range() const
    { return m_pc_range; }

    /// LSDA Location
    ///
    /// @return returns the location of the LSDA given the encoding defined
    ///     in the CIE
    ///
    uint64_t lsda() const
    { return m_lsda; }

    /// Instructions
    ///
    /// @return returns the location of the DWARF instructions that define how
    ///     to unwind the CFA that this FDE defines.
    ///
    char *instructions() const
    { return m_instructions; }

    /// CIE
    ///
    /// @return returns the CIE associated with this FDE.
    ///
    const ci_entry &cie() const
    { return m_cie; }

protected:
    void parse(char *addr) override;
    void non_virtual_parse(char *addr);

private:
    uint64_t m_pc_begin;
    uint64_t m_pc_range;
    uint64_t m_lsda;
    char *m_instructions;

    ci_entry m_cie;
};

#endif
