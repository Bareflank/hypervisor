//
// Bareflank Hypervisor
// Copyright (C) 2018 Assured Information Security, Inc.
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


#ifndef HYP_X86_64_H
#define HYP_X86_64_H

#include "bfefi.h"
#include "stdint.h"

#define KGDT64_SYS_TSS          0x60
#define AMD64_TSS               9

typedef union _KGDTENTRY64 {
    struct {
        UINT16 LimitLow;
        UINT16 BaseLow;
        union {
            struct {
                UINT8 BaseMiddle;
                UINT8 Flags1;
                UINT8 Flags2;
                UINT8 BaseHigh;
            } Bytes;
            struct {
                UINT32 BaseMiddle : 8;
                UINT32 Type : 5;
                UINT32 Dpl : 2;
                UINT32 Present : 1;
                UINT32 LimitHigh : 4;
                UINT32 System : 1;
                UINT32 LongMode : 1;
                UINT32 DefaultBig : 1;
                UINT32 Granularity : 1;
                UINT32 BaseHigh : 8;
            } Bits;
        };
        UINT32 BaseUpper;
        UINT32 MustBeZero;
    };
    struct {
        INT64 DataLow;
        INT64 DataHigh;
    };
} KGDTENTRY64, *PKGDTENTRY64;

#pragma pack(push,4)
typedef struct _KTSS64 {
    UINT32 Reserved0;
    UINT64 Rsp0;
    UINT64 Rsp1;
    UINT64 Rsp2;
    UINT64 Ist[8];
    UINT64 Reserved1;
    UINT16 Reserved2;
    UINT16 IoMapBase;
} KTSS64, *PKTSS64;
#pragma pack(pop)

typedef struct _KDESCRIPTOR {
    UINT16 Pad[3];
    UINT16 Limit;
    void *Base;
} KDESCRIPTOR, *PKDESCRIPTOR;

void _writerflags(int64_t);
int64_t _readrflags();
void _sgdt(void *);
void _lgdt(void *);
void _ltr(int16_t);
uint16_t _str();
void _set_vmxe();
void _unset_vmxe();
void _set_ne();


EFI_STATUS PrepareProcessor();
EFI_STATUS CheckProcessor();

#endif