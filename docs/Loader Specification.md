## Table of Contents <!-- omit in toc -->

- [1. Introduction](#1-introduction)
  - [1.1. Reserved Values](#11-reserved-values)
  - [1.2. Document Revision](#12-document-revision)
  - [1.3. Glossary](#13-glossary)
  - [1.4. Scalar Types](#14-scalar-types)
  - [1.5. Memory Address Types](#15-memory-address-types)
  - [1.6. Constants, Structures, Enumerations and Bit Fields](#16-constants-structures-enumerations-and-bit-fields)
  - [1.7. Endianness](#17-endianness)
- [2. Feature and Interface Discovery](#2-feature-and-interface-discovery)
- [3. Syscall Interface](#3-syscall-interface)

# 1. Introduction

This specification defines the ABI between user-space software and the loader kernel driver. This interface can be used to start and stop the Bareflank hypervisor as well as dump the hypervisor's internal debug ring, which can be used to debug issues with the hypervisor.

## 1.1. Reserved Values

| Name | Description |
| :--- | :---------- |
| REVZ | reserved zero, meaning the value must be set to 0 |
| REVI | reserved ignore, meaning the value is ignored |

## 1.2. Document Revision

| Version | Description |
| :------ | :---------- |
| Bf#1 | The initial version of this specification |

## 1.3. Glossary

| Abbreviation | Description |
| :----------- | :---------- |

## 1.4. Scalar Types

TBD

## 1.5. Memory Address Types

| Name | Type |
| :--- | :--- |
| System Physical Address (SPA) | mv_uint64_t |
| Guest Physical Address (GPA) | mv_uint64_t |
| Guest Virtual Address (GVA) | mv_uint64_t |

## 1.6. Constants, Structures, Enumerations and Bit Fields

TBD

## 1.7. Endianness

This document only applies to 64bit Intel, AMD and ARM systems conforming to the amd64/aarch64 architectures. As such, this document is limited to little endian.

# 2. Feature and Interface Discovery

TBD

# 3. Syscall Interface
