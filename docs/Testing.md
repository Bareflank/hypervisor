## Table of Contents <!-- omit in toc -->

# 1. Introduction

This document defines the testing methodology for Bareflank, and some notes
when writing tests.

# 2. Unit Tests

## 2.1 "constexpr"

As much of the code as possible is written as a constexpr. This means that the majority of the code can be compiled and executed at compile time from a static assert. This allows us to execute the unit tests while the code is being compiled, which ensures two things:
- When code is modified, the compiler not only checks for the correctness of the code, but also the correctness of the logic itself, making it far more difficult to make mistakes.
- Undefined behavior is mostly impossible as UB is not allowed in constexpr functions. We also use UBSAN to check for this, but in general, this check is not needed as the use of constexpr performs a much better and more reliable check than attempting to verify this at runtime using UBSAN.

Some of the code (e.g., the assembly logic) cannot be compiled as a constexpr. In these cases we usually provide a mock that is a constexpr, or we check to see if we are executing at compile-time and if we are, we return early, allowing the function to act as a constexpr at compile-time, avoiding the logic that is not constexpr friendly. For this reason, unit tests are always executed at both compile-time and run-time. All of the non-constexpr logic is tested at runtime to ensure that it is also tested.

## 2.2 Branch Tests

The unit tests come complete with 100% branch coverage in addition to function and line coverage. Bareflank's version of the Clang Tidy static analysis engine does not allow the use of boolean operators, and if statements are required to be in a specific form to ensure that line coverage should be the same as the branch coverage. When this does not end up being the case is when templates are used. Specifically, each template argument to a function or class creates a new copy of this function or class, and duplicates all of the branches. This means that all of the unit tests need to test every branch for every template type it is provided in the test. Since the test reports are merged across all tests, it is extremely important that template arguments are managed across all of the unit tests. Just providing a new implementation of an object that is passed to a function or class that takes a template is usually a bad idea is it will add requirements for other tests with a cascade style effect. Branch coverage is required to ensure compliance with ASIL/D so it is important that this is done properly. What this means is that the unit tests should have a single mock type, and that type should be capable of supporting all tests that are needed. In some cases, additional seams in the code are needed to support this.

## 2.3 Std C++

The BSL is fully compatible with the standard C++ library, so feel free to use standard C++ in a unit test if needed. Ideally, this is kept to a minimum to support systems that do not have access to a standard C++ library (especially on some RTOS operating systems). In these cases, the unit tests for these systems can be ignored, so keeping the use of the standard C++ library to a minimum is ideal, but when absolutely needed, it is supported.

# 3. Integration Tests

All of the ABIs that Bareflank supports have a complete set of integration tests to ensure they operate as expected at runtime. This ensures that all of the assembly code is also tested and works as expected. Note that the use of these integration tests on a specific system can be used to perform system level testing as well, meaning the integration tests can also be used to ensure that all of the code is working on each system tests. The examples also provide an additional level of system level testing as they exercise specific features on the system.
