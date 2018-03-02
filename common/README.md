# Build System

## Description

Currently, Bareflank uses a custom build system that depends on GNU make. Someday we might attempt to use cmake, but at the moment we are using our own custom build system. The purpose of this build system is to compile:
- All cross compiled source (including dummy modules)
- All native source
- All unit tests
- Driver entries

## How It is Used

To make this work, the build system is broken up into three main files:
- common_subdir.mk
- common_target.mk
- common_test.mk

The subdir makefile moves make recursively into the different subdirectories. Generally there are two different types of subdir makefiles: parent subdirs, and target subdirs. The parent subdir makefiles link to other subdir makefiles, while the target subdir makefiles link to folders that have target makefiles (they actually compile something). A parent subdir makefile can have pretty much any folder name while the target subdir makefiles can have any folder name except bin and test. Any folder named bin should be used to contain compiled results and additional makefiles for testing. Any folder named test will get compiled after all other folders, ensuring that all of the libraries are compiled and available for testing (to resolve cyclic dependencies). 

The target makefile is capable of compiling both cross compiled sources and target sources (and in a lot of cases both, which is how most of the VMM source files are compiled). For example, the vCPU module for the VMM needs to be compiled using the cross compiler so that the library can be loaded and used by the driver entries, but also needs to be compiled natively so that it can be used in a unit test. The Bareflank Manager (BFM) only needs to be compiled natively since it is always used on the native system (it is not loaded by the driver entry), while the dummy modules only need to be compiled using the cross compiler as they are only used to test the ELF loader and driver entry code. The target makefile tries to contain all of the business logic in itself, while exposing a set of variables each target can set in it's own makefile, providing a simple way to create makefiles for each target. 

Finally the test makefile is used by "make run_tests". This makefile executes a test, and simplifies the output to prevent confusion when running the tests (as these tests can spit out a lot of garbage as error conditions are being tested). 

## Notes

Running "make" will compile everything no matter what folder you are in. You can however run "make build_src" or "make build_tests" if you are only interested in a specific portion of the code. The same applies to "make clean" vs "make clean_src" and "make clean_tests". 
