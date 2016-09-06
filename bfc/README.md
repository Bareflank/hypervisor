# C Library
## Present
Currently Bareflank uses newlib for libc. Newlib itself works, but causes a lot of issues with respect to compilation. Newlib won't compile a shared library for libc unless it's on a known platform, meaning all we get is a libc.a. This causes an issue with respect to how to support getting libc symbols into the VMM. Additionally, libc++abi is it's own library that also needs access to libc further complicating the issue, which leaves us with only a couple of options:

+ One option is to compile libc, libc++abi and the unwinder as static libraries, and link them into libc++.so. 
+ Another option is to statically link libc and the unwinder into libc++abi.so, and libc (again) into libc++.so. 
+ Create a custom libc so that we can have a libc.so, libc++abi.so and libc++.so

Currently we use option #1. The only disadvantage to this approach is that there might be symbols in libc++abi that are not being compiled into libc++.so that are needed (we know of one that we have to manually include). In addition, libc++abi really doesn't like being compiled as a static library, and CMake spits out warnings for both libc++abi and libc++ about it's use, something we would like to remove in the future. The advantage of this approach is there is no duplication, and it provides a simple first step to introducing libc++. 

Option #2 is just ugly, and could cause issues with linking. Its never a good idea to have the same library compiled and linked into the same executable more than once, and with a custom ELF loader, it's just adding more instability. 

It should be noted that we currently use [libbfc](https://github.com/Bareflank/libbfc) to provide libc functions that newlib does not provide, which all return not supported minus the pthread library which provides mutex support. 

## Future

Going forward we would like to provide a custom libc, written in C++ (yes that can be done, for an example please see the unwinder), that adheres to the [C++ Core Guidelines](https://github.com/isocpp/CppCoreGuidelines). There aren't many symbols that need to be provide (maybe 30 of them), and the large majority of them can just return "not supported" as they are not needed (e.g. file operations). 

With a custom libc, we will be able to remove our dependence on newlib, and provide a cleaner build system that can leverage option #3. For example, if you compile Bareflank a second time, you will notice that libc++ is recompiled (future compilations will not do this). This is because the installation of sysroot files triggers a file change, which causes the build to occur a second time, something that can be avoided with a custom libc. Additionally, a custom libc would remove the need for [libbfc](https://github.com/Bareflank/libbfc) reducing the complexity of the system. 
