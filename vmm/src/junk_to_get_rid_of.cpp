// TODO: This is all junk to let the vmm compile while defining the project
// strucutre. Remove everything in this file as we start to fill in real
// implementaiton details.

typedef unsigned long size_t;

extern "C"
void * memset (void * ptr, int value, size_t num ) noexcept
{ return nullptr; }

void operator delete(void * p) noexcept
{
    return;
}

extern "C" void __cxa_pure_virtual() { while (1); }

extern "C" void __cxa_atexit() { return; }
