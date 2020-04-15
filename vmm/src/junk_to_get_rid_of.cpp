typedef unsigned long size_t;

extern "C"
void * memset (void * ptr, int value, size_t num ) noexcept
{ return nullptr; }

void operator delete(void * p) noexcept // or delete(void *, std::size_t)
{
    return;
}

extern "C" void __cxa_pure_virtual() { while (1); }

extern "C" void __cxa_atexit() { return; }
