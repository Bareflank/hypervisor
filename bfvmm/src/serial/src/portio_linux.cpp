#include <portio_linux.h>
#include <sys/io.h>


portio_linux::portio_linux()
{
    // Elevate this process's IO permissions to
    // the highest possible (bottom two bits of
    // the int).
    iopl(3);
}

portio_linux::~portio_linux()
{

}

void portio_linux::port_write_8(uint16_t port, uint8_t value)
{
    outb(value, port);
}

void portio_linux::port_write_16(uint16_t port, uint16_t value)
{
    outw(value, port);
}

uint8_t portio_linux::port_read_8(uint16_t port)
{
    return inb(port);
}

uint16_t portio_linux::port_read_16(uint16_t port)
{
    return inw(port);
}
