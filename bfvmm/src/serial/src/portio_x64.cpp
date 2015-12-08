#include <portio_x64.h>
#include <bf_portio.h>

portio_x64::portio_x64()
{

}

portio_x64::~portio_x64()
{

}

void portio_x64::port_write_8(uint16_t port, uint8_t value)
{
    bf_outb(value, port);
}

void portio_x64::port_write_16(uint16_t port, uint16_t value)
{
    bf_outw(value, port);
}

uint8_t portio_x64::port_read_8(uint16_t port)
{
    return bf_inb(port);
}

uint16_t portio_x64::port_read_16(uint16_t port)
{
    return bf_inw(port);
}
