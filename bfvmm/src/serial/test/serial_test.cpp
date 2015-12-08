#include <stdint.h>
#include <serial_port.h>
#include <serial_port_x86.h>
#include <portio_x64.h>
#include <portio_linux.h>


int main(int argc, char **argv)
{
    portio_linux io;
    portio_x64 io_x64;
    serial_port_x86 tmp(io_x64);
    serial_port *com = &tmp;

    com->open();

    do
    {
        if (com->data_ready())
        {
            *com << com->read();
        }
    }
    while (1);

    return 0;
}
