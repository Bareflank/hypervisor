#include <stdint.h>
#include <serial/serial_port.h>
#include <serial/serial_port_x86.h>

int main(int argc, char **argv)
{
    serial_port_x86 com;

    com.open();

    do
    {
        if (com.data_ready())
        {
            com << com.read();
        }
    }
    while (1);

    return 0;
}
