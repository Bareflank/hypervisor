#include <vmcs/bitmap.h>

bitmap::bitmap(uint32_t num_bits)
{
    m_length = num_bits / 8;

    if (num_bits % 8)
    {
        m_length++;
    }

    m_bitmap = new uint8_t[m_length];

    for (uint32_t i = 0; i < num_bits; i++)
    {
        set_bit(i);
        clear_bit(i);
    }
}

uint8_t *bitmap::address()
{
    return m_bitmap;
}

void bitmap::set_bit(uint32_t n)
{
    if ((n / 8) > m_length) return;

    m_bitmap[n / 8] |= (1 << (n % 8));
}

void bitmap::clear_bit(uint32_t n)
{
    if ((n / 8) > m_length) return;

    m_bitmap[n / 8] &= ~(1 << (n % 8));
}

bool bitmap::bit(uint32_t n)
{
    if ((n / 8) > m_length) return false;

    if (m_bitmap[n / 8] & (1 << (n % 8)))
    {
        return true;
    }

    return false;
}
