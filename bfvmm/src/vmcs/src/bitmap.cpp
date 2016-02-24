#include <vmcs/bitmap.h>

bitmap::bitmap(uint32_t num_bits)
{
    m_length = num_bits / 8;

    if (num_bits % 8)
    {
        m_length++;
    }

    // make_unique provides a calloc like buffer
    m_bitmap = std::make_unique<uint8_t[]>(m_length);
}

uint8_t *bitmap::address()
{
    return m_bitmap.get();
}

void bitmap::set_bit(uint32_t n)
{
    auto bitmap = m_bitmap.get();

    if ((n / 8) > m_length) return;

    bitmap[n / 8] |= (1 << (n % 8));
}

void bitmap::clear_bit(uint32_t n)
{
    auto bitmap = m_bitmap.get();

    if ((n / 8) > m_length) return;

    bitmap[n / 8] &= ~(1 << (n % 8));
}

bool bitmap::bit(uint32_t n)
{
    auto bitmap = m_bitmap.get();

    if ((n / 8) > m_length) return false;

    if (bitmap[n / 8] & (1 << (n % 8)))
    {
        return true;
    }

    return false;
}
