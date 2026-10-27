#ifndef PALLAS_HASH_HPP
#define PALLAS_HASH_HPP
#include <cstddef>
#include <cstdint>

// Byte-wise seeded hash, with explicit unsigned arithmetic and no unaligned loads.
// This CPU reference does not reproduce the Tofino CRC hashes.
inline std::uint64_t HashKey(const unsigned char* key, std::size_t length,
                             std::uint64_t seed) {
    std::uint64_t h = UINT64_C(14695981039346656037) ^ seed;
    for (std::size_t i = 0; i < length; ++i) {
        h ^= key[i];
        h *= UINT64_C(1099511628211);
    }
    h ^= h >> 30;
    h *= UINT64_C(0xbf58476d1ce4e5b9);
    h ^= h >> 27;
    h *= UINT64_C(0x94d049bb133111eb);
    return h ^ (h >> 31);
}
#endif
