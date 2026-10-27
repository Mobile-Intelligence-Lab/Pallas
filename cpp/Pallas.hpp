#ifndef PALLAS_HPP
#define PALLAS_HPP
#include <cstddef>
#include <cstdint>
#include <random>
#include <vector>
#include "datatypes.hpp"

class Pallas {
public:
    enum class Variant { Basic, Optimized };

    // width = buckets per row; lgn is in bits (64 for an IPv4 pair).
    Pallas(int depth, int width, int lgn = 8 * LGN,
           Variant variant = Variant::Basic, double alpha = 0.11,
           std::uint64_t seed = 42);

    // Each call is one arrival. value (e.g. packet bytes) is intentionally ignored.
    void Update(const unsigned char* key, val_tp value = 1);
    val_tp PointQuery(const unsigned char* key) const;
    // Replaces results; inclusive threshold, as in the paper.
    void Query(val_tp threshold, myvector& results) const;
    void NewWindow(); // O(1), no per-bucket reset; caller controls boundaries.
    void Reset();     // Resets buckets, current window and random stream.
    val_tp GetCount() const { return packet_count_; }
    std::uint32_t GetWindow() const { return current_window_; }
    std::size_t MemoryBytes() const { return buckets_.size() * sizeof(Bucket); }
    static std::size_t BucketBytes() { return sizeof(Bucket); }
    static double DecayProbability(Variant variant, std::uint32_t persistence,
                                   std::uint32_t inactivity, double alpha = 0.11);

private:
    struct Bucket {
        key_tp key;
        std::uint32_t persistence = 0; // Zero marks an empty bucket, not a key value.
        std::uint32_t last_window = 0;
    };
    std::size_t Index(const unsigned char* key, std::size_t row) const;
    static void Insert(Bucket& bucket, const unsigned char* key, std::uint32_t window);
    std::size_t RandomRow();
    double RandomUnit();

    std::size_t depth_, width_;
    Variant variant_;
    double alpha_;
    std::uint64_t seed_;
    std::mt19937_64 rng_;
    std::vector<Bucket> buckets_;
    val_tp packet_count_ = 0;
    std::uint32_t current_window_ = 1;
};
#endif
