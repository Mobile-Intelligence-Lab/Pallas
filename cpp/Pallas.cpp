#include "Pallas.hpp"
#include <algorithm>
#include <cmath>
#include <limits>
#include <stdexcept>

Pallas::Pallas(int depth, int width, int lgn, Variant variant, double alpha,
               std::uint64_t seed)
    : depth_(depth), width_(width), variant_(variant), alpha_(alpha),
      seed_(seed), rng_(seed) {
    if (depth <= 0 || width <= 0 || lgn != 8 * LGN)
        throw std::invalid_argument("depth and width must be positive; lgn must be 64");
    if (variant != Variant::Basic && variant != Variant::Optimized)
        throw std::invalid_argument("unknown PALLAS variant");
    if (!std::isfinite(alpha) || alpha <= 0)
        throw std::invalid_argument("alpha must be finite and positive");
    if (depth_ > buckets_.max_size() / width_)
        throw std::length_error("sketch dimensions are too large");
    buckets_.resize(depth_ * width_);
}

std::size_t Pallas::Index(const unsigned char* key, std::size_t row) const {
    return row * width_ + HashKey(key, LGN,
        UINT64_C(0x9e3779b97f4a7c15) * (row + 1)) % width_;
}

void Pallas::Insert(Bucket& b, const unsigned char* key, std::uint32_t window) {
    std::memcpy(b.key.key, key, LGN);
    b.persistence = 1;
    b.last_window = window;
}

std::size_t Pallas::RandomRow() {
    // Rejection avoids modulo bias and gives repeatable results across libraries.
    const auto bound = static_cast<std::uint64_t>(depth_);
    const auto reject_below = (std::uint64_t(0) - bound) % bound;
    std::uint64_t draw;
    do { draw = rng_(); } while (draw < reject_below);
    return static_cast<std::size_t>(draw % bound);
}

double Pallas::RandomUnit() {
    return static_cast<double>(rng_() >> 11) * (1.0 / 9007199254740992.0);
}

double Pallas::DecayProbability(Variant variant, std::uint32_t persistence,
                               std::uint32_t inactivity, double alpha) {
    if (persistence == 0 || inactivity == 0) return 0.0;
    if (variant == Variant::Basic) return 1.0 / (double(persistence) + 1.0);
    if (variant != Variant::Optimized || !std::isfinite(alpha) || alpha <= 0)
        throw std::invalid_argument("invalid decay parameters");
    return -std::expm1(-alpha * double(inactivity) / double(persistence));
}

void Pallas::Update(const unsigned char* key, val_tp value) {
    (void)value;
    if (!key) throw std::invalid_argument("null key");
    if (packet_count_ == std::numeric_limits<val_tp>::max())
        throw std::overflow_error("packet counter exhausted");
    ++packet_count_;
    for (std::size_t row = 0; row < depth_; ++row) {
        auto& b = buckets_[Index(key, row)];
        if (b.persistence == 0) {
            Insert(b, key, current_window_);
            return;
        }
        if (std::memcmp(b.key.key, key, LGN) == 0) {
            if (b.last_window < current_window_) {
                ++b.persistence; // At most current_window_, which cannot wrap.
                b.last_window = current_window_;
            }
            return;
        }
    }
    auto& candidate = buckets_[Index(key, RandomRow())];
    if (candidate.last_window == current_window_) return;
    const auto gap = current_window_ - candidate.last_window;
    if (RandomUnit() < DecayProbability(variant_, candidate.persistence, gap, alpha_)) {
        if (--candidate.persistence == 0) Insert(candidate, key, current_window_);
        // A decay without replacement does not update the incumbent's arrival window.
    }
}

val_tp Pallas::PointQuery(const unsigned char* key) const {
    if (!key) throw std::invalid_argument("null key");
    val_tp estimate = 0;
    for (std::size_t row = 0; row < depth_; ++row) {
        const auto& b = buckets_[Index(key, row)];
        if (b.persistence && std::memcmp(b.key.key, key, LGN) == 0)
            estimate = std::max(estimate, val_tp(b.persistence));
    }
    return estimate;
}

void Pallas::Query(val_tp threshold, myvector& results) const {
    results.clear();
    // A key can have stale copies in different rows after earlier-row eviction.
    // Collapse them using max, never sum estimates for the same flow.
    mymap candidates;
    for (const auto& b : buckets_) {
        if (b.persistence && b.persistence >= threshold) {
            auto& count = candidates[b.key];
            count = std::max(count, val_tp(b.persistence));
        }
    }
    results.assign(candidates.begin(), candidates.end());
    std::sort(results.begin(), results.end(), [](const myvector::value_type& a,
                                               const myvector::value_type& b) {
        return std::memcmp(a.first.key, b.first.key, LGN) < 0;
    });
}

void Pallas::NewWindow() {
    if (current_window_ == std::numeric_limits<std::uint32_t>::max())
        throw std::overflow_error("window counter exhausted; start a new experiment");
    ++current_window_;
}

void Pallas::Reset() {
    std::fill(buckets_.begin(), buckets_.end(), Bucket{});
    current_window_ = 1;
    packet_count_ = 0;
    rng_.seed(seed_);
}
