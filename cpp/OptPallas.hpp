#ifndef OPT_PALLAS_HPP
#define OPT_PALLAS_HPP
#include "Pallas.hpp"

// Same Update/PointQuery/Query/NewWindow interface as the basic variant.
class OptPallas : public Pallas {
public:
    OptPallas(int depth, int width, int lgn = 8 * LGN,
              double alpha = 0.11, std::uint64_t seed = 42)
        : Pallas(depth, width, lgn, Variant::Optimized, alpha, seed) {}
};
#endif
