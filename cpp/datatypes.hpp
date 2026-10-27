#ifndef PALLAS_DATATYPES_HPP
#define PALLAS_DATATYPES_HPP

#include <cstdint>
#include <cstring>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>
#include "hash.hpp"

// Source and destination IPv4 addresses, in network byte order.
constexpr int LGN = 8;
struct key_tp { unsigned char key[LGN] = {}; };
using val_tp = std::uint64_t;
struct key_tp_hash {
    std::size_t operator()(const key_tp& k) const {
        return static_cast<std::size_t>(HashKey(k.key, LGN, 388650253));
    }
};
struct key_tp_eq {
    bool operator()(const key_tp& a, const key_tp& b) const {
        return std::memcmp(a.key, b.key, LGN) == 0;
    }
};
using myset = std::unordered_set<key_tp, key_tp_hash, key_tp_eq>;
using mymap = std::unordered_map<key_tp, val_tp, key_tp_hash, key_tp_eq>;
using myvector = std::vector<std::pair<key_tp, val_tp>>;
struct tuple_t { key_tp key; std::uint16_t size = 0; };
#endif
