#ifndef PALLAS_ADAPTOR_HPP
#define PALLAS_ADAPTOR_HPP
#include <cstddef>
#include <string>
#include <vector>
#include "datatypes.hpp"

class Adaptor {
public:
    // format is "text" or "pcap"; buffersize bounds accepted tuple payload, not capacity/RSS.
    explicit Adaptor(const std::string& filename,
                     std::uint64_t buffersize = UINT64_C(1073741824),
                     const std::string& format = "pcap");
    int GetNext(tuple_t* tuple);
    void Reset() { cursor_ = 0; }
    std::uint64_t GetDataSize() const { return data_.size(); }
    const std::vector<tuple_t>& Data() const { return data_; }
private:
    void Append(const tuple_t& tuple, std::uint64_t max_records);
    std::vector<tuple_t> data_;
    std::size_t cursor_ = 0;
};
#endif
