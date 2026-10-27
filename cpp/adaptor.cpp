#include "adaptor.hpp"
#include <arpa/inet.h>
#include <fstream>
#include <memory>
#include <sstream>
#include <stdexcept>
#ifdef WITH_PCAP
#include <pcap/pcap.h>
#endif

namespace {
#ifdef WITH_PCAP
unsigned Read16(const unsigned char* p) { return (unsigned(p[0]) << 8) | p[1]; }
// Read only the IPv4 pair; transport headers need not be captured.
bool Decode(const unsigned char* p, std::size_t n, int link, tuple_t& tuple) {
    std::size_t offset = 0;
    if (link == DLT_EN10MB) {
        if (n < 14) return false;
        unsigned type = Read16(p + 12);
        offset = 14;
        while (type == 0x8100 || type == 0x88a8) {
            if (n - offset < 4) return false;
            type = Read16(p + offset + 2);
            offset += 4;
        }
        if (type != 0x0800) return false;
    } else if (link == DLT_LINUX_SLL) {
        if (n < 16 || Read16(p + 14) != 0x0800) return false;
        offset = 16;
#ifdef DLT_LINUX_SLL2
    } else if (link == DLT_LINUX_SLL2) {
        if (n < 20 || Read16(p) != 0x0800) return false;
        offset = 20;
#endif
    } else if (link != DLT_RAW) {
        throw std::runtime_error("unsupported pcap link type: " + std::to_string(link));
    }
    if (n - offset < 20) return false;
    p += offset;
    const unsigned header = (p[0] & 15) * 4;
    if ((p[0] >> 4) != 4 || header < 20 || n - offset < header) return false;
    if (Read16(p + 2) < header) return false;
    std::memcpy(tuple.key.key, p + 12, LGN);
    tuple.size = static_cast<std::uint16_t>(Read16(p + 2));
    return true;
}
#endif
}

void Adaptor::Append(const tuple_t& tuple, std::uint64_t max_records) {
    if (data_.size() >= max_records)
        throw std::length_error("trace exceeds tuple storage budget (--buffer-mb)");
    data_.push_back(tuple);
}

Adaptor::Adaptor(const std::string& filename, std::uint64_t buffersize,
                 const std::string& format) {
    const auto max_records = buffersize / sizeof(tuple_t);
    if (format == "text") {
        std::ifstream input(filename);
        if (!input) throw std::runtime_error("cannot open trace: " + filename);
        std::string line;
        std::size_t line_number = 0;
        while (std::getline(input, line)) {
            ++line_number;
            line = line.substr(0, line.find('#'));
            std::istringstream fields(line);
            std::string src, dst, extra;
            if (!(fields >> src)) continue;
            tuple_t tuple;
            if (!(fields >> dst) || fields >> extra ||
                inet_pton(AF_INET, src.c_str(), tuple.key.key) != 1 ||
                inet_pton(AF_INET, dst.c_str(), tuple.key.key + 4) != 1)
                throw std::runtime_error("invalid IPv4 pair at " + filename + ":" +
                                         std::to_string(line_number));
            Append(tuple, max_records);
        }
        if (input.bad()) throw std::runtime_error("trace read failed: " + filename);
    } else if (format == "pcap") {
#ifdef WITH_PCAP
        char error[PCAP_ERRBUF_SIZE] = {};
        std::unique_ptr<pcap_t, decltype(&pcap_close)> input(
            pcap_open_offline(filename.c_str(), error), &pcap_close);
        if (!input) throw std::runtime_error("cannot open pcap: " + std::string(error));
        const int link = pcap_datalink(input.get());
        pcap_pkthdr* header;
        const unsigned char* bytes;
        int status;
        while ((status = pcap_next_ex(input.get(), &header, &bytes)) >= 0) {
            if (status == 0) continue;
            tuple_t tuple;
            if (Decode(bytes, header->caplen, link, tuple)) Append(tuple, max_records);
        }
        if (status == -1) throw std::runtime_error(pcap_geterr(input.get()));
#else
        throw std::runtime_error("pcap support disabled; rebuild with make WITH_PCAP=1");
#endif
    } else {
        throw std::invalid_argument("format must be text or pcap");
    }
}

int Adaptor::GetNext(tuple_t* tuple) {
    if (!tuple) throw std::invalid_argument("null output tuple");
    if (cursor_ == data_.size()) return -1;
    *tuple = data_[cursor_++];
    return 1;
}
