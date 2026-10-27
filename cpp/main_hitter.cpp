#include "Pallas.hpp"
#include "adaptor.hpp"
#include <chrono>
#include <cmath>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <string>

namespace {
struct Options {
    std::uint64_t memory_kb = 64, windows = 1500, seed = 42, buffer_mb = 1024;
    int rows = 2;
    double gamma = 0.4, alpha = 0.11;
    std::string traces = "iptraces.txt", format = "pcap", variant = "both";
};
std::uint64_t Number(const std::string& text) {
    if (text.empty() || text.find_first_not_of("0123456789") != std::string::npos)
        throw std::invalid_argument("expected an unsigned integer: " + text);
    std::size_t end;
    const auto value = std::stoull(text, &end);
    if (end != text.size()) throw std::invalid_argument("invalid integer: " + text);
    return value;
}
double Real(const std::string& text) {
    std::size_t end;
    const double value = std::stod(text, &end);
    if (end != text.size() || !std::isfinite(value))
        throw std::invalid_argument("invalid finite number: " + text);
    return value;
}
void Usage() {
    std::cout << "Usage: ./main_hitter [--memory-kb 64] [--rows 2] [--windows 1500]\n"
        "  [--gamma 0.4] [--alpha 0.11] [--seed 42] [--variant both|pallas|opt]\n"
        "  [--traces iptraces.txt] [--format pcap|text] [--buffer-mb 1024]\n"
        "No arguments: read memory budget in KiB from standard input.\n";
}
Options Parse(int argc, char** argv) {
    Options options;
    if (argc == 1) {
        std::string memory;
        if (!(std::cin >> memory)) throw std::invalid_argument("expected memory budget in KiB");
        options.memory_kb = Number(memory);
    }
    for (int i = 1; i < argc; ++i) {
        const std::string arg(argv[i]);
        if (++i == argc) throw std::invalid_argument("missing value for " + arg);
        const std::string value(argv[i]);
        if (arg == "--memory-kb") options.memory_kb = Number(value);
        else if (arg == "--windows") options.windows = Number(value);
        else if (arg == "--seed") options.seed = Number(value);
        else if (arg == "--buffer-mb") options.buffer_mb = Number(value);
        else if (arg == "--rows") {
            const auto rows = Number(value);
            if (rows > std::uint64_t(std::numeric_limits<int>::max()))
                throw std::invalid_argument("too many rows");
            options.rows = static_cast<int>(rows);
        } else if (arg == "--gamma") options.gamma = Real(value);
        else if (arg == "--alpha") options.alpha = Real(value);
        else if (arg == "--variant") options.variant = value;
        else if (arg == "--traces") options.traces = value;
        else if (arg == "--format") options.format = value;
        else throw std::invalid_argument("unknown option: " + arg);
    }
    if (!options.memory_kb || options.memory_kb > std::numeric_limits<std::size_t>::max()/1024 ||
        !options.windows || options.windows > std::numeric_limits<std::uint32_t>::max() ||
        options.rows <= 0 || options.gamma <= 0 || options.gamma > 1 || options.alpha <= 0 ||
        !options.buffer_mb || options.buffer_mb > std::numeric_limits<std::uint64_t>::max()/1048576)
        throw std::invalid_argument("invalid memory, row, window, probability or buffer settings");
    if (options.variant != "both" && options.variant != "pallas" && options.variant != "opt")
        throw std::invalid_argument("variant must be both, pallas or opt");
    if (options.format != "text" && options.format != "pcap")
        throw std::invalid_argument("format must be text or pcap");
    return options;
}

struct Truth { val_tp count = 0; std::uint64_t last = 0; };
using Ground = std::unordered_map<key_tp, Truth, key_tp_hash, key_tp_eq>;
using Clock = std::chrono::steady_clock;

void Evaluate(const Options& o, const std::vector<tuple_t>& data, const Ground& truth,
              std::uint64_t window_length, val_tp threshold, int width,
              Pallas::Variant variant) {
    Pallas sketch(o.rows, width, 8 * LGN, variant, o.alpha, o.seed);
    auto start = Clock::now();
    for (std::size_t i = 0; i < data.size(); ++i) {
        if (i && i % window_length == 0) sketch.NewWindow();
        sketch.Update(data[i].key.key, data[i].size);
    }
    const double update_seconds = std::chrono::duration<double>(Clock::now() - start).count();
    myvector results;
    start = Clock::now();
    sketch.Query(threshold, results);
    const double query_seconds = std::chrono::duration<double>(Clock::now() - start).count();
    std::size_t positives = 0, true_positives = 0;
    double absolute_error = 0, relative_error = 0;
    for (const auto& pair : truth) {
        if (pair.second.count < threshold) continue;
        ++positives;
        const double error = std::abs(double(pair.second.count) -
                                      double(sketch.PointQuery(pair.first.key)));
        absolute_error += error;
        relative_error += error / double(pair.second.count);
    }
    for (const auto& result : results) {
        const auto it = truth.find(result.first);
        if (it != truth.end() && it->second.count >= threshold) ++true_positives;
    }
    const double precision = results.empty() ? 0.0 : double(true_positives) / results.size();
    const double recall = positives ? double(true_positives) / positives : 0.0;
    const double f1 = precision + recall ? 2 * precision * recall / (precision + recall) : 0.0;
    std::cout << (variant == Pallas::Variant::Basic ? "PALLAS" : "OPT-PALLAS")
        << ',' << positives << ',' << results.size() << ',' << true_positives
        << ',' << precision << ',' << recall << ',' << f1
        << ',' << (positives ? absolute_error / positives : 0.0)
        << ',' << (positives ? relative_error / positives : 0.0)
        << ',' << (update_seconds > 0 ? data.size() / update_seconds / 1e6 : 0.0)
        << ',' << query_seconds * 1000 << ',' << sketch.MemoryBytes() << '\n';
}
}

int main(int argc, char** argv) {
    try {
        if (argc == 2 && std::string(argv[1]) == "--help") { Usage(); return 0; }
        const auto o = Parse(argc, argv);
        const auto width64 = o.memory_kb * 1024 / Pallas::BucketBytes() / o.rows;
        if (!width64 || width64 > std::uint64_t(std::numeric_limits<int>::max()))
            throw std::invalid_argument("memory budget cannot represent a valid width");
        std::ifstream list(o.traces);
        if (!list) throw std::runtime_error("cannot open trace list: " + o.traces);
        std::size_t files = 0;
        for (std::string file; std::getline(list, file);) {
            const auto first = file.find_first_not_of(" \t\r");
            if (first == std::string::npos || file[first] == '#') continue;
            file = file.substr(first, file.find_last_not_of(" \t\r") - first + 1);
            Adaptor adaptor(file, o.buffer_mb * 1048576, o.format);
            const auto& data = adaptor.Data();
            if (data.empty()) throw std::runtime_error("no valid IPv4 packets: " + file);
            // Fixed-size windows, including the last partial window. No packet is skipped.
            const std::uint64_t length = data.size() / o.windows + (data.size() % o.windows != 0);
            const std::uint64_t windows = data.size() / length + (data.size() % length != 0);
            const val_tp threshold = static_cast<val_tp>(std::ceil(o.gamma * windows));
            Ground truth;
            for (std::size_t i = 0; i < data.size(); ++i) {
                auto& item = truth[data[i].key];
                const std::uint64_t window = i / length + 1;
                if (item.last != window) { ++item.count; item.last = window; }
            }
            std::cout << "# Dataset: " << file << "; packets=" << data.size()
                << "; flows=" << truth.size() << "; requested_windows=" << o.windows
                << "; actual_windows=" << windows << "; packets_per_window=" << length
                << "; threshold=" << threshold << "; rows=" << o.rows
                << "; width=" << width64 << "; bucket_bytes=" << Pallas::BucketBytes() << '\n';
            std::cout << "Sketch,GroundTruth,Reported,TruePositives,Precision,Recall,F1,"
                         "AAE,ARE,UpdateMpps,QueryMs,BucketMemoryBytes\n" << std::setprecision(9);
            if (o.variant != "opt") Evaluate(o, data, truth, length, threshold,
                static_cast<int>(width64), Pallas::Variant::Basic);
            if (o.variant != "pallas") Evaluate(o, data, truth, length, threshold,
                static_cast<int>(width64), Pallas::Variant::Optimized);
            ++files;
        }
        if (list.bad()) throw std::runtime_error("cannot read trace list");
        if (!files) throw std::runtime_error("trace list is empty");
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << '\n';
        return 1;
    }
}
