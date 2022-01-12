#include "cveinfo/cve/DebianSecurityTracker.hpp"
#include "cveinfo/cve/nist.hpp"

#include <spdlog/fmt/bundled/color.h>
#include <spdlog/fmt/chrono.h>
#include <spdlog/fmt/fmt.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>

#include <optional>
#include <stdio.h>
#include <unistd.h>

namespace {

void print(const cveinfo::nist::CveDescription& description) {
    if (isatty(fileno(stdout))) {
        fmt::print(fmt::emphasis::underline | fg(fmt::color::cyan), "{}:\n", description.cveId);
    } else {
        fmt::print("{}:\n", description.cveId);
    }
    if (description.description) {
        fmt::print("  {}\n\n", *description.description);
    }
    if (description.vectorString || description.severity || description.score) {
        fmt::print("CVSS:\n");
        if (description.vectorString) {
            fmt::print("  {}\n", *description.vectorString);
        }
        if (description.severity) {
            fmt::print("  Severity: ");
            if (isatty(fileno(stdout))) {
                fmt::text_style style;
                if (*description.severity == "LOW") {
                    style = fg(fmt::color::green);
                } else if (*description.severity == "MEDIUM") {
                    style = fg(fmt::color::orange);
                } else if (*description.severity == "HIGH") {
                    style = fg(fmt::color::red);
                } else if (*description.severity == "CRITICAL") {
                    style = fmt::emphasis::bold | fg(fmt::color::red);
                }
                fmt::print(style, "{}", *description.severity);
            } else {
                fmt::print("{}", *description.severity);
            }
            fmt::print("\n");
        }
        if (description.score) {
            fmt::print("  Score: {}\n", *description.score);
        }
    }
}

void printTrackerInfo(const cveinfo::debian::DebianSecurityTracker& tracker, const std::string& cveId) {
    try {
        if (auto package = tracker.findCveInPackage(cveId); package) {
            const std::string packageName = package->first;
            const json releases = package->second[cveId]["releases"];
            fmt::print("  Package: {}\n", packageName);
            fmt::print("    bullseye:\n");
            fmt::print("      Status: {}\n", releases["bullseye"]["status"]);
            fmt::print("      Fixed version: {}\n", releases["bullseye"]["fixed_version"]);
        }
    } catch (...) {
    }
}

} // namespace

int main(const int argc, const char** argv) {
    auto logger =
        std::make_shared<spdlog::logger>("logger", std::make_shared<spdlog::sinks::stderr_color_sink_mt>());
    logger->set_level(spdlog::level::info);
    static constexpr auto LOGGER_FORMAT = "[%^%l%$] %v";
    logger->set_pattern(LOGGER_FORMAT);
    spdlog::set_default_logger(logger);

    if (argc < 2) {
        spdlog::error("Usage: {} <CVE ID>", argv[0]);
        return 1;
    }
    const std::string cveId = argv[1];

    const auto cveDescription = cveinfo::nist::getCveDescription(cveId);
    if (!cveDescription) {
        return 1;
    }
    print(*cveDescription);
    printTrackerInfo(cveinfo::debian::DebianSecurityTracker(), cveId);
}
