#include "cveinfo/cve/DebianSecurityTracker.hpp"
#include "cveinfo/cve/nist.hpp"

#include <spdlog/fmt/bundled/color.h>
#include <spdlog/fmt/chrono.h>
#include <spdlog/fmt/fmt.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>

#include <optional>
#include <stdio.h>
#include <string_view>
#include <unistd.h>

namespace {

static std::string formatSeverity(const std::string& severity) {
    if (isatty(fileno(stdout))) {
        fmt::text_style style;
        if (severity == "LOW") {
            style = fg(fmt::color::green);
        } else if (severity == "MEDIUM") {
            style = fg(fmt::color::orange);
        } else if (severity == "HIGH") {
            style = fg(fmt::color::red);
        } else if (severity == "CRITICAL") {
            style = fmt::emphasis::bold | fg(fmt::color::red);
        }
        return fmt::format(style, "{}", severity);
    } else {
        return fmt::format("{}", severity);
    }
}

void print(const cveinfo::nist::CveDescription& description, bool no_cvss) {
    if (isatty(fileno(stdout))) {
        fmt::print(fmt::emphasis::underline | fg(fmt::color::cyan), "{}:", description.cveId);
    } else {
        fmt::print("{}:", description.cveId);
    }
    if (description.severity) {
        fmt::print(" {}\n", formatSeverity(*description.severity));
    } else {
        fmt::print("\n");
    }

    if (description.description) {
        fmt::print("  {}\n\n", *description.description);
    }

    if (!no_cvss && (description.vectorString || description.severity || description.score)) {
        fmt::print("CVSS:\n");
        if (description.vectorString) {
            fmt::print("  {}\n", *description.vectorString);
        }
        if (description.severity) {
            fmt::print("  Severity: {}\n", formatSeverity(*description.severity));
        }
        if (description.score) {
            fmt::print("  Score: {}\n", *description.score);
        }
    }
}

void print(const cveinfo::debian::DebianSecurityTracker& tracker,
           const std::string& cveId,
           const std::optional<std::string>& name) {
    const auto printPackage = [](const cveinfo::debian::TrackerInfo& info) {
        fmt::println("  Package: {}", info.packageName);
        for (const auto& codename : info.codenames) {
            fmt::println("    {}:", codename.name);
            if (codename.status) {
                fmt::println("      Status: {}", *codename.status);
            }
            if (codename.fixedVersion) {
                fmt::println("      Fixed version: {}", *codename.fixedVersion);
            }
        }
    };
    try {
        const auto packages = tracker.getTrackerInfo(cveId);
        if (name && packages.size() > 1) {
            // Try finding exact match
            auto it =
                std::find_if(std::begin(packages), std::end(packages), [name = *name](const auto& package) {
                    return package.packageName == name;
                });

            // Try finding given package name in debian's package name
            if (it == std::end(packages)) {
                it = std::find_if(
                    std::begin(packages), std::end(packages), [name = *name](const auto& package) {
                        return package.packageName.find(name) != std::string::npos;
                    });
                if (it != std::end(packages)) {
                    spdlog::warn("Given CVE ID {} matching package name only partially: {} ~= {}",
                                 cveId,
                                 *name,
                                 it->packageName);
                }
            }

            // Try finding debian's package name in given package's name
            if (it == std::end(packages)) {
                it = std::find_if(
                    std::begin(packages), std::end(packages), [name = *name](const auto& package) {
                        return name.find(package.packageName) != std::string::npos;
                    });
                if (it != std::end(packages)) {
                    spdlog::warn("Given CVE ID {} matching package name only partially: {} ~= {}",
                                 cveId,
                                 it->packageName,
                                 *name);
                }
            }

            if (it != std::end(packages)) {
                printPackage(*it);
            } else {
                spdlog::error("Given CVE ID {} not found in the given package", cveId, *name);
            }
        } else {
            for (const auto& info : packages) {
                printPackage(info);
            }
        }
    } catch (const std::exception& e) {
        spdlog::error("Failed to print debian tracker info: {}", e.what());
    }
}

} // namespace

static void printUsage(const char* progname) {
    using namespace fmt::literals;
    fmt::print(stderr,
               R"usg({b}Usage{r}: {b}{progname}{r} [OPTIONS] <CVE ID> [package-name]

{b}OPTIONS{r}:
  {b}-h{r}, {b}--help{r}                  Print this help message and exit
  {b}-v{r}, {b}--no-cvss{r}               Don't print CVSS vector
  {b}-c{r}, {b}--codename{r} {b}<codename>{r}   Use specific debian codename
  {b}-k{r}, {b}--api-key{r} {b}<API KEY>{r}     NIST NVD API-key
)usg",
               "progname"_a = progname,
               "b"_a = "[1m",
               "r"_a = "[0m");
}

int main(const int argc, const char** argv) {
    auto logger =
        std::make_shared<spdlog::logger>("logger", std::make_shared<spdlog::sinks::stderr_color_sink_mt>());
    logger->set_level(spdlog::level::info);
    static constexpr auto LOGGER_FORMAT = "[%^%l%$] %v";
    logger->set_pattern(LOGGER_FORMAT);
    spdlog::set_default_logger(logger);

    using namespace std::string_literals;
    bool no_cvss = false;
    std::optional<std::string> codename;
    std::optional<std::string> apiKey;
    int parsed = 0;
    for (int i = 1; i < argc; ++i) {
        if (*argv[i] != '-') {
            break;
        }
        if (argv[i] == "-h"s || argv[i] == "--help"s) {
            printUsage(argc > 0 ? basename(argv[0]) : "cveinfo");
            return 0;
        }
        if (argv[i] == "-v"s || argv[i] == "--no-cvss"s) {
            ++parsed;
            no_cvss = true;
        } else if ((argv[i] == "-c"s || argv[i] == "--codename"s) && i + 1 < argc) {
            codename = argv[i + 1];
            parsed += 2;
            ++i;
        } else if ((argv[i] == "-k"s || argv[i] == "--api-key"s) && i + 1 < argc) {
            apiKey = argv[i + 1];
            parsed += 2;
            ++i;
        } else {
            spdlog::error("Unknown argument: {}", argv[i]);
            return 1;
        }
    }

    if (argc < parsed + 2) {
        printUsage(argc > 0 ? basename(argv[0]) : "cveinfo");
        return 1;
    }
    const std::string cveId = argv[parsed + 1];
    std::optional<std::string> packageName =
        argc > parsed + 2 ? std::optional(argv[parsed + 2]) : std::nullopt;

    const auto cveDescription = cveinfo::nist::getCveDescription(cveId, apiKey);
    if (!cveDescription) {
        return 1;
    }
    print(*cveDescription, no_cvss);
    print(cveinfo::debian::DebianSecurityTracker(codename), cveId, packageName);
}
