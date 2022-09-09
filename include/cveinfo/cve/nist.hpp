#ifndef CVEINFO_INCLUDE_CVEINFO_CVE_NIST_HPP_
#define CVEINFO_INCLUDE_CVEINFO_CVE_NIST_HPP_

#include "cveinfo/utils/utils.hpp"

#include <cpr/cpr.h>
#include <spdlog/spdlog.h>

#include <fstream>
#include <optional>

namespace cveinfo::nist {

using CveInfo = std::optional<json>;
namespace fs = std::filesystem;
using namespace std::chrono_literals;

namespace detail {
    inline std::nullopt_t handleNonOkStatusCode(long code, const std::string& cveId) {
        switch (code) {
        case 403:
            spdlog::error("{} - request forbidden: try limiting the request frequency", cveId);
            return std::nullopt;
        case 404:
            spdlog::error("{} not found in the NIST database", cveId);
            return std::nullopt;
        case 503:
            spdlog::error("Couldn't retrieve infornation about {} - NIST database temporarily unavailable",
                          cveId);
            return std::nullopt;
        case 500:
            spdlog::error(
                "Couldn't retrieve infornation about {} - internal server error in the NIST database", cveId);
            return std::nullopt;
        default:
            spdlog::error("Couldn't retrieve infornation about {} - status code {}", cveId, code);
            return std::nullopt;
        }
    }

    inline std::optional<std::string> fetchFromNist(const std::string& cveId) {
        try {
            int attempts = 3;
            cpr::Response r;
            while (attempts-- > 0) {
                r = cpr::Get(cpr::Url{ "https://services.nvd.nist.gov/rest/json/cve/1.0/" + cveId },
                             cpr::VerifySsl{ false });
                // If the response is "forbidden", it probably means we're sending too many requests.
                // Let's wait for a bit before issuing another request.
                if (r.status_code == 403) {
                    std::this_thread::sleep_for(5s * (3 - attempts));
                    continue;
                }
                if (r.status_code != 200) {
                    return handleNonOkStatusCode(r.status_code, cveId);
                }
                return r.text;
            }
            return handleNonOkStatusCode(r.status_code, cveId);
        } catch (const std::exception& e) {
            spdlog::error("Couldn't retrieve infornation about {} - {}", cveId, e.what());
            return std::nullopt;
        }
    }

} // namespace detail

inline CveInfo getCveInfo(const std::string& cveId) {
    try {
        const fs::path cachedFile = utils::createCveInfoDir() / cveId;
        const bool exists = fs::exists(cachedFile);
        if (!exists || cachedFile == utils::OlderThan(1h)) {
            const auto jsonBody = detail::fetchFromNist(cveId);
            if (jsonBody) {
                if (!(std::ofstream(cachedFile) << *jsonBody)) {
                    spdlog::warn("Failed to cache {} to {}", cveId, cachedFile.string());
                }
                return json::parse(*jsonBody);
            }
        }
        if (!exists) {
            return std::nullopt;
        }
        if (cachedFile == utils::OlderThan(1h)) {
            spdlog::warn("Using local cache from {} for {}", utils::lastWriteTime(cachedFile), cveId);
        }
        return json::parse(std::ifstream(cachedFile));
    } catch (const std::exception& e) {
        spdlog::error("Couldn't retrieve infornation about {} - {}", cveId, e.what());
        return std::nullopt;
    }
}

struct CveDescription {
    std::string cveId;
    std::optional<std::string> description;
    std::optional<std::string> vectorString;
    std::optional<std::string> severity;
    std::optional<float> score;
};

inline std::optional<CveDescription> getCveDescription(const std::string& cveId) {
    const CveInfo cveInfo = getCveInfo(cveId);
    if (!cveInfo) {
        return std::nullopt;
    }
    try {
        const json cveInfoJson = (*cveInfo)["result"]["CVE_Items"][0];
        CveDescription desc;
        desc.cveId = cveId;
        desc.description =
            utils::jsonGet<std::string>(cveInfoJson, "cve.description.description_data[0].value");

        if (const auto cvssJson = utils::jsonGet<json>(cveInfoJson, "impact.baseMetricV3.cvssV3"); cvssJson) {
            desc.vectorString = utils::jsonGet<std::string>(*cvssJson, "vectorString");
            desc.severity = utils::jsonGet<std::string>(*cvssJson, "baseSeverity");
            desc.score = utils::jsonGet<float>(*cvssJson, "baseScore");
        }
        return desc;
    } catch (const std::exception& e) {
        spdlog::error("Failed to get {} info: {}", cveId, e.what());
        return std::nullopt;
    }
}

} // namespace cveinfo::nist

#endif // CVEINFO_INCLUDE_CVEINFO_CVE_NIST_HPP_
