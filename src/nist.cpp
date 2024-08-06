#include "cveinfo/cve/nist.hpp"

#include "cveinfo/utils/json.hpp"
#include "cveinfo/utils/utils.hpp"

#include <cpr/cpr.h>
#include <nlohmann/json.hpp>
#include <spdlog/fmt/chrono.h>
#include <spdlog/spdlog.h>

#include <chrono>
#include <fstream>

using namespace std::chrono_literals;
using namespace cveinfo;
using nlohmann::json;

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
        spdlog::error("Couldn't retrieve infornation about {} - internal server error in the NIST database",
                      cveId);
        return std::nullopt;
    default:
        spdlog::error("Couldn't retrieve infornation about {} - status code {}", cveId, code);
        return std::nullopt;
    }
}

static std::optional<std::string> fetchFromNist(const std::string& cveId,
                                                const std::optional<std::string>& apiKey) {
    try {
        int attempts = 3;
        cpr::Response r;
        cpr::Header apiKeyHeader;
        if (apiKey) {
            apiKeyHeader.emplace("apiKey", *apiKey);
        }
        while (attempts-- > 0) {
            r = cpr::Get(cpr::Url{ "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=" + cveId },
                         cpr::VerifySsl{ false },
                         apiKeyHeader);

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

static std::optional<json> getCveInfo(const std::string& cveId, const std::optional<std::string>& apiKey) {
    try {
        const std::filesystem::path cachedFile = utils::createCveInfoDir() / cveId;
        const bool exists = std::filesystem::exists(cachedFile);
        if (!exists || cachedFile == utils::OlderThan(1h)) {
            const auto jsonBody = detail::fetchFromNist(cveId, apiKey);
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

std::optional<nist::CveDescription> nist::getCveDescription(const std::string& cveId,
                                                            const std::optional<std::string>& apiKey) {
    const auto cveInfo = getCveInfo(cveId, apiKey);
    if (!cveInfo) {
        return std::nullopt;
    }
    try {
        nist::CveDescription desc;
        desc.cveId = cveId;

        if (const auto cve = utils::getAs<json>(*cveInfo, "/vulnerabilities/0/cve")) {
            if (const auto cvssData = utils::getAs<json>(*cve, "/metrics/cvssMetricV31/0/cvssData")) {
                desc.vectorString = utils::getAs<std::string>(*cvssData, "/vectorString");
                desc.severity = utils::getAs<std::string>(*cvssData, "/baseSeverity");
                desc.score = utils::getAs<float>(*cvssData, "/baseScore");
            } else {
                spdlog::error("Failed to get CVSS for {}", cveId);
            }

            if (const auto descriptions = utils::getAs<json>(*cve, "/descriptions")) {
                for (const auto& description : *descriptions) {
                    if (auto lang = utils::getAs<std::string>(description, "/lang"); lang == "en") {
                        desc.description = utils::getAs<std::string>(description, "/value");
                    }
                }
            }
        } else {
            spdlog::error("Failed to get info for {}: CVE not found", cveId);
        }

        return desc;
    } catch (const std::exception& e) {
        spdlog::error("Failed to get {} info: {}", cveId, e.what());
        return std::nullopt;
    }
}
