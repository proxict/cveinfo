#include "cveinfo/cve/DebianSecurityTracker.hpp"

#include "cveinfo/utils/json.hpp"
#include "cveinfo/utils/utils.hpp"

#include <cpr/cpr.h>
#include <spdlog/fmt/chrono.h>
#include <spdlog/spdlog.h>

#include <fstream>

using namespace std::chrono_literals;

using namespace cveinfo;
using debian::DebianSecurityTracker;
using debian::TrackerInfo;
using nlohmann::json;

DebianSecurityTracker::DebianSecurityTracker(std::optional<std::string> codename)
    : mCodename(std::move(codename)) {
    const auto dbPath = utils::createCveInfoDir() / "debian-tracker.json";
    if (!updateDebianSecurityTrackerDb(dbPath)) {
        if (!std::filesystem::exists(dbPath)) {
            throw std::system_error{ std::error_code{ ENOENT, std::system_category() }, dbPath };
        }
        mJsonDatabase = json::parse(std::ifstream(dbPath));
        spdlog::warn("Using local debian security tracker database from {}", utils::lastWriteTime(dbPath));
    } else {
        mJsonDatabase = json::parse(std::ifstream(dbPath));
    }
}

std::vector<TrackerInfo> DebianSecurityTracker::getTrackerInfo(const std::string& cveId) const {
    std::vector<TrackerInfo> infos;

    const auto addCodenameInfo = [](TrackerInfo& info, const json& releases, const std::string& codename) {
        if (const auto desiredRelease = utils::getAs<json>(releases, "/" + codename)) {
            auto status = utils::getAs<std::string>(*desiredRelease, "/status");
            auto fixedVersion = utils::getAs<std::string>(*desiredRelease, "/fixed_version");
            info.codenames.push_back(CodenameInfo{ codename, std::move(status), std::move(fixedVersion) });
        } else {
            spdlog::warn("Given Debian release not found: {}", codename);
        }
    };

    try {
        for (auto package = std::begin(mJsonDatabase); package != std::end(mJsonDatabase); ++package) {
            const auto& cveIt = package->find(cveId);
            if (cveIt == std::end(*package)) {
                continue;
            }

            const auto& cve = *cveIt;
            TrackerInfo info;
            info.packageName = package.key();
            info.cveId = cveId;

            if (const auto releases = utils::getAs<json>(cve, "/releases")) {
                if (mCodename) {
                    addCodenameInfo(info, *releases, *mCodename);
                } else {
                    for (auto codename = std::begin(*releases); codename != std::end(*releases); ++codename) {
                        addCodenameInfo(info, *releases, codename.key());
                    }
                }
            }
            infos.push_back(std::move(info));
        }

        return infos;
    } catch (const std::exception& e) {
        spdlog::error(
            "Error occurred while searching for {} in the debian security tracker: {}", cveId, e.what());
        return {};
    }
}

bool DebianSecurityTracker::updateDebianSecurityTrackerDb(const std::filesystem::path& dbPath) const {
    try {
        if (!std::filesystem::exists(dbPath) || dbPath == utils::OlderThan(1h)) {
            spdlog::info("Downloading debian security tracker database...");
            cpr::Response r = cpr::Get(cpr::Url{ "https://security-tracker.debian.org/tracker/data/json" },
                                       cpr::VerifySsl{ false });
            if (r.status_code != 200) {
                spdlog::error("Failed to download debian security tracker database ({}): {}",
                              r.status_code,
                              r.error.message);
                return false;
            }
            return bool(std::ofstream(dbPath) << r.text);
        }
        return true;
    } catch (const std::exception& e) {
        spdlog::error("Failed to update debian security tracker database: {}", e.what());
        return false;
    }
}
