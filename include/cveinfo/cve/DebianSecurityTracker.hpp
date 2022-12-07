#ifndef CVEINFO_INCLUDE_CVEINFO_CVE_DEBIANSECURITYTRACKER_HPP_
#define CVEINFO_INCLUDE_CVEINFO_CVE_DEBIANSECURITYTRACKER_HPP_

#include "cveinfo/utils/utils.hpp"

#include <cpr/cpr.h>
#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include <filesystem>
#include <fstream>
#include <optional>

using json = nlohmann::json;

namespace cveinfo::debian {

namespace fs = std::filesystem;
using namespace std::chrono_literals;

class DebianSecurityTracker {
public:
    DebianSecurityTracker(std::string codename)
        : mCodename(std::move(codename))
        , mDbPath(utils::createCveInfoDir() / "debian-tracker.json")
        , mHasDb(true) {
        if (!updateDebianSecurityTrackerDb(mDbPath)) {
            if (!fs::exists(mDbPath)) {
                mHasDb = false;
            }
            spdlog::warn("Using local debian security tracker database from {}",
                         utils::lastWriteTime(mDbPath));
        }
    }

    const std::string& getCodename() const {
        return mCodename;
    }

    std::vector<std::pair<std::string, json>> getPackagesWithCVE(const std::string& cveId) const {
        if (!mHasDb) {
            return {};
        }
        std::vector<std::pair<std::string, json>> packages;
        try {
            const json debTrackerJson = json::parse(std::ifstream(mDbPath));

            for (auto package = std::begin(debTrackerJson); package != std::end(debTrackerJson); ++package) {
                package = std::find_if(package, std::end(debTrackerJson), [&cveId](const json& obj) {
                    return obj.find(cveId) != std::end(obj);
                });

                if (package != std::end(debTrackerJson)) {
                    packages.emplace_back(package.key(), *package);
                } else {
                    break;
                }
            }

            return packages;
        } catch (const std::exception& e) {
            spdlog::error(
                "Error occurred while searching for {} in the debian security tracker: {}", cveId, e.what());
            return {};
        }
    }

private:
    bool updateDebianSecurityTrackerDb(const fs::path& dbPath) const {
        try {
            if (!fs::exists(dbPath) || dbPath == utils::OlderThan(1h)) {
                spdlog::info("Downloading debian security tracker database...");
                cpr::Response r =
                    cpr::Get(cpr::Url{ "https://security-tracker.debian.org/tracker/data/json" },
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

    std::string mCodename;
    fs::path mDbPath;
    bool mHasDb;
};

} // namespace cveinfo::debian

#endif // CVEINFO_INCLUDE_CVEINFO_CVE_DEBIANSECURITYTRACKER_HPP_
