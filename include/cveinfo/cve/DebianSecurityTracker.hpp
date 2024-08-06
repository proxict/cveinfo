#ifndef CVEINFO_INCLUDE_CVEINFO_CVE_DEBIANSECURITYTRACKER_HPP_
#define CVEINFO_INCLUDE_CVEINFO_CVE_DEBIANSECURITYTRACKER_HPP_

#include <nlohmann/json.hpp>

#include <filesystem>
#include <optional>
#include <string>

namespace cveinfo::debian {

struct CodenameInfo {
    std::string name;
    std::optional<std::string> status;
    std::optional<std::string> fixedVersion;
};

struct TrackerInfo {
    std::string packageName;
    std::string cveId;
    std::vector<CodenameInfo> codenames;
};

class DebianSecurityTracker {
public:
    DebianSecurityTracker(std::optional<std::string> codename);

    std::vector<TrackerInfo> getTrackerInfo(const std::string& cveId) const;

private:
    bool updateDebianSecurityTrackerDb(const std::filesystem::path& dbPath) const;

    std::optional<std::string> mCodename;
    nlohmann::json mJsonDatabase;
};

} // namespace cveinfo::debian

#endif // CVEINFO_INCLUDE_CVEINFO_CVE_DEBIANSECURITYTRACKER_HPP_
