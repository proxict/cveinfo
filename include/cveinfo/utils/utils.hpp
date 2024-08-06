#ifndef CVEINFO_INCLUDE_CVEINFO_UTILS_UTILS_HPP_
#define CVEINFO_INCLUDE_CVEINFO_UTILS_UTILS_HPP_

#include "cveinfo/typeTraits.hpp"
#include "cveinfo/utils/stringUtils.hpp"

#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <limits>
#include <optional>
#include <string>
#include <sys/stat.h>

namespace cveinfo::utils {

inline std::filesystem::path getCacheDirectory() {
    char* cacheEnv = getenv("XDG_CACHE_HOME");
    if (cacheEnv) {
        return cacheEnv;
    }
    char* homeEnv = getenv("HOME");
    if (homeEnv) {
        return std::filesystem::path(homeEnv) / ".cache/";
    }
    return std::filesystem::temp_directory_path();
}

inline std::filesystem::path createCveInfoDir() {
    const std::filesystem::path dir = utils::getCacheDirectory() / "cveinfo";
    if (!std::filesystem::exists(dir)) {
        std::filesystem::create_directories(dir);
    }
    return dir;
}

inline std::chrono::system_clock::time_point lastWriteTime(const std::filesystem::path& p) {
    struct stat buf;
    if (stat(p.c_str(), &buf) != 0) {
        return std::numeric_limits<std::chrono::system_clock::time_point>::min();
    }
    return std::chrono::system_clock::from_time_t(time_t(buf.st_mtim.tv_sec));
}

template <typename TRep, typename TPeriod>
inline bool isOlderThan(const std::filesystem::path& p,
                        const std::chrono::duration<TRep, TPeriod>& duration) {
    return std::chrono::system_clock::now() - utils::lastWriteTime(p) > duration;
}

struct OlderThan {
    template <typename TRep, typename TPeriod>
    OlderThan(const std::chrono::duration<TRep, TPeriod>& d)
        : duration(std::chrono::duration_cast<std::chrono::milliseconds>(d)) {}
    std::chrono::milliseconds duration;
};

} // namespace cveinfo::utils

namespace cveinfo {

inline bool operator==(const std::filesystem::path& p, const utils::OlderThan& duration) {
    return utils::isOlderThan(p, duration.duration);
}

} // namespace cveinfo

#endif // CVEINFO_INCLUDE_CVEINFO_UTILS_UTILS_HPP_
