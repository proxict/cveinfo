#ifndef CVEINFO_INCLUDE_CVEINFO_UTILS_UTILS_HPP_
#define CVEINFO_INCLUDE_CVEINFO_UTILS_UTILS_HPP_

#include "cveinfo/typeTraits.hpp"
#include "cveinfo/utils/stringUtils.hpp"

#include <nlohmann/json.hpp>

#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <limits>
#include <optional>
#include <string>
#include <sys/stat.h>

using json = nlohmann::json;

namespace cveinfo::utils {

template <typename T, typename..., typename std::enable_if<std::is_integral_v<T>, bool>::type = 1>
inline std::optional<T> parse(const std::string& str) {
    try {
        std::size_t idx = 0;
        if constexpr (std::is_unsigned_v<T>) {
            if (const uint64_t num = std::stoull(str, &idx);
                idx == str.size() && num <= std::numeric_limits<T>::max()) {
                return num;
            }
        } else {
            if (const int64_t num = std::stoll(str, &idx); idx == str.size() &&
                                                           num >= std::numeric_limits<T>::min() &&
                                                           num <= std::numeric_limits<T>::max()) {
                return num;
            }
        }
    } catch (...) {
    }
    return std::nullopt;
}

template <typename T>
inline std::optional<T> jsonGet(const json& j, const std::string& key) {
    try {
        json res = j;
        for (const std::string& k : utils::tokenize(key, '.')) {
            if (std::size_t arrayPos = k.rfind('['); arrayPos != std::string::npos) {
                if (k.size() < 3 || arrayPos >= k.size() - 2 || k.back() != ']') {
                    return std::nullopt;
                }
                std::string arrayIndex = k.substr(arrayPos + 1);
                arrayIndex.pop_back();
                if (const auto idx = utils::parse<uint64_t>(arrayIndex); idx) {
                    res = res[k.substr(0, arrayPos)][*idx];
                } else {
                    return std::nullopt;
                }
            } else {
                res = res[k];
            }
        }
        return res.get<T>();
    } catch (...) {
        return std::nullopt;
    }
}

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
