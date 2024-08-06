#ifndef CVEINFO_INCLUDE_CVEINFO_UTILS_JSON_HPP_
#define CVEINFO_INCLUDE_CVEINFO_UTILS_JSON_HPP_

#include <nlohmann/json.hpp>

#include <string>

namespace cveinfo::utils {

template <typename T>
static std::optional<T> getAs(const nlohmann::json& object, const std::string& path) {
    try {
        return object.at(nlohmann::json::json_pointer(path)).get<T>();
    } catch (...) {
    }
    return std::nullopt;
}

} // namespace cveinfo::utils

#endif // CVEINFO_INCLUDE_CVEINFO_UTILS_JSON_HPP_
