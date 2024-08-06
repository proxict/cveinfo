#ifndef CVEINFO_INCLUDE_CVEINFO_CVE_NIST_HPP_
#define CVEINFO_INCLUDE_CVEINFO_CVE_NIST_HPP_

#include <optional>
#include <string>

namespace cveinfo::nist {

struct CveDescription {
    std::string cveId;
    std::optional<std::string> description;
    std::optional<std::string> vectorString;
    std::optional<std::string> severity;
    std::optional<float> score;
};

std::optional<CveDescription> getCveDescription(const std::string& cveId,
                                                const std::optional<std::string>& apiKey = std::nullopt);

} // namespace cveinfo::nist

#endif // CVEINFO_INCLUDE_CVEINFO_CVE_NIST_HPP_
