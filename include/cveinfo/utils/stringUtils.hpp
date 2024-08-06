#ifndef CVEINFO_INCLUDE_CVEINFO_UTILS_STRINGUTILS_HPP_
#define CVEINFO_INCLUDE_CVEINFO_UTILS_STRINGUTILS_HPP_

#include "cveinfo/typeTraits.hpp"

#include <string>

namespace cveinfo::utils {

enum class TokenizeMode {
    INCLUDE_EMPTY_TOKENS,
    EXCLUDE_EMPTY_TOKENS,
};

inline std::vector<std::string> tokenize(const std::string& str,
                                         const std::string& delimiter,
                                         const TokenizeMode mode = TokenizeMode::INCLUDE_EMPTY_TOKENS) {
    if (str.empty()) {
        return mode == TokenizeMode::EXCLUDE_EMPTY_TOKENS ? std::vector<std::string>{}
                                                          : std::vector<std::string>({ str });
    }
    if (delimiter.empty()) {
        return { str };
    }
    std::vector<std::string> tokens;
    std::size_t last = 0;
    for (std::size_t next = 0; (next = str.find(delimiter, last)) != std::string::npos;) {
        if (mode == TokenizeMode::INCLUDE_EMPTY_TOKENS || next > last) {
            tokens.emplace_back(str.substr(last, next - last));
        }
        last = next + delimiter.size();
    }
    if (mode == TokenizeMode::INCLUDE_EMPTY_TOKENS || last < str.size()) {
        tokens.emplace_back(str.substr(last));
    }
    return tokens;
}

template <typename TPredicate,
          typename...,
          typename std::enable_if<IsCallable<TPredicate, bool(char)>::value, int>::type = 1>
inline std::vector<std::string> tokenize(const std::string& str,
                                         const TPredicate& predicate,
                                         const TokenizeMode mode = TokenizeMode::INCLUDE_EMPTY_TOKENS) {
    if (str.empty()) {
        return mode == TokenizeMode::EXCLUDE_EMPTY_TOKENS ? std::vector<std::string>{}
                                                          : std::vector<std::string>({ str });
    }
    std::vector<std::string> tokens;
    auto last = std::begin(str);
    for (auto next = last; (next = std::find_if(last, std::end(str), predicate)) != std::end(str);) {
        if (mode == TokenizeMode::INCLUDE_EMPTY_TOKENS || next > last) {
            tokens.emplace_back(str.substr(static_cast<std::size_t>(std::distance(std::begin(str), last)),
                                           static_cast<std::size_t>(std::distance(last, next))));
        }
        last = next + 1;
    }
    if (mode == TokenizeMode::INCLUDE_EMPTY_TOKENS || last != std::end(str)) {
        tokens.emplace_back(str.substr(static_cast<std::size_t>(std::distance(std::begin(str), last))));
    }
    return tokens;
}

std::vector<std::string> inline tokenize(const std::string& s,
                                         const char delimiter,
                                         const TokenizeMode mode = TokenizeMode::INCLUDE_EMPTY_TOKENS) {
    return tokenize(
        s, [delimiter](const char c) { return c == delimiter; }, mode);
}

} // namespace cveinfo::utils

#endif // CVEINFO_INCLUDE_CVEINFO_UTILS_STRINGUTILS_HPP_
