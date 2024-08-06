#ifndef CVEINFO_INCLUDE_CVEINFO_TYPETRAITS_HPP_
#define CVEINFO_INCLUDE_CVEINFO_TYPETRAITS_HPP_

#include <functional>
#include <type_traits>

namespace cveinfo {

template <typename T, typename TSignature>
struct IsCallable;

template <typename T, typename TRet, class... TArgs>
struct IsCallable<T, TRet(TArgs...)>
    : std::conditional<std::is_assignable<std::function<TRet(TArgs...)>, T>::value,
                       std::true_type,
                       std::false_type>::type {};

} // namespace cveinfo

#endif // CVEINFO_INCLUDE_CVEINFO_TYPETRAITS_HPP_
