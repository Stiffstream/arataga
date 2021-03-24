/*!
 * @file
 * @brief Helpers to simplify working with std::variant.
 */

#pragma once

#include <variant>

namespace arataga::utils
{

//
// overloaded
//
// Source: https://en.cppreference.com/w/cpp/utility/variant/visit
template<class... Ts> struct overloaded : Ts... { using Ts::operator()...; };
template<class... Ts> overloaded(Ts...) -> overloaded<Ts...>;

} /* namespace arataga::utils */

