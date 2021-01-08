/*!
 * @file
 * @brief Вспомогательные средства для упрощения работы с std::variant.
 */

#pragma once

#include <variant>

namespace arataga::utils
{

//
// overloaded
//
// Взято отсюда: https://en.cppreference.com/w/cpp/utility/variant/visit
template<class... Ts> struct overloaded : Ts... { using Ts::operator()...; };
template<class... Ts> overloaded(Ts...) -> overloaded<Ts...>;

} /* namespace arataga::utils */

