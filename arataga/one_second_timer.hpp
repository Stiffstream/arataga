/*!
 * @file
 * @brief Сигнал, который отсылается раз в секунду.
 */

#pragma once

#include <so_5/all.hpp>

namespace arataga
{

//! Тип сигнала, который рассылается раз в секунду.
struct one_second_timer_t final : public so_5::signal_t {};

} /* namespace arataga */

