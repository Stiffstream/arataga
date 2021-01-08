/*!
 * @file
 * @brief Счетчики статистики для сообщений лога.
 */

#pragma once

#include <spdlog/spdlog.h>

#include <atomic>
#include <utility>
#include <cstdint>

namespace arataga::logging
{

// Выравнивание, которое нужно использовать для отдельных полей-счетчиков
// в общей структуре для того, чтобы избежать проблемы false-sharing.
constexpr unsigned default_aligment = 64;

// Тип для одного счетчика.
using counter_type_t = std::atomic<std::uint64_t>;

// Набор счетчиков, относящихся к количеству сообщений разных типов.
struct counter_values_t
{
	alignas(default_aligment) counter_type_t m_level_trace_count{0u};
	alignas(default_aligment) counter_type_t m_level_debug_count{0u};
	alignas(default_aligment) counter_type_t m_level_info_count{0u};
	alignas(default_aligment) counter_type_t m_level_warn_count{0u};
	alignas(default_aligment) counter_type_t m_level_error_count{0u};
	alignas(default_aligment) counter_type_t m_level_critical_count{0u};
};

// Получить ссылку на экземпляр с набором счетчиков с количеством
// сообщений разных типов.
[[nodiscard]]
counter_values_t &
counters() noexcept;

namespace impl
{

void
increment_counters_if_neccessary(
	spdlog::level::level_enum level ) noexcept;

} /* namespace impl */

} /* namespace arataga::logging */

