/*!
 * @file
 * @brief Stats counters for log messages.
 */

#pragma once

#include <spdlog/spdlog.h>

#include <atomic>
#include <utility>
#include <cstdint>

namespace arataga::logging
{

// An alignment to be used to avoid false-sharing problem.
constexpr unsigned default_aligment = 64;

// Type for a single counter.
using counter_type_t = std::atomic<std::uint64_t>;

// A bunch of counters for log messages.
struct counter_values_t
{
	alignas(default_aligment) counter_type_t m_level_trace_count{0u};
	alignas(default_aligment) counter_type_t m_level_debug_count{0u};
	alignas(default_aligment) counter_type_t m_level_info_count{0u};
	alignas(default_aligment) counter_type_t m_level_warn_count{0u};
	alignas(default_aligment) counter_type_t m_level_error_count{0u};
	alignas(default_aligment) counter_type_t m_level_critical_count{0u};
};

// Get a reference to object with counters.
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

