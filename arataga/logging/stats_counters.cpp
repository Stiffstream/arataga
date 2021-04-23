/*!
 * @file
 * @brief Stats counters for log messages.
 */

#include <arataga/logging/stats_counters.hpp>

namespace arataga::logging
{

static counter_values_t g_counters{};

[[nodiscard]]
counter_values_t &
counters() noexcept
{
	return g_counters;
}

namespace impl
{

void
increment_counters_if_neccessary(
	spdlog::level::level_enum level ) noexcept
{
	auto & cnts = counters();

	switch( level )
	{
	case spdlog::level::trace:
		cnts.m_level_trace_count += 1u;
	break;

	case spdlog::level::debug:
		cnts.m_level_debug_count += 1u;
	break;

	case spdlog::level::info:
		cnts.m_level_info_count += 1u;
	break;

	case spdlog::level::warn:
		cnts.m_level_warn_count += 1u;
	break;

	case spdlog::level::err:
		cnts.m_level_error_count += 1u;
	break;

	case spdlog::level::critical:
		cnts.m_level_critical_count += 1u;
	break;

	case spdlog::level::off:
	break;

	case spdlog::level::n_levels:
	break;
	}
}

void
increment_count_of_exceptions_during_logging() noexcept
{
	auto & cnts = counters();
	cnts.m_exceptions_during_logging += 1u;
}

} /* namespace impl */

} /* namespace arataga::logging */

