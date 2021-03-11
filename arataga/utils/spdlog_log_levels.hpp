/*!
 * @file
 * @brief Helpers for working with spdlog's severity levels.
 */

#pragma once

#include <spdlog/spdlog.h>

#include <optional>

namespace arataga
{

namespace utils
{

[[nodiscard]]
inline std::optional<spdlog::level::level_enum>
name_to_spdlog_level_enum(spdlog::string_view_t name) noexcept {
	if("trace" == name)
		return spdlog::level::trace;
	else if("debug" == name)
		return spdlog::level::debug;
	else if("info" == name)
		return spdlog::level::info;
	else if("warn" == name)
		return spdlog::level::warn;
	else if("error" == name)
		return spdlog::level::err;
	else if("crit" == name)
		return spdlog::level::critical;
	else if("off" == name)
		return spdlog::level::off;
	else
		return std::nullopt;
}

} /* namespace utils */

} /* namespace arataga */

