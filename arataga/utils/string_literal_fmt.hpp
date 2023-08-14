/*!
 * @file
 * @brief Helper for formatting/printing of string_literal via fmtlib.
 * @since v.0.3.0.1
 */

#pragma once

#include <arataga/utils/string_literal.hpp>

#include <fmt/ostream.h>

template<>
struct fmt::formatter< arataga::utils::string_literal_t >
	:	public fmt::ostream_formatter
{};

