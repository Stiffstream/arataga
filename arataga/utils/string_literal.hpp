/*!
 * @file
 * @brief Helper class for representation of string literals.
 * @since v.0.3.0.1
 */

#pragma once

#include <string_view>

namespace arataga::utils
{

// Forward declaration.
class string_literal_t;

namespace string_literals
{

// Forward declaration.
[[nodiscard]]
constexpr string_literal_t
operator""_static_str( const char *, std::size_t ) noexcept;

} /* namespace string_literals */

//
// string_literal_t
//
//FIXME: document this!
class string_literal_t
{
	//! Value of string-literal incapsulated into string_view.
	std::string_view m_value;

	//! Initializing constructor.
	constexpr string_literal_t( std::string_view value ) noexcept
		:	m_value{ value }
	{}

	// The only way for the creation of string_literal instances.
	friend constexpr string_literal_t
	string_literals::operator""_static_str( const char *, std::size_t ) noexcept;

public:
	[[nodiscard]]
	constexpr std::string_view
	as_view() const noexcept { return m_value; }

	[[nodiscard]]
	constexpr operator std::string_view() const noexcept { return m_value; }
};

inline std::ostream &
operator<<( std::ostream & to, const string_literal_t & str )
{
	return (to << str.as_view());
}

namespace string_literals
{

[[nodiscard]]
inline constexpr string_literal_t
operator""_static_str( const char * v, std::size_t l ) noexcept
{
	return { std::string_view{ v, l } };
}

} /* namespace string_literals */

} /* namespace arataga::utils */

