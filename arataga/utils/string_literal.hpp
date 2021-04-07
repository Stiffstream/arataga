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
/*!
 * @brief Class for representing string literal stored in static memory.
 *
 * Some strings in an application is represented as string literals
 * (those literals are stored in static memory). It means that the
 * pointer to such literal remains valid while application works.
 * But it is a question how to distinguish such literals from
 * temporary values as char arrays on the stack. For example:
 *
 * @code
 * class some_long_living_object
 * {
 * 	const char * m_value;
 *
 * public:
 * 	some_long_living_object(const char * value) : m_value{value} {}
 * 	...
 * };
 *
 * some_long_living_object make_object_ok()
 * {
 * 	// It's OK, that pointer remains valid because string literals
 * 	// are stored in static memory.
 * 	return some_long_living_object{ "Hello!" };
 * }
 *
 * some_long_living_object make_object_bug()
 * {
 * 	// It's a bug because there will be a dangling pointer.
 *		auto name = "Number #" + std::to_string(1);
 *		return some_long_living_object{ name.c_str() };
 * }
 * @endcode
 *
 * By using string_literal_t that problem can be solved that way:
 * 
 * @code
 * class some_long_living_object
 * {
 * 	arataga::utils::string_literal_t m_value;
 *
 * public:
 * 	some_long_living_object(
 * 		arataga::utils::string_literal_t value)
 * 		: m_value{value}
 * 	{}
 * 	...
 * };
 *
 * some_long_living_object make_object_ok()
 * {
 * 	// It's OK, that pointer remains valid because string literals
 * 	// are stored in static memory.
 * 	using namespace arataga::utils::string_literals;
 * 	return some_long_living_object{ "Hello!"_static_str };
 * }
 *
 * some_long_living_object make_object_bug()
 * {
 * 	// Won't be compiled because there is no way to construct
 * 	// string_literal_t from ordinary `const char*`.
 *		auto name = "Number #" + std::to_string(1);
 *		return some_long_living_object{ name.c_str() };
 * }
 * @endcode
 *
 * @note
 * The only way to get an initialized instance of string_literal_t
 * is use `_static_str` user-defined literal from
 * aragata::utils::string_literals namespace:
 * @code
 * using namespace arataga::utils::string_literals;
 * const auto content_type = "Content-Type"_static_str;
 * const auto host = "Host"_static_str;
 * @endcode
 */
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

