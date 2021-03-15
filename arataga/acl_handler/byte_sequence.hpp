/*!
 * @file
 * @brief An analog of string_view but for std::byte.
 */

#pragma once

#include <algorithm>
#include <cstddef>
#include <iterator>
#include <string>

namespace arataga::acl_handler
{

//
// byte_sequence_t
//
/*!
 * @brief A very trivial analog of string_view but for std::byte.
 */
class byte_sequence_t
{
	const std::byte * m_data;
	std::size_t m_size;

public:
	byte_sequence_t()
		:	m_data{ nullptr }, m_size{ 0u }
	{}

	byte_sequence_t(
		const std::byte * data,
		std::size_t size )
		:	m_data{ data }, m_size{ size }
	{}

	byte_sequence_t(
		const std::byte * begin,
		const std::byte * end )
		:	m_data{ begin }, m_size{ static_cast<std::size_t>(end - begin) }
	{}

	[[nodiscard]]
	bool
	empty() const noexcept { return 0u == m_size; }

	[[nodiscard]]
	std::size_t
	size() const noexcept { return m_size; }

	[[nodiscard]]
	const std::byte *
	begin() const noexcept { return m_data; }

	[[nodiscard]]
	const std::byte *
	end() const noexcept { return m_data + m_size; }

	[[nodiscard]]
	std::string
	to_string() const 
	{
		std::string result;
		result.reserve( size() );

		std::transform( begin(), end(), std::back_inserter(result),
				std::to_integer<std::string::value_type> );

		return result;
	}
};

} /* namespace arataga::acl_handler */

