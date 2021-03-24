/*!
 * @file
 * @brief A type for representing turn's sequence number.
 */

#pragma once

#include <cstdint>
#include <iostream>

namespace arataga::acl_handler
{

//
// sequence_number_t
//
/*!
 * @brief A type for representing turn's sequence number.
 *
 * It is needed to aviod acidental passing of turn's number instead
 * of unsigned number (or vice verse).
 */
class sequence_number_t
{
public:
	using underlying_type_t = std::uint_least64_t;

private:
	underlying_type_t m_value{};

public:
	sequence_number_t() noexcept = default;
	explicit sequence_number_t( underlying_type_t initial ) noexcept
		:	m_value{ initial }
	{}

	[[nodiscard]]
	auto get() const noexcept { return m_value; }

	void increment() noexcept { ++m_value; }

	[[nodiscard]]
	friend bool operator==(
		const sequence_number_t & a,
		const sequence_number_t & b ) noexcept
	{
		return a.m_value == b.m_value;
	}

	[[nodiscard]]
	friend bool operator!=(
		const sequence_number_t & a,
		const sequence_number_t & b ) noexcept
	{
		return a.m_value != b.m_value;
	}

	friend std::ostream &
	operator<<( std::ostream & to, const sequence_number_t & v )
	{
		return (to << v.m_value);
	}
};

} /* namespace arataga::acl_handler */

