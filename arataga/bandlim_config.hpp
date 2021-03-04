/*!
 * @file
 * @brief Parameters for band-limits.
 */

#pragma once

#include <cstdint>
#include <iostream>

namespace arataga
{

//
// bandlim_config_t
//
/*!
 * @brief Band-limits for a client.
 */
struct bandlim_config_t
{
	//! Type for holding one value.
	using value_t = std::uint_fast64_t;

	//! A special value for the case when limit is not set.
	static constexpr value_t unlimited{ 0u };

	//! The limit for incoming (from target host to client) traffic.
	/*!
	 * In bytes.
	 */
	value_t m_in{ unlimited };

	//! The limit for outgoing (from client to target host) traffic. 
	/*!
	 * In bytes.
	 */
	value_t m_out{ unlimited };

	//! A helper method for checking that limit isn't set.
	/*!
	 * The usage example:
	 * @code
	 * if( bandlim_config_t::is_unlimited(my_limits.m_in) ) {...}
	 * @endcode
	 */
	[[nodiscard]]
	static bool
	is_unlimited( value_t v ) noexcept { return unlimited == v; }
};

inline std::ostream &
operator<<( std::ostream & to, const bandlim_config_t & v )
{
	to << "in=";
	if( bandlim_config_t::is_unlimited( v.m_in ) )
		to << "unlimited";
	else
		to << v.m_in;

	to << ", out=";
	if( bandlim_config_t::is_unlimited( v.m_out ) )
		to << "unlimited";
	else
		to << v.m_out;

	return to;
}

} /* namespace arataga */

