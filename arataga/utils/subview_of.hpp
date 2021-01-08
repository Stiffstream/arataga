/*!
 * @file
 * @brief Вспомогательные средства для получения подстроки.
 */

#pragma once

#include <algorithm>
#include <array>
#include <string>
#include <string_view>

namespace arataga::utils
{

//
// subview_t
//
template< std::size_t Capacity >
struct subview_t
{
	std::array< char, Capacity > m_data;
	std::size_t m_length;
};

template< std::size_t Capacity >
std::ostream &
operator<<( std::ostream & to, const subview_t<Capacity> & v )
{
	return (to << std::string_view{ &(v.m_data[0]), v.m_length });
}

//
// subview_of
//
template< std::size_t Capacity >
[[nodiscard]]
subview_t< Capacity >
subview_of( std::string_view str )
{
	constexpr std::size_t min_capacity = 6u;
	static_assert( Capacity >= min_capacity,
			"Capacity should be big enough to hold values like \"...\"" );

	// Capacity without quotes.
	constexpr std::size_t max_chars_to_fit = Capacity - 2u;

	subview_t<Capacity> result;
	result.m_data[0] = '"';

	if( str.size() <= max_chars_to_fit )
	{
		auto it = std::copy( str.begin(), str.end(), &result.m_data[1] );
		*it = '"';
		result.m_length = str.size() + 2u;
	}
	else
	{
		constexpr std::string_view ellipsis{ "..." };

		auto it = std::copy_n(
				str.begin(), max_chars_to_fit - 3u, &result.m_data[1] );
		it = std::copy(
				ellipsis.begin(), ellipsis.end(), it );
		*it = '"';
		result.m_length = Capacity;
	}

	return result;
}

template< std::size_t Capacity >
[[nodiscard]]
subview_t< Capacity >
subview_of( const std::string & src ) noexcept
{
	return subview_of< Capacity >( std::string_view{ src } );
}

template< std::size_t Capacity >
[[nodiscard]]
subview_t< Capacity >
subview_of( const char * src ) noexcept
{
	return subview_of< Capacity >( std::string_view{ src } );
}

} /* namespace arataga::utils */

