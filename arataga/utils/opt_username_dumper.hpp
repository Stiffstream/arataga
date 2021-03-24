/*!
 * @file
 * @brief Helpers for printing optional username and password values.
 */

#pragma once

#include <iostream>
#include <optional>
#include <string>

namespace arataga::opt_username_dumper
{

/*!
 * @brief A special wrapper for printing an optional username into ostream.
 *
 * Usage example:
 *
 * @code
 * using namespace arataga::opt_username_dumper;
 *
 * fmt::format( "login={}, password={}",
 * 	opt_username_dumper_t{ cmd.m_username },
 * 	opt_password_dumper_t{ cmd.m_password } );
 * @endcode
 */
struct opt_username_dumper_t
{
	const std::optional< std::string > & m_username;
};

inline std::ostream &
operator<<( std::ostream & to, const opt_username_dumper_t & d )
{
	if( d.m_username )
	{
		to << '"' << *(d.m_username) << '"';
	}
	else
	{
		to << "<none>";
	}

	return to;
}

/*!
 * @brief A special wrapper for printing an optional password into ostream.
 *
 * Usage example:
 *
 * @code
 * using namespace arataga::opt_username_dumper;
 *
 * fmt::format( "login={}, password={}",
 * 	opt_username_dumper_t{ cmd.m_username },
 * 	opt_password_dumper_t{ cmd.m_password } );
 * @endcode
 */
struct opt_password_dumper_t
{
	const std::optional< std::string > & m_password;
};

inline std::ostream &
operator<<( std::ostream & to, const opt_password_dumper_t & d )
{
	if( d.m_password )
	{
		to << '"' << *(d.m_password) << '"';
	}
	else
	{
		to << "<none>";
	}

	return to;
}

} /* namespace opt_username_dumper */

