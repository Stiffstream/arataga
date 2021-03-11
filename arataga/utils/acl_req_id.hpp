/*!
 * @file
 * @brief Type to be used by ACL for requests to authentificator-
 * and dns_resolver-agents.
 */

#pragma once

#include <cstdint>
#include <iostream>
#include <tuple>

namespace arataga::utils
{

//! Type for ID from ACL.
struct acl_req_id_t
{
private:
	[[nodiscard]]
	auto
	tie() const noexcept { return std::tie( m_proxy_port, m_id ); }

public:
	//! TCP-port of ACL that has sent the request.
	/*!
	 * This number is necessary to simplify distinguishing
	 * issuers of requests in log files.
	 */
	std::uint16_t m_proxy_port;

	//! Ordinal number of the request.
	std::uint_fast64_t m_id;

	[[nodiscard]]
	bool
	operator<( const acl_req_id_t & o ) const noexcept
	{
		return this->tie() < o.tie();
	}

	[[nodiscard]]
	bool
	operator==( const acl_req_id_t & o ) const noexcept
	{
		return this->tie() == o.tie();
	}

};

inline std::ostream &
operator<<( std::ostream & to, const acl_req_id_t & what )
{
	return (to << '(' << what.m_proxy_port << ',' << what.m_id << ')');
}

} /* namespace arataga::utils */

