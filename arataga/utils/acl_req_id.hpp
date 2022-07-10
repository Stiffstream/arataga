/*!
 * @file
 * @brief Type to be used by ACL for requests to authentificator-
 * and dns_resolver-agents.
 */

#pragma once

#include <cstdint>
#include <iostream>
#include <tuple>

#include <fmt/ostream.h>

namespace arataga::utils
{

//! Type of unique seed for ACL.
/*!
 * @since v.0.3.1.2
 */
struct acl_req_id_seed_t
{
private:
	[[nodiscard]]
	auto
	tie() const noexcept { return std::tie( m_seed, m_ordinal ); }

public:
	//! Type of seed value.
	using seed_t = unsigned int;

	//! Random seed for ID generation.
	seed_t m_seed;

	//! Ordinal number of ACL.
	std::uint_fast64_t m_ordinal;

	[[nodiscard]]
	bool
	operator<( const acl_req_id_seed_t & o ) const noexcept
	{
		return this->tie() < o.tie();
	}

	[[nodiscard]]
	bool
	operator==( const acl_req_id_seed_t & o ) const noexcept
	{
		return this->tie() == o.tie();
	}
};

inline std::ostream &
operator<<( std::ostream & to, const acl_req_id_seed_t & what )
{
	return (to << what.m_seed << '_' << what.m_ordinal);
}

//! Type for ID from ACL.
struct acl_req_id_t
{
private:
	[[nodiscard]]
	auto
	tie() const noexcept { return std::tie( m_seed, m_proxy_port, m_id ); }

public:
	//! Unique seed assigned to ACL.
	acl_req_id_seed_t m_seed;

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
	return (to << '('
			<< what.m_seed << ','
			<< what.m_proxy_port << ','
			<< what.m_id << ')');
}

} /* namespace arataga::utils */

template<> struct fmt::formatter< arataga::utils::acl_req_id_seed_t >
	:	public fmt::ostream_formatter
{};

template<> struct fmt::formatter< arataga::utils::acl_req_id_t >
	:	public fmt::ostream_formatter
{};

