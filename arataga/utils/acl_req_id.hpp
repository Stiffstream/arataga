/*!
 * @file
 * @brief Тип, который должен использоваться ACL для выдачи запросов
 * в authentificator и dns_resolver.
 */

#pragma once

#include <cstdint>
#include <iostream>
#include <tuple>

namespace arataga::utils
{

//! Идентификатор запроса от ACL.
struct acl_req_id_t
{
private:
	[[nodiscard]]
	auto
	tie() const noexcept { return std::tie( m_proxy_port, m_id ); }

public:
	//! Номер порта ACL, от которого пришел запрос.
	/*!
	 * Этот номер необходим для того, чтобы в логах было проще
	 * отличать от кого именно поступил запрос.
	 */
	std::uint16_t m_proxy_port;

	//! Порядковый номер запроса.
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

