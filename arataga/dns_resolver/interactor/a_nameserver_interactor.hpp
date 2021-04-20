/*!
 * @file
 * @brief Agent for interaction with nameservers.
 * @since v.0.4.0
 */

#pragma once

#include <arataga/dns_resolver/interactor/pub.hpp>

#include <asio/ip/udp.hpp>

namespace arataga::dns_resolver::interactor
{

//
// a_nameserver_interactor_t
//

//FIXME: document this!
class a_nameserver_interactor_t final : public so_5::agent_t
{
public:
	a_nameserver_interactor_t(
		context_t ctx,
		params_t params );

	void
	so_define_agent() override;

	void
	so_evt_start() override;

private:
	//! Personal parameters for that agent.
	const params_t m_params;

	//! UPD socket to be user for interaction with nameservers.
	asio::ip::udp::socket m_socket;
};

} /* namespace arataga::dns_resolver::interactor */

