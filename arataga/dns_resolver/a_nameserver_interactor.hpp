/*!
 * @file
 * @brief Agent for interaction with nameservers.
 * @since v.0.4.0
 */

#pragma once

#include <so_5/all.hpp>

#include <asio/ip/udp.hpp>

namespace arataga::dns_resolver
{

//
// a_nameserver_interactor_t
//

//FIXME: document this!
class a_nameserver_interactor_t final : public so_5::agent_t
{
public:
	//
	// params_t
	//
	/*!
	 * @brief Initial parameters for nameserver_interactor-agent.
	 */
	struct params_t
	{
		//! Asio's io_context to be used by nameserver_interactor.
		/*!
		 * @note
		 * This reference is expected to be valid for the whole lifetime
		 * of nameserver_interactor-agent.
		 */
		asio::io_context & m_io_ctx;

		//! Unique name of that agent.
		/*!
		 * Intended to be used for logging.
		 */
		std::string m_name;
	};

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
};

} /* namespace arataga::dns_resolver */

