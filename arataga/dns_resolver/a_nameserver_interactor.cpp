/*!
 * @file
 * @brief Agent for interaction with nameservers.
 * @since v.0.4.0
 */
#include <arataga/dns_resolver/a_nameserver_interactor.hpp>

#include <arataga/logging/wrap_logging.hpp>

namespace arataga::dns_resolver
{

//
// a_nameserver_interactor_t
//

a_nameserver_interactor_t::a_nameserver_interactor_t(
	context_t ctx,
	params_t params )
	:	so_5::agent_t{ std::move(ctx) }
	,	m_params{ std::move(params) }
{}

void
a_nameserver_interactor_t::so_define_agent()
{
}

void
a_nameserver_interactor_t::so_evt_start()
{
	::arataga::logging::wrap_logging(
			direct_logging_mode,
			spdlog::level::info,
			[&]( auto & logger, auto level )
			{
				logger.log(
						level,
						"{}: started", m_params.m_name );
			} );
}

} /* namespace arataga::dns_resolver */

