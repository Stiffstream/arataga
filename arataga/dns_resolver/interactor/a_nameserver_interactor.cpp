/*!
 * @file
 * @brief Agent for interaction with nameservers.
 * @since v.0.4.0
 */
#include <arataga/dns_resolver/interactor/a_nameserver_interactor.hpp>

#include <arataga/logging/wrap_logging.hpp>

namespace arataga::dns_resolver::interactor
{

//
// a_nameserver_interactor_t
//

a_nameserver_interactor_t::a_nameserver_interactor_t(
	context_t ctx,
	params_t params )
	:	so_5::agent_t{ std::move(ctx) }
	,	m_params{ std::move(params) }
	,	m_socket{ m_params.m_io_ctx }
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
			spdlog::level::trace,
			[&]( auto & logger, auto level )
			{
				logger.log(
						level,
						"{}: opening UDP socket", m_params.m_name );
			} );

	m_socket.open( asio::ip::udp::v4() );
	//FIXME: the first async_receive should be called here!

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

[[nodiscard]]
so_5::mbox_t
make_interactor(
	so_5::agent_t & parent,
	so_5::disp_binder_shptr_t disp_binder,
	params_t params )
{
	return so_5::introduce_child_coop(
			parent,
			disp_binder,
			[&params]( so_5::coop_t & coop ) {
				auto * interactor = coop.make_agent< a_nameserver_interactor_t >(
						std::move(params) );

				return interactor->so_direct_mbox();
			} );
}

} /* namespace arataga::dns_resolver::interactor */

