/*!
 * @file
 * @brief Agent that starts all main agents in the right sequence.
 */

#include <arataga/startup_manager/a_manager.hpp>

#include <arataga/stats_collector/introduce_stats_collector.hpp>
#include <arataga/stats_collector/msg_get_stats.hpp>
#include <arataga/user_list_processor/pub.hpp>
#include <arataga/config_processor/pub.hpp>

#include <arataga/logging/wrap_logging.hpp>

#include <arataga/one_second_timer.hpp>

#include <arataga/exception.hpp>

#include <so_5_extra/mboxes/retained_msg.hpp>

namespace arataga::startup_manager
{

//
// startup_manager_ex_t
//
//! Exception to be used by startup_manager.
struct startup_manager_ex_t : public exception_t
{
public:
	startup_manager_ex_t( const std::string & what )
		:	exception_t{ what }
	{}
};

namespace impl
{

//
// actual_requests_mailbox_t
//
//! Actual implementation of admin_http_entry::requests_mailbox interface.
class actual_requests_mailbox_t final
	:	public ::arataga::admin_http_entry::requests_mailbox_t
{
public:
	actual_requests_mailbox_t(
		application_context_t app_ctx )
		:	m_app_ctx{ std::move(app_ctx) }
	{}

	void
	new_config(
		::arataga::admin_http_entry::replier_shptr_t replier,
		std::string_view content ) override
	{
		so_5::send< ::arataga::config_processor::new_config_t >(
				m_app_ctx.m_config_processor_mbox,
				std::move(replier),
				std::move(content) );
	}

	void
	get_acl_list(
		::arataga::admin_http_entry::replier_shptr_t replier ) override
	{
		so_5::send< ::arataga::config_processor::get_acl_list_t >(
				m_app_ctx.m_config_processor_mbox,
				std::move(replier) );
	}

	void
	new_user_list(
		::arataga::admin_http_entry::replier_shptr_t replier,
		std::string_view content ) override
	{
		so_5::send< ::arataga::user_list_processor::new_user_list_t >(
				m_app_ctx.m_user_list_processor_mbox,
				std::move(replier),
				std::move(content) );
	}

	void
	get_current_stats(
		::arataga::admin_http_entry::replier_shptr_t replier ) override
	{
		so_5::send< ::arataga::stats_collector::get_current_stats_t >(
				m_app_ctx.m_stats_collector_mbox,
				std::move(replier) );
	}

	void
	debug_authentificate(
		::arataga::admin_http_entry::replier_shptr_t replier,
		::arataga::admin_http_entry::debug_requests::authentificate_t
				request ) override
	{
		so_5::send< ::arataga::config_processor::debug_auth_t >(
				m_app_ctx.m_config_processor_mbox,
				std::move(replier),
				std::move(request) );
	}

	void
	debug_dns_resolve(
		::arataga::admin_http_entry::replier_shptr_t replier,
		::arataga::admin_http_entry::debug_requests::dns_resolve_t
				request ) override
	{
		so_5::send< ::arataga::config_processor::debug_dns_resolve_t >(
				m_app_ctx.m_config_processor_mbox,
				std::move(replier),
				std::move(request) );
	}

private:
	const application_context_t m_app_ctx;
};

} /* namespace impl */

//
// a_manager_t
//
a_manager_t::a_manager_t(
	context_t ctx,
	params_t params )
	:	so_5::agent_t{ std::move(ctx) }
	,	m_params{ std::move(params) }
	,	m_app_ctx{ make_application_context( so_environment(), m_params ) }
	,	m_admin_entry_requests_mailbox{
			std::make_unique< impl::actual_requests_mailbox_t >( m_app_ctx ) }
{}

void
a_manager_t::so_define_agent()
{
	// NOTE: on_enter handlers can't throw exceptions.
	// But we don't care about this because the whole application
	// has to be terminated in the case of an error in on_enter handlers.
	st_wait_user_list_processor
		.on_enter( [this]{ on_enter_wait_user_list_processor(); } )
		.event( &a_manager_t::on_user_list_processor_started )
		.event( &a_manager_t::on_user_list_processor_startup_timeout );

	st_wait_config_processor
		.on_enter( [this]{ on_enter_wait_config_processor(); } )
		.event( &a_manager_t::on_config_processor_started )
		.event( &a_manager_t::on_config_processor_startup_timeout );

	st_http_entry_stage
		.on_enter( [this]{ on_enter_http_entry_stage(); } )
		.event( &a_manager_t::on_make_admin_http_entry );
}

void
a_manager_t::so_evt_start()
{
	::arataga::logging::direct_mode::info(
			[&]( auto & logger, auto level )
			{
				logger.log( level, "startup_manager: startup procedure started" );
			} );
	
	// One-second timer should be started.
	m_one_second_timer = so_5::send_periodic< one_second_timer_t >(
			m_app_ctx.m_global_timer_mbox,
			std::chrono::seconds{1},
			std::chrono::seconds{1} );

	// Start stats_collector because it doesn't require additional attention
	// to itself.
	::arataga::stats_collector::introduce_stats_collector(
			so_environment(),
			so_coop(),
			// This agent will use own worker thread.
			so_5::disp::one_thread::make_dispatcher(
					so_environment(),
					"stats_collector" ).binder(),
			m_app_ctx,
			::arataga::stats_collector::params_t{} );

	// Initiate launch of more heavy agents.
	this >>= st_wait_user_list_processor;
}

void
a_manager_t::so_evt_finish()
{
	// If HTTP-entry works then it should be stopped.
	if( m_admin_entry )
		m_admin_entry->stop();
}

application_context_t
a_manager_t::make_application_context(
	so_5::environment_t & env,
	const params_t & /*params*/ )
{
	application_context_t result;

	result.m_config_processor_mbox = env.create_mbox();
	result.m_user_list_processor_mbox = env.create_mbox();

	// A special retained_mbox will be used.
	// It stores the last message sent and resend it automatically
	// for every new subscriber.
	// It's necessary for new agents: they will get the last config
	// right after the subscription to this mbox.
	result.m_config_updates_mbox = so_5::extra::mboxes::retained_msg::
			make_mbox( env );

	result.m_stats_collector_mbox = env.create_mbox();

	result.m_global_timer_mbox = env.create_mbox();

	result.m_acl_stats_manager = ::arataga::stats::connections::
			make_std_acl_stats_reference_manager();

	result.m_auth_stats_manager = ::arataga::stats::auth::
			make_std_auth_stats_reference_manager();

	result.m_dns_stats_manager = ::arataga::stats::dns::
			make_std_dns_stats_reference_manager();

	return result;
}

void
a_manager_t::on_enter_wait_user_list_processor()
{
	::arataga::logging::direct_mode::debug(
			[&]( auto & logger, auto level )
			{
				logger.log(
						level,
						"startup_manager: starting user_list_processor" );
			} );

	// user_list_processor will use own worker thread.
	namespace ulp = arataga::user_list_processor;
	ulp::introduce_user_list_processor(
			so_environment(),
			so_5::disp::one_thread::make_dispatcher(
					so_environment(),
					"user_list_processor" ).binder(),
			m_app_ctx,
			ulp::params_t{
					m_params.m_local_config_path,
					so_direct_mbox()
			} );

	// Limit the time of user_list_processor startup.
	so_5::send_delayed< user_list_processor_startup_timeout >(
			*this,
			m_params.m_max_stage_startup_time );
}

void
a_manager_t::on_user_list_processor_started(
	mhood_t< arataga::user_list_processor::started_t > )
{
	::arataga::logging::direct_mode::debug(
			[]( auto & logger, auto level )
			{
				logger.log(
						level,
						"startup_manager: user_list_processor started" );
			} );

	this >>= st_wait_config_processor;
}

[[noreturn]] void
a_manager_t::on_user_list_processor_startup_timeout(
	mhood_t< user_list_processor_startup_timeout > )
{
	::arataga::logging::direct_mode::critical(
			[]( auto & logger, auto level )
			{
				logger.log(
						level,
						"startup_manager: user_list_processor startup timed-out" );
			} );

	// This exception will kill the whole application.
	throw startup_manager_ex_t{ "user_list_processor startup timed-out" };
}

void
a_manager_t::on_enter_wait_config_processor()
{
	::arataga::logging::direct_mode::debug(
			[]( auto & logger, auto level )
			{
				logger.log(
						level,
						"startup_manager: starting config_processor" );
			} );

	// The config_processor agent will work on own worker thread.
	namespace cp = arataga::config_processor;
	cp::introduce_config_processor(
			so_environment(),
			so_5::disp::one_thread::make_dispatcher(
					so_environment(),
					"config_processor" ).binder(),
			m_app_ctx,
			cp::params_t{
					m_params.m_local_config_path,
					so_direct_mbox(),
					m_params.m_io_threads_count
			} );

	// Limit the time of config_processor startup.
	so_5::send_delayed< config_processor_startup_timeout >(
			*this,
			m_params.m_max_stage_startup_time );
}

void
a_manager_t::on_config_processor_started(
	mhood_t< arataga::config_processor::started_t > )
{
	::arataga::logging::direct_mode::debug(
			[]( auto & logger, auto level )
			{
				logger.log(
						level,
						"startup_manager: config_processor started" );
			} );

	this >>= st_http_entry_stage;
}

[[noreturn]] void
a_manager_t::on_config_processor_startup_timeout(
	mhood_t< config_processor_startup_timeout > )
{
	::arataga::logging::direct_mode::critical(
			[]( auto & logger, auto level )
			{
				logger.log(
						level,
						"startup_manager: config_processor startup timed-out" );
			} );

	// This exception will kill the whole application.
	throw startup_manager_ex_t{ "config_processor startup timed-out" };
}

void
a_manager_t::on_enter_http_entry_stage()
{
	so_5::send< make_admin_http_entry >( *this );
}

void
a_manager_t::on_make_admin_http_entry(
	mhood_t< make_admin_http_entry > )
{
	::arataga::logging::direct_mode::debug(
			[]( auto & logger, auto level )
			{
				logger.log(
						level,
						"startup_manager: starting HTTP-entry" );
			} );

	m_admin_entry = ::arataga::admin_http_entry::start_entry(
			m_params.m_admin_http_ip,
			m_params.m_admin_http_port,
			m_params.m_admin_http_token,
			*m_admin_entry_requests_mailbox );
}

//
// introduce_startup_manager
//
void
introduce_startup_manager(
	so_5::environment_t & env,
	params_t params )
{
	env.register_agent_as_coop(
			env.make_agent< a_manager_t >( std::move(params) ) );
}

} /* namespace arataga::startup_manager */

