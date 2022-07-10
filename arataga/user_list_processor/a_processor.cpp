/*!
 * @file
 * @brief Agent for handling user-list.
 */

#include <arataga/user_list_processor/a_processor.hpp>
#include <arataga/user_list_processor/notifications.hpp>

#include <arataga/user_list_auth_data.hpp>

#include <arataga/admin_http_entry/helpers.hpp>

#include <arataga/utils/load_file_into_memory.hpp>

#include <arataga/logging/wrap_logging.hpp>

#include <arataga/exception.hpp>

#include <fmt/std.h>

namespace arataga::user_list_processor
{

//
// user_list_processor_ex_t
//
//! Exception to be used by user_list_processor-agent.
struct user_list_processor_ex_t : public exception_t
{
public:
	user_list_processor_ex_t( const std::string & what )
		:	exception_t{ what }
	{}
};

//
// a_processor_t
//
a_processor_t::a_processor_t(
	context_t ctx,
	application_context_t app_ctx,
	params_t params )
	:	so_5::agent_t{ std::move(ctx) }
	,	m_app_ctx{ std::move(app_ctx) }
	,	m_params{ std::move(params) }
	,	m_local_user_list_file_name{
			m_params.m_local_config_path / "local-user-list.cfg" }
{}

void
a_processor_t::so_define_agent()
{
	so_subscribe( m_app_ctx.m_user_list_processor_mbox )
		.event( &a_processor_t::on_new_user_list );
}

void
a_processor_t::so_evt_start()
{
	try_load_local_user_list_first_time();

	// Now we can acknowledge the successful start.
	so_5::send< started_t >( m_params.m_startup_notify_mbox );
}

void
a_processor_t::on_new_user_list(
	mhood_t< new_user_list_t > cmd )
{
	namespace http_entry = ::arataga::admin_http_entry;

	http_entry::envelope_sync_request_handling(
			"user_list_processor::a_processor_t::on_new_user_list",
			*(cmd->m_replier),
			http_entry::status_user_list_processor_failure,
			[&]() -> http_entry::replier_t::reply_params_t
			{
				try_handle_new_user_list_from_post_request( cmd->m_content );

				// Everything is OK if we are here.
				return http_entry::replier_t::reply_params_t{
						http_entry::status_ok,
						"New user list accepted\r\n"
				};
			} );
}

void
a_processor_t::try_load_local_user_list_first_time()
{
	auto auth_data = try_load_local_user_list_content();

	if( auth_data )
	{
		// User-list successfully loaded, it can now be distributed
		// for all subscribers.
		distribute_updated_user_list( std::move(*auth_data) );
	}
}

void
a_processor_t::try_handle_new_user_list_from_post_request(
	std::string_view content )
{
	::arataga::logging::direct_mode::info(
			[&]( auto & logger, auto level )
			{
				logger.log(
						level,
						"user_list_processor: {} byte(s) received "
							"from admin HTTP-entry",
						content.size() );
			} );

	// Try to parse the data.
	auto auth_data = ::arataga::user_list_auth::parse_auth_data( content );

	// Parsing was successful, data can be stored in local file.
	store_new_user_list_to_file( content );

	// New user-list should be distributed.
	distribute_updated_user_list( std::move(auth_data) );

	::arataga::logging::direct_mode::info(
			[]( auto & logger, auto level )
			{
				logger.log(
						level,
						"user_list_processor: new user-list processed" );
			} );
}

std::optional< ::arataga::user_list_auth::auth_data_t >
a_processor_t::try_load_local_user_list_content()
{
	std::optional< ::arataga::user_list_auth::auth_data_t > result;

	::arataga::logging::direct_mode::info(
			[&]( auto & logger, auto level )
			{
				logger.log(
						level,
						"user_list_processor: trying load local "
						"user-list file at startup, "
						"local_user_list_file_name: {}",
						m_local_user_list_file_name.string() );
			} );

	// Exceptions related to user-list loading can be ignored because
	// even in the case of failure a new user-list will be received from
	// HTTP-entry sooner or later.
	try
	{
		// Use a lambda to destroy `content` as soon as possible.
		result = [this] {
			// Load the content...
			auto content = ::arataga::utils::load_file_into_memory(
					m_local_user_list_file_name );
			::arataga::logging::direct_mode::trace(
					[&content]( auto & logger, auto level )
					{
						logger.log(
								level,
								"user_list_processor: {} byte(s) loaded "
								"from local user-list file",
								content.size() );
					} );

			// ...and parse it.
			return ::arataga::user_list_auth::parse_auth_data(
					std::string_view{ content.data(), content.size() } );
		}();
	}
	catch( const std::exception & x )
	{
		::arataga::logging::direct_mode::err(
				[&x]( auto & logger, auto level )
				{
					logger.log(
							level,
							"user_list_processor: load local "
							"user-list file at startup failed: {}",
							x.what() );
				} );
	}

	return result;
}

void
a_processor_t::distribute_updated_user_list(
	::arataga::user_list_auth::auth_data_t auth_data ) noexcept
{
	bool needs_terminate = false;

	try
	{
		::arataga::logging::direct_mode::debug(
				[&]( auto & logger, auto level )
				{
					logger.log(
							level,
							"user_list_processor: distribution of new user-list" );
				} );

		so_5::send< updated_user_list_t >(
				m_app_ctx.m_config_updates_mbox,
				std::move(auth_data) );
	}
	catch( const std::exception & x )
	{
		::arataga::logging::direct_mode::critical(
				[&x]( auto & logger, auto level )
				{
					logger.log(
							level,
							"user_list_processor: "
							"an exception caught during distribution of new user-list: {}",
							x.what() );
				} );

		needs_terminate = true;
	}
	catch( ... )
	{
		::arataga::logging::direct_mode::critical(
				[]( auto & logger, auto level )
				{
					logger.log(
							level,
							"user_list_processor: "
							"unknown exception caught during "
							"distribution of new user-list" );
				} );

		needs_terminate = true;
	}

	if( needs_terminate )
	{
		::arataga::logging::direct_mode::critical(
				[]( auto & logger, auto level )
				{
					logger.log(
							level,
							"user_list_processor: "
							"work can't be continued, aborting..." );
				} );

		std::abort();
	}
}

void
a_processor_t::store_new_user_list_to_file(
	std::string_view content )
{
	try
	{
		::arataga::logging::direct_mode::trace(
				[&]( auto & logger, auto level )
				{
					logger.log(
							level,
							"user_list_processor: updating local "
							"user-list file {}",
							fmt::streamed(m_local_user_list_file_name) );
				} );

		std::ofstream file( m_local_user_list_file_name,
				std::ios_base::out | std::ios_base::binary |
						std::ios_base::trunc );
		if( !file )
			::arataga::utils::ensure_successful_syscall( -1,
					fmt::format( "unable to open local user-list file {} for "
							"writting",
							fmt::streamed(m_local_user_list_file_name) ) );

		file.exceptions( std::ifstream::badbit | std::ifstream::failbit );

		file.write(
				content.data(),
				static_cast<std::streamsize>(content.size()) );

		file.close();
	}
	catch( const std::exception & x )
	{
		::arataga::logging::direct_mode::err(
				[&]( auto & logger, auto level )
				{
					logger.log(
							level,
							"user_list_processor: error storing new "
							"user-list into local file {}: {}",
							m_local_user_list_file_name,
							x.what() );
				} );
	}
}

//
// introduce_user_list_processor
//
void
introduce_user_list_processor(
	so_5::environment_t & env,
	so_5::disp_binder_shptr_t disp_binder,
	application_context_t app_ctx,
	params_t params )
{
	env.introduce_coop(
			disp_binder,
			[&]( so_5::coop_t & coop ) {
				coop.make_agent< a_processor_t >(
						std::move(app_ctx),
						std::move(params) );
			} );
}

} /* namespace arataga::user_list_processor */

