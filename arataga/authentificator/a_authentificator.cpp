/*!
 * @file
 * @brief Описание агента authentificator.
 */

#include <arataga/authentificator/a_authentificator.hpp>

#include <arataga/utils/opt_username_dumper.hpp>

#include <arataga/logging/wrap_logging.hpp>

#include <fmt/ostream.h>
#include <fmt/chrono.h>

namespace arataga::authentificator
{

using ::arataga::opt_username_dumper::opt_username_dumper_t;
using ::arataga::opt_username_dumper::opt_password_dumper_t;

//
// a_authentificator_t
//
a_authentificator_t::a_authentificator_t(
	context_t ctx,
	application_context_t app_ctx,
	params_t params )
	:	so_5::agent_t{ std::move(ctx) }
	,	m_app_ctx{ std::move(app_ctx) }
	,	m_params{ std::move(params) }
	,	m_auth_stats_reg{
			m_app_ctx.m_auth_stats_manager,
			m_auth_stats
		}
{}

void
a_authentificator_t::so_define_agent()
{
	so_subscribe_self()
		.event( &a_authentificator_t::on_auth_request );
}

void
a_authentificator_t::so_evt_start()
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

	so_subscribe( m_app_ctx.m_config_updates_mbox )
		.event( &a_authentificator_t::on_updated_user_list )
		.event( &a_authentificator_t::on_updated_auth_params );
}

void
a_authentificator_t::on_updated_user_list(
	mhood_t< ::arataga::user_list_processor::updated_user_list_t > cmd )
{
	::arataga::logging::wrap_logging(
			direct_logging_mode,
			spdlog::level::info,
			[&]( auto & logger, auto level )
			{
				logger.log(
						level,
						"{}: updated user-list received", m_params.m_name );
			} );

	m_auth_data = cmd->m_auth_data;
}

void
a_authentificator_t::on_updated_auth_params(
	mhood_t< ::arataga::config_processor::updated_auth_params_t > cmd )
{
	::arataga::logging::wrap_logging(
			direct_logging_mode,
			spdlog::level::info,
			[&]( auto & logger, auto level )
			{
				logger.log(
						level,
						"{}: updated auth-params received", m_params.m_name );
			} );

	m_denied_ports = cmd->m_denied_ports;
	m_failed_auth_reply_timeout = cmd->m_failed_auth_reply_timeout;
}

void
a_authentificator_t::on_auth_request(
	mhood_t< auth_request_t > cmd )
{
	::arataga::logging::wrap_logging(
			direct_logging_mode,
			spdlog::level::trace,
			[&]( auto & logger, auto level )
			{
				logger.log(
						level,
						"{}: auth_request received, "
							"req_id={}, proxy_in_addr={}, proxy_port={}, "
							"user_ip={}, username={} (password={}), target_host={}, "
							"target_port={}",
						m_params.m_name,
						cmd->m_req_id,
						cmd->m_proxy_in_addr,
						cmd->m_proxy_port,
						cmd->m_user_ip,
						opt_username_dumper_t{cmd->m_username},
						opt_password_dumper_t{cmd->m_password},
						cmd->m_target_host,
						cmd->m_target_port );
			} );

	m_auth_stats.m_auth_total_count += 1u;

	if( cmd->m_username )
		do_auth_by_login_password( *cmd );
	else
		do_auth_by_ip( *cmd );
}

void
a_authentificator_t::do_auth_by_ip(
	const auth_request_t & req )
{
	const auto it = m_auth_data.m_by_ip.find(
			::arataga::user_list_auth::auth_by_ip_key_t{
					req.m_proxy_in_addr,
					req.m_proxy_port,
					req.m_user_ip
			}
		);
	if( it == m_auth_data.m_by_ip.end() )
	{
		// Такой клиент нам неизвестен.
		m_auth_stats.m_failed_auth_by_ip_count += 1u;
		complete_failed_auth( req, failure_reason_t::unknown_user );
	}
	else
	{
		m_auth_stats.m_auth_by_ip_count += 1u;

		// Клиент успешно аутентифицирован и теперь должен пройти
		// авторизацию.
		const auto authorize_result = try_authorize_user( req );
		if( authorize_result )
		{
			if( failure_reason_t::target_blocked == *authorize_result )
			{
				m_auth_stats.m_failed_authorization_denied_port += 1u;
			}

			// Клиент не авторизован, работать дальше он не может.
			complete_failed_auth( req, *authorize_result );
		}
		else
		{
			// Клиент авторизован, можно отсылать ему положительный
			// результат.
			complete_successful_auth( req, it->second );
		}
	}
}

void
a_authentificator_t::do_auth_by_login_password(
	const auth_request_t & req )
{
	const auto it = m_auth_data.m_by_login.find(
			::arataga::user_list_auth::auth_by_login_key_t{
					req.m_proxy_in_addr,
					req.m_proxy_port,
					req.m_username.value(),
					req.m_password.value_or( std::string{} )
			}
		);
	if( it == m_auth_data.m_by_login.end() )
	{
		// Такой клиент нам неизвестен.
		m_auth_stats.m_failed_auth_by_login_count += 1u;
		complete_failed_auth( req, failure_reason_t::unknown_user );
	}
	else
	{
		m_auth_stats.m_auth_by_login_count += 1u;

		// Клиент успешно аутентифицирован и теперь должен пройти
		// авторизацию.
		const auto authorize_result = try_authorize_user( req );
		if( authorize_result )
		{
			if( failure_reason_t::target_blocked == *authorize_result )
			{
				m_auth_stats.m_failed_authorization_denied_port += 1u;
			}

			// Клиент не авторизован, работать дальше он не может.
			complete_failed_auth( req, *authorize_result );
		}
		else
		{
			// Клиент авторизован, можно отсылать ему положительный
			// результат.
			complete_successful_auth( req, it->second );
		}
	}
}

void
a_authentificator_t::complete_failed_auth(
	const auth_request_t & req,
	failure_reason_t reason )
{
	::arataga::logging::wrap_logging(
			direct_logging_mode,
			spdlog::level::debug,
			[&]( auto & logger, auto level )
			{
				logger.log(
						level,
						"{}: auth_request failed, "
								"req_id={}, reason={}, reply_timeout={}",
						m_params.m_name,
						req.m_req_id,
						to_string_view( reason ),
						m_failed_auth_reply_timeout );
			} );

	so_5::send_delayed< auth_reply_t >(
			req.m_reply_to,
			m_failed_auth_reply_timeout,
			req.m_req_id,
			req.m_completion_token,
			auth_result_t{ failed_auth_t{ reason } } );
}

void
a_authentificator_t::complete_successful_auth(
	const auth_request_t & req,
	const ::arataga::user_list_auth::user_data_t & user_data )
{
	successful_auth_t result;
	result.m_user_id = user_data.m_user_id;
	result.m_user_bandlims = user_data.m_bandlims;

	// Определяем лимит для домена, к которому пользователь собирается
	// подключаться.
	result.m_domain_limits = try_detect_domain_limits(
			user_data,
			req.m_target_host );

	::arataga::logging::wrap_logging(
			direct_logging_mode,
			spdlog::level::debug,
			[&]( auto & logger, auto level )
			{
				logger.log(
						level,
						"{}: auth_request successed, req_id={}",
						m_params.m_name,
						req.m_req_id );
			} );

	so_5::send< auth_reply_t >(
			req.m_reply_to,
			req.m_req_id,
			req.m_completion_token,
			auth_result_t{ std::move(result) } );
}

std::optional< failure_reason_t >
a_authentificator_t::try_authorize_user(
	const auth_request_t & req )
{
	std::optional< failure_reason_t > result;

	// Клиент не должен обращаться к заблокированном порту.
	if( m_denied_ports.is_denied( req.m_target_port ) )
		result = failure_reason_t::target_blocked;

	return result;
}

std::optional< one_domain_limit_t >
a_authentificator_t::try_detect_domain_limits(
	const ::arataga::user_list_auth::user_data_t & user_data,
	const std::string & target_host ) const
{
	std::optional< one_domain_limit_t > result;

	// Сперва нужно найти список лимитов для этого пользователя,
	// если такой список вообще определен.
	if( const auto it_list = m_auth_data.m_site_limits.find(
			::arataga::user_list_auth::site_limits_key_t{
					user_data.m_site_limits_id
			} );
			it_list != m_auth_data.m_site_limits.end() )
	{
		// И если такой список есть, то нужно поискать домен уже
		// в этот список.
		result = it_list->second.try_find_limits_for(
				::arataga::user_list_auth::domain_name_t{ target_host } );
	}

	return result;
}

//
// introduce_authentificator
//
std::tuple< so_5::coop_handle_t, so_5::mbox_t >
introduce_authentificator(
	so_5::environment_t & env,
	so_5::coop_handle_t parent_coop,
	so_5::disp_binder_shptr_t disp_binder,
	application_context_t app_ctx,
	params_t params )
{
	auto coop_holder = env.make_coop( parent_coop, std::move(disp_binder) );
	auto auth_mbox = coop_holder->make_agent< a_authentificator_t >(
			std::move(app_ctx),
			std::move(params) )->so_direct_mbox();

	auto h_coop = env.register_coop( std::move(coop_holder) );

	return { std::move(h_coop), std::move(auth_mbox) };
}

std::string_view
to_string_view( failure_reason_t reason ) noexcept
{
	using namespace std::string_view_literals;

	std::string_view r{ "<unknown>" };

	switch( reason )
	{
	case failure_reason_t::unknown_user: r = "unknown_user"sv; break;

	case failure_reason_t::target_blocked: r = "target_blocked"sv; break;

	case failure_reason_t::auth_operation_timedout:
			r = "auth_operation_timedout"sv;
	break;
	}

	return r;
}

//
// completion_token_t
//
completion_token_t::~completion_token_t()
{}

} /* namespace arataga::authentificator */

