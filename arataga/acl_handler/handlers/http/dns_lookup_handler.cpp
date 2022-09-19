/*!
 * @file
 * @brief Implementation of dns_lookup_handler.
 */

#include <arataga/acl_handler/handlers/http/basics.hpp>
#include <arataga/acl_handler/handlers/http/factories.hpp>
#include <arataga/acl_handler/handlers/http/helpers.hpp>
#include <arataga/acl_handler/handlers/http/responses.hpp>

#include <arataga/utils/overloaded.hpp>

namespace arataga::acl_handler
{

namespace handlers::http
{

//
// dns_lookup_handler_t
//
/*!
 * @brief Connection-handler that performs DNS lookup.
 */
class dns_lookup_handler_t final : public basic_http_handler_t
{
	//! Request parsing state.
	http_handling_state_unique_ptr_t m_request_state;

	//! Additional info for the request.
	request_info_t m_request_info;

	//! Traffic limiter for the user.
	traffic_limiter_unique_ptr_t m_traffic_limiter;

	//! Timepoint when DNS lookup was started.
	std::chrono::steady_clock::time_point m_created_at;

public:
	dns_lookup_handler_t(
		handler_context_holder_t ctx,
		handler_context_t::connection_id_t id,
		asio::ip::tcp::socket connection,
		http_handling_state_unique_ptr_t request_state,
		request_info_t request_info,
		traffic_limiter_unique_ptr_t traffic_limiter )
		:	basic_http_handler_t{ std::move(ctx), id, std::move(connection) }
		,	m_request_state{ std::move(request_state) }
		,	m_request_info{ std::move(request_info) }
		,	m_traffic_limiter{ std::move(traffic_limiter) }
		,	m_created_at{ std::chrono::steady_clock::now() }
	{}

protected:
	void
	on_start_impl() override
	{
		context().async_resolve_hostname(
				m_id,
				m_request_info.m_target_host,
				with<const dns_resolving::hostname_result_t &>()
				.make_handler(
					[this]( const dns_resolving::hostname_result_t & result )
					{
						on_hostname_result( result );
					} )
			);
	}

	void
	on_timer_impl() override
	{
		if( std::chrono::steady_clock::now() >= m_created_at +
				context().config().dns_resolving_timeout() )
		{
			::arataga::logging::proxy_mode::warn(
					[this]( auto level )
					{
						log_message_for_connection(
								level,
								"DNS-lookup timed out" );
					} );

			send_negative_response_then_close_connection(
					remove_reason_t::current_operation_timed_out,
					response_request_timeout_dns_lookup_timeout );
		}
	}

public:
	arataga::utils::string_literal_t
	name() const noexcept override
	{
		using namespace arataga::utils::string_literals;
		return "http-dns-lookup-handler"_static_str;
	}

private:
	void
	on_hostname_result(
		const dns_resolving::hostname_result_t & result )
	{
		std::visit( ::arataga::utils::overloaded{
				[&]( const dns_resolving::hostname_found_t & info )
				{
					// Now we know the target address.
					// But the connection will be established by the next handler.
					const asio::ip::tcp::endpoint target_endpoint{
							info.m_ip,
							m_request_info.m_target_port
						};

					replace_handler(
							[this, &target_endpoint]()
							{
								return make_target_connector_handler(
										std::move(m_ctx),
										m_id,
										std::move(m_connection),
										std::move(m_request_state),
										std::move(m_request_info),
										target_endpoint,
										std::move(m_traffic_limiter) );
							} );
				},
				[&]( const dns_resolving::hostname_not_found_t & info )
				{
					// There is no info about the target.
					// We have to log that fact, send the negative response
					// and close the connection.
					::arataga::logging::proxy_mode::warn(
							[this, &info]( auto level )
							{
								log_message_for_connection(
										level,
										fmt::format( "DNS resolving failure: {}",
												info.m_error_desc ) );
							} );

					send_negative_response_then_close_connection(
							remove_reason_t::unresolved_target,
							response_bad_gateway_dns_lookup_failure );
				}
			},
			result );
	}
};

//
// make_dns_lookup_handler
//
[[nodiscard]]
connection_handler_shptr_t
make_dns_lookup_handler(
	handler_context_holder_t ctx,
	handler_context_t::connection_id_t id,
	asio::ip::tcp::socket connection,
	http_handling_state_unique_ptr_t request_state,
	request_info_t request_info,
	traffic_limiter_unique_ptr_t traffic_limiter )
{
	return std::make_shared< dns_lookup_handler_t >(
			std::move(ctx),
			id,
			std::move(connection),
			std::move(request_state),
			std::move(request_info),
			std::move(traffic_limiter) );
}

} /* namespace arataga::acl_handler */

} /* namespace handlers::http */

