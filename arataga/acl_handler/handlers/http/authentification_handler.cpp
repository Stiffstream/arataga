/*!
 * @file
 * @brief The implementation of authentification_handler.
 */

#include <arataga/acl_handler/handlers/http/basics.hpp>
#include <arataga/acl_handler/handlers/http/factories.hpp>
#include <arataga/acl_handler/handlers/http/helpers.hpp>
#include <arataga/acl_handler/handlers/http/responses.hpp>

#include <arataga/utils/overloaded.hpp>

#include <restinio/helpers/http_field_parsers/authorization.hpp>
#include <restinio/helpers/http_field_parsers/basic_auth.hpp>
#include <restinio/helpers/http_field_parsers/host.hpp>

namespace arataga::acl_handler
{

namespace handlers::http
{

//
// authentification_handler_t
//
/*!
 * @brief Connection-handler that performs authentification.
 */
class authentification_handler_t final : public basic_http_handler_t
{
	//! The result of successful extraction of username/password
	//! from header fields of HTTP-request.
	struct username_password_t
	{
		std::string m_username;
		std::string m_password;
	};

	//! The result for the case when username/password weren't set.
	struct no_username_password_provided_t {};

	//! The result for the case of an error during username/password
	//! extraction.
	struct username_password_extraction_failure_t
	{
		//! The description of the error.
		std::string m_description;
	};

	//! The generic result of username/password extraction from a HTTP-request.
	using username_password_extraction_result_t = std::variant<
			username_password_t,
			no_username_password_provided_t,
			username_password_extraction_failure_t
		>;

	//! The result of successful extraction of host/port from a HTTP-request.
	struct target_host_and_port_t
	{
		std::string m_host;
		std::uint16_t m_port;
	};

	//! The result of a failed extraction of host/port from a HTTP-request.
	struct target_host_and_port_extraction_failure_t
	{
		//! The description of the error.
		std::string m_description;
	};

	//! Generic result of host/port extraction from a HTTP-request.
	using target_host_and_port_extraction_result_t = std::variant<
			target_host_and_port_t,
			target_host_and_port_extraction_failure_t
		>;

	//! The result of successful transformation of request-target.
	struct update_request_target_success_t {};

	//! The result of failed transformation of request-target.
	struct update_request_target_failure_t
	{
		//! The description of the error.
		std::string m_description;
	};

	//! Generic result of request-target transformation.
	using update_request_target_result_t = std::variant<
			update_request_target_success_t,
			update_request_target_failure_t
		>;

	//! The state of HTTP-request parsing.
	http_handling_state_unique_ptr_t m_request_state;

	//! Additional info for the HTTP-request.
	/*!
	 * In the case of successful analisys of request-target and Host
	 * header field the actual target-host and target-port will be
	 * stored here.
	 */
	request_info_t m_request_info;

	//! The timepoint of the start of authentification.
	std::chrono::steady_clock::time_point m_created_at;

public:
	authentification_handler_t(
		handler_context_holder_t ctx,
		handler_context_t::connection_id_t id,
		asio::ip::tcp::socket connection,
		http_handling_state_unique_ptr_t request_state,
		request_info_t request_info )
		:	basic_http_handler_t{ std::move(ctx), id, std::move(connection) }
		,	m_request_state{ std::move(request_state) }
		,	m_request_info{ std::move(request_info) }
		,	m_created_at{ std::chrono::steady_clock::now() }
	{
	}

protected:
	void
	on_start_impl() override
	{
		wrap_action_and_handle_exceptions(
			[this]( can_throw_t can_throw )
			{
				// If username/password are set, they have to be extracted.
				auto username_password_extraction_result =
						try_extract_username_and_password( can_throw );
				// There is no sense to continue in the case of an error.
				if( auto * err = std::get_if<username_password_extraction_failure_t>(
						&username_password_extraction_result); err )
				{
					::arataga::logging::proxy_mode::err(
							[this, can_throw, err]( auto level )
							{
								log_message_for_connection(
										can_throw,
										level,
										fmt::format(
												"username/password extraction failure: {}",
												err->m_description ) );
							} );

					send_negative_response_then_close_connection(
							can_throw,
							remove_reason_t::protocol_error,
							response_bad_request_auth_params_extraction_failure );

					return;
				}

				// Detect the target host and port.
				auto target_host_and_port_extraction_result =
						try_extract_target_host_and_port( can_throw );
				if( auto * err = std::get_if<target_host_and_port_extraction_failure_t>(
						&target_host_and_port_extraction_result); err )
				{
					::arataga::logging::proxy_mode::err(
							[this, can_throw, err]( auto level )
							{
								log_message_for_connection(
										can_throw,
										level,
										fmt::format(
												"target-host+port extraction failure: {}",
												err->m_description ) );
							} );

					send_negative_response_then_close_connection(
							can_throw,
							remove_reason_t::protocol_error,
							response_bad_request_target_host_extraction_failure );

					return;
				}

				// If request-target is in absolute-form it should be
				// transformed into origin-form.
				auto update_request_target_result =
						try_update_request_target( can_throw );
				if( auto * err = std::get_if<update_request_target_failure_t>(
						&update_request_target_result); err )
				{
					::arataga::logging::proxy_mode::err(
							[this, can_throw, err]( auto level )
							{
								log_message_for_connection(
										can_throw,
										level,
										fmt::format(
												"update request-target failure: {}",
												err->m_description ) );
							} );

					send_negative_response_then_close_connection(
							can_throw,
							remove_reason_t::protocol_error,
							response_bad_request_invalid_request_target );

					return;
				}


				// Now we can initiate the authentification.
				initiate_authentification(
						can_throw,
						username_password_extraction_result,
						target_host_and_port_extraction_result );
			} );
	}

	void
	on_timer_impl() override
	{
		if( std::chrono::steady_clock::now() >= m_created_at +
				context().config().authentification_timeout() )
		{
			wrap_action_and_handle_exceptions(
				[this]( can_throw_t can_throw )
				{
					::arataga::logging::proxy_mode::warn(
							[this, can_throw]( auto level )
							{
								log_message_for_connection(
										can_throw,
										level,
										"authentification timed out" );
							} );

					// We can only send the response and close the connection.
					send_negative_response_then_close_connection(
							can_throw,
							remove_reason_t::current_operation_timed_out,
							response_proxy_auth_required_auth_timeout );
				} );
		}
	}

public:
	arataga::utils::string_literal_t
	name() const noexcept override
	{
		using namespace arataga::utils::string_literals;
		return "http-authenitification-handler"_static_str;
	}

private:
	[[nodiscard]]
	username_password_extraction_result_t
	try_extract_username_and_password(
		can_throw_t /*can_throw*/ )
	{
		auto opt_proxy_auth_value = m_request_info.m_headers.opt_value_of(
				restinio::http_field_t::proxy_authorization );
		if( !opt_proxy_auth_value )
			return no_username_password_provided_t{};

		using namespace restinio::http_field_parsers;
		const auto auth_value_result = authorization_value_t::try_parse(
				*opt_proxy_auth_value );
		if( !auth_value_result )
			return username_password_extraction_failure_t{
					make_error_description(
							auth_value_result.error(),
							*opt_proxy_auth_value )
			};

		auto & auth_value = *auth_value_result;
		if( "basic" != auth_value.auth_scheme )
			return username_password_extraction_failure_t{
					fmt::format( "unsupported auth-scheme: {}",
							auth_value.auth_scheme )
			};

		auto basic_auth_result = basic_auth::try_extract_params(
				auth_value );
		if( !basic_auth_result )
			return username_password_extraction_failure_t{
					fmt::format( "basic-auth param extraction failed: {}",
							static_cast<int>(basic_auth_result.error()) )
			};

		// The Proxy-Authorization header field isn't needed anymore
		// and should be removed.
		m_request_info.m_headers.remove_all_of(
				restinio::http_field_t::proxy_authorization );

		auto & basic_auth = *basic_auth_result;
		return username_password_t{
				std::move(basic_auth.username),
				std::move(basic_auth.password)
		};
	}

	[[nodiscard]]
	target_host_and_port_extraction_result_t
	try_extract_target_host_and_port( can_throw_t can_throw )
	{
		auto extraction_result =
				try_extract_target_host_and_port_from_request_target( can_throw );

		if( std::holds_alternative<target_host_and_port_extraction_failure_t>(
				extraction_result ) )
		{
			extraction_result =
					try_extract_target_host_and_port_from_host_field( can_throw );
		}

		// The Host header field should be removed after the extraction.
		m_request_info.m_headers.remove_all_of( restinio::http_field_t::host );

		return extraction_result;
	}

	[[nodiscard]]
	target_host_and_port_extraction_result_t
	try_extract_target_host_and_port_from_request_target(
		can_throw_t /*can_throw*/ )
	{
		// Try to deconstruct the URL.
		http_parser_url parser_url;
		http_parser_url_init( &parser_url );

		const auto & value_to_process = m_request_info.m_request_target;

		const auto parse_url_result = http_parser_parse_url(
				value_to_process.data(),
				value_to_process.size(),
				HTTP_CONNECT == m_request_state->m_parser.method,
				&parser_url );
		if( parse_url_result )
			return target_host_and_port_extraction_failure_t{
					fmt::format( "unable to parse request-target, "
							"http_parser_parse_url result: {}",
							parse_url_result )
			};

		const auto is_component_present = [&]( unsigned int component ) -> bool
			{
				return parser_url.field_set & (1u << component);
			};

		const auto try_extract_url_component =
			[&]( unsigned int component ) -> std::string_view
			{
				std::string_view result;
				if( is_component_present(component) )
					result = std::string_view{
							value_to_process.data() +
									parser_url.field_data[component].off,
							parser_url.field_data[component].len
					};
				return result;
			};

		const auto schema_sv = try_extract_url_component( UF_SCHEMA );
		const auto host_sv = try_extract_url_component( UF_HOST );

		std::optional< std::uint16_t > opt_port{ 80u };
		if( is_component_present( UF_PORT ) ) 
			opt_port = parser_url.port;

		if( !host_sv.empty() && opt_port )
			// We already have the result.
			return target_host_and_port_t{
					std::string{ host_sv },
					*opt_port
			};

		// If there are 'schema' and 'host' then the port number can be detected.
		if( !schema_sv.empty() && !host_sv.empty() )
		{
			if( "http" == schema_sv )
				return target_host_and_port_t{
						std::string{ host_sv },
						80u
				};
			else if( "https" == schema_sv )
				return target_host_and_port_t{
						std::string{ host_sv },
						443u
				};
			else
				// Unsupported scheme found.
				return target_host_and_port_extraction_failure_t{
						fmt::format( "unsupported schema in request-target: {}",
								schema_sv )
				};
		}

		// target-host and port are not extracted.
		return target_host_and_port_extraction_failure_t{
				fmt::format( "no target-host and port in request-target" )
		};
	}

	[[nodiscard]]
	target_host_and_port_extraction_result_t
	try_extract_target_host_and_port_from_host_field(
		can_throw_t /*can_throw*/ )
	{
		// If there are more than one Host header fields then the request
		// should be rejected. So count the fields.
		std::optional< std::string_view > opt_host;
		std::size_t host_occurrences{ 0u };

		m_request_info.m_headers.for_each_value_of(
				restinio::http_field_t::host,
				[&]( std::string_view value )
				{
					++host_occurrences;
					if( 1u == host_occurrences )
					{
						opt_host = value;
					}

					return restinio::http_header_fields_t::continue_enumeration();
				} );

		if( 0u == host_occurrences )
			return target_host_and_port_extraction_failure_t{
					"no Host http-field"
			};
		else if( 1u != host_occurrences )
			return target_host_and_port_extraction_failure_t{
					fmt::format( "too many Host http-fields: {}",
							host_occurrences )
			};

		// We have to parse the value.
		// The parser from RESTinio is used because http_parser_parse_url
		// can't handle values like "localhost:9090".
		using namespace restinio::http_field_parsers;

		auto parse_result = raw_host_value_t::try_parse( opt_host.value() );
		if( !parse_result )
			return target_host_and_port_extraction_failure_t{
					fmt::format( "unable to parse Host http-field: {}",
							make_error_description(
									parse_result.error(),
									opt_host.value() ) )
			};

		std::string target_host = std::visit(
				::arataga::utils::overloaded{
					[]( raw_host_value_t::reg_name_t & n ) -> std::string
					{
						return std::move(n.v);
					},
					[]( raw_host_value_t::ipv4_address_t & n ) -> std::string
					{
						return std::move(n.v);
					},
					[]( raw_host_value_t::ipv6_address_t & n ) -> std::string
					{
						return std::move(n.v);
					}
				},
				parse_result->host );

		return target_host_and_port_t{
				std::move(target_host),
				parse_result->port ? *(parse_result->port) : std::uint16_t{80u}
		};
	}

	[[nodiscard]]
	update_request_target_result_t
	try_update_request_target(
		can_throw_t /*can_throw*/ )
	{
		// The value of request-target should be borrowed into 
		// a separate object because we need a reference to that value
		// during the construction of new m_request_target value.
		std::string value_to_process{
				std::move(m_request_info.m_request_target)
			};

		// Try to deconstruct URL.
		http_parser_url parser_url;
		http_parser_url_init( &parser_url );

		const auto parse_url_result = http_parser_parse_url(
				value_to_process.data(),
				value_to_process.size(),
				HTTP_CONNECT == m_request_state->m_parser.method,
				&parser_url );
		if( parse_url_result )
			return update_request_target_failure_t{
					fmt::format( "unable to parse request-target, "
							"http_parser_parse_url result: {}",
							parse_url_result )
			};

		const auto is_component_present = [&]( unsigned int component ) -> bool
			{
				return parser_url.field_set & (1u << component);
			};

		const auto try_extract_url_component =
			[&]( unsigned int component ) -> std::string_view
			{
				std::string_view result;
				if( is_component_present(component) )
					result = std::string_view{
							value_to_process.data() +
									parser_url.field_data[component].off,
							parser_url.field_data[component].len
					};
				return result;
			};

		const auto path = try_extract_url_component( UF_PATH );
		const auto query = try_extract_url_component( UF_QUERY );
		const auto fragment = try_extract_url_component( UF_FRAGMENT );

		m_request_info.m_request_target.clear();

		// If request-target is specified in authority-form then 'path'
		// could be empty after the parsing.
		if( !path.empty() )
			m_request_info.m_request_target.append( path.data(), path.size() );
		else
			m_request_info.m_request_target += '/';

		if( !query.empty() )
		{
			m_request_info.m_request_target += '?';
			m_request_info.m_request_target.append( query.data(), query.size() );
		}

		if( !fragment.empty() )
		{
			m_request_info.m_request_target += '#';
			m_request_info.m_request_target.append( fragment.data(), fragment.size() );
		}

		return update_request_target_success_t{};
	}

	void
	initiate_authentification(
		can_throw_t /*can_throw*/,
		username_password_extraction_result_t & username_password_info,
		target_host_and_port_extraction_result_t & target_host_and_port_info )
	{
		std::optional< std::string > username;
		std::optional< std::string > password;
		if( auto * upi = std::get_if<username_password_t>(
				&username_password_info ) )
		{
			username = std::move(upi->m_username);
			password = std::move(upi->m_password);
		}

		// Info about target-host and target-port should be stored into
		// request_info because it'll necessary later.
		{
			auto & host_port =
				std::get< target_host_and_port_t >( target_host_and_port_info );
			m_request_info.m_target_host = std::move(host_port.m_host);
			m_request_info.m_target_port = host_port.m_port;
		}

		context().async_authentificate(
				m_id,
				authentification::request_params_t {
					// We work with IPv4 addresses only so don't expect
					// something else.
					m_connection.remote_endpoint().address().to_v4(),
					std::move(username),
					std::move(password),
					m_request_info.m_target_host,
					m_request_info.m_target_port
				},
				with<authentification::result_t>().make_handler(
					[this](
						can_throw_t can_throw,
						authentification::result_t result )
					{
						on_authentification_result(
								can_throw, result );
					} )
			);
	}

	void
	on_authentification_result(
		can_throw_t can_throw,
		authentification::result_t & result )
	{
		std::visit( ::arataga::utils::overloaded{
				[&]( authentification::success_t & info )
				{
					replace_handler(
							can_throw,
							[this, &info]( can_throw_t )
							{
								return make_dns_lookup_handler(
										std::move(m_ctx),
										m_id,
										std::move(m_connection),
										std::move(m_request_state),
										std::move(m_request_info),
										std::move(info.m_traffic_limiter) );
							} );
				},
				[&]( const authentification::failure_t & info )
				{
					::arataga::logging::proxy_mode::warn(
							[this, can_throw, &info]( auto level )
							{
								log_message_for_connection(
										can_throw,
										level,
										fmt::format(
												"user is not authentificated, reason: {}",
												authentification::to_string_literal(
														info.m_reason ) ) );
							} );

					send_negative_response_then_close_connection(
							can_throw,
							remove_reason_t::access_denied,
							response_proxy_auth_required_not_authorized );
				}
			},
			result );
	}
};

//
// make_authentification_handler
//
[[nodiscard]]
connection_handler_shptr_t
make_authentification_handler(
	handler_context_holder_t ctx,
	handler_context_t::connection_id_t id,
	asio::ip::tcp::socket connection,
	http_handling_state_unique_ptr_t request_state,
	request_info_t request_info )
{
	return std::make_shared< authentification_handler_t >(
			std::move(ctx),
			id,
			std::move(connection),
			std::move(request_state),
			std::move(request_info) );
}

} /* namespace arataga::acl_handler */

} /* namespace handlers::http */

