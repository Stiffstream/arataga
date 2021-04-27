/*!
 * @file
 * @brief The implementation of initial_http_handler.
 */

#include <arataga/acl_handler/handlers/http/basics.hpp>
#include <arataga/acl_handler/handlers/http/factories.hpp>
#include <arataga/acl_handler/handlers/http/helpers.hpp>
#include <arataga/acl_handler/handlers/http/responses.hpp>

#include <arataga/utils/overloaded.hpp>
#include <arataga/utils/subview_of.hpp>

#include <restinio/helpers/http_field_parsers/connection.hpp>

#include <algorithm>
#include <iterator>

namespace arataga::acl_handler
{

namespace handlers::http
{

//
// initial_http_handler_t
//
/*!
 * @brief The initial handler of HTTP-connection.
 *
 * This handler makes a decision about further processing of the connection.
 */
class initial_http_handler_t final : public basic_http_handler_t
{
	// A special marker that indicates that we are in valid state
	// before the change of connection-handler.
	struct valid_state_t {};

	// Special marker that indicates that we are in an invalid state and
	// can't do the replacement of connection-handler.
	// A negative response should be sent instead, then the connection
	// should be stopped.
	struct invalid_state_t
	{
		//! Description that should be sent to the user.
		arataga::utils::string_literal_t m_response;
	};

	//! The result of validity check of the incoming request.
	using validity_check_result_t = std::variant<
			valid_state_t, invalid_state_t >;

	//! The state of HTTP-request processing.
	http_handling_state_unique_ptr_t m_request_state;

	//! Additional info for the HTTP-request that will be collected
	//! during the parsing of the request.
	request_info_t m_request_info;

	//! Settings for the HTTP-parser.
	http_parser_settings m_http_parser_settings;

	//! Flag that indicates that the parsing of the incoming request started.
	/*!
	 * If the user uses keep-alive connection that the following
	 * scenario can happen:
	 *
	 * - the user send the first request;
	 * - the request will be processed and the response will be sent to
	 *   the user;
	 * - a new connection-handler will be created for the connection for
	 *   waiting for a new incoming request;
	 * - the user doesn't send anything new.
	 *
	 * In that scenarion the connection has to be closed after a timeout
	 * without sending anything to the client. But we should know was
	 * something received from the client or not.
	 *
	 * This flag tells us about presence of some incoming data from the
	 * client.
	 *
	 * It'll be set in on_message_begin().
	 */
	bool m_incoming_message_started{ false };

	//! The flag that tells that we have to create the next
	//! connection-handler.
	bool m_should_next_handler_be_created{ false };

	//! The timepoint when the connection was accepted.
	std::chrono::steady_clock::time_point m_created_at;

	//! Object for collecting a name of the current HTTP header field.
	std::string m_current_http_field_name;
	//! Object for collecting a value of the current HTTP header field.
	std::string m_current_http_field_value;
	//! The flag that tells that the value of the current HTTP header field
	//! has been extracted.
	bool m_on_header_value_called{ false };
	//! The total size of all HTTP header fields.
	std::size_t m_total_headers_size{ 0u };

	//! How many bytes were parsed during the request processing.
	/*!
	 * This value will be used during error handling for I/O errors.
	 *
	 * If socket has been closed on remote side but nothing was read
	 * from it then it isn't an error and this case can't be logged
	 * with `warning` or higher levels.
	 */
	std::size_t m_total_bytes_parsed{ 0u };

public:
	initial_http_handler_t(
		handler_context_holder_t ctx,
		handler_context_t::connection_id_t id,
		asio::ip::tcp::socket connection,
		byte_sequence_t whole_first_pdu,
		std::chrono::steady_clock::time_point created_at )
		:	basic_http_handler_t{ std::move(ctx), id, std::move(connection) }
		,	m_request_state{
				std::make_unique< http_handling_state_t >(
						context().config().io_chunk_size(),
						whole_first_pdu )
			}
		,	m_created_at{ created_at }
	{
		m_request_state->m_parser.data = this;

		// Settings for HTTP-parser should also be initialized here.
		initialize_http_parser_settings();
	}

protected:
	void
	on_start_impl( delete_protector_t delete_protector ) override
	{
		wrap_action_and_handle_exceptions(
			delete_protector,
			[this]( delete_protector_t delete_protector, can_throw_t can_throw )
			{
				// Try to parse existing data.
				try_handle_data_read( delete_protector, can_throw );
			} );
	}

	void
	on_timer_impl( delete_protector_t delete_protector ) override
	{
		if( std::chrono::steady_clock::now() >= m_created_at +
				context().config().http_headers_complete_timeout() )
		{
			wrap_action_and_handle_exceptions(
				delete_protector,
				[this]( delete_protector_t delete_protector, can_throw_t can_throw )
				{
					handle_headers_complete_timeout(
							delete_protector,
							can_throw );
				} );
		}
	}

public:
	arataga::utils::string_literal_t
	name() const noexcept override
	{
		using namespace arataga::utils::string_literals;
		return "http-initial-handler"_static_str;
	}

private:
	// Just delete connection-handler if the user didn't sent anything.
	// Or sends a negative response because of long time of waiting
	// the completeness of the request.
	void
	handle_headers_complete_timeout(
		delete_protector_t delete_protector,
		can_throw_t can_throw )
	{
		if( m_incoming_message_started )
		{
			// Client started the request.
			// In that case we should send a response.
			::arataga::logging::wrap_logging(
					proxy_logging_mode,
					spdlog::level::warn,
					[this, can_throw]( auto level )
					{
						log_message_for_connection(
								can_throw,
								level,
								"http_headers_complete timed out" );
					} );

			send_negative_response_then_close_connection(
					delete_protector,
					can_throw,
					remove_reason_t::current_operation_timed_out,
					response_request_timeout_headers_complete_timeout );
		}
		else
		{
			// There was no incoming data. No need to send a response.
			// Just close the connection.
			log_and_remove_connection(
					delete_protector,
					can_throw,
					remove_reason_t::http_no_incoming_request,
					spdlog::level::info,
					"no incoming HTTP request for a long time" );
		}
	}

	// The return value the same as for http_parser's callbacks.
	[[nodiscard]]
	int
	complete_current_field_if_necessary( can_throw_t can_throw )
	{
		if( m_on_header_value_called )
		{
			// This is the start of a new header field.
			m_total_headers_size +=
					m_current_http_field_name.size() +
					m_current_http_field_value.size();

			if( const auto lim =
					context().config().http_message_limits().m_max_total_headers_size;
					lim < m_total_headers_size )
			{
				::arataga::logging::wrap_logging(
						proxy_logging_mode,
						spdlog::level::err,
						[this, can_throw, &lim]( auto level )
						{
							log_message_for_connection(
									can_throw,
									level,
									fmt::format(
											"total http-fields size exceeds limit: "
											"size={}, limit={}",
											m_total_headers_size,
											lim )
								);
						} );

				return -1;
			}

			m_request_info.m_headers.add_field(
					std::move(m_current_http_field_name),
					std::move(m_current_http_field_value) );

			m_on_header_value_called = false;
		}

		return 0;
	}

	/*!
	 * @name http_parser's callbacks.
	 * @{
	 */
	int
	on_message_begin( can_throw_t /*can_throw*/ )
	{
		// Set the flag of the start of processing of new HTTP-request.
		// We can't handle time-outs right way without that flag.
		m_incoming_message_started = true;

		m_request_info.m_method = static_cast<http_method>(
				m_request_state->m_parser.method);

		// If we have bodyless HTTP method then a part of callbacks has
		// to be changed.
		if( helpers::is_bodyless_method( m_request_info.m_method ) )
		{
			m_http_parser_settings.on_headers_complete =
				helpers::make_http_parser_callback<
					&initial_http_handler_t::on_headers_complete_for_bodyless_method >();
			m_http_parser_settings.on_body =
				helpers::make_http_parser_callback<
					&initial_http_handler_t::on_body_for_bodyless_method >();

			m_http_parser_settings.on_chunk_header =
				helpers::make_http_parser_callback<
					&initial_http_handler_t::on_chunk_header_for_bodyless_method >();

			m_http_parser_settings.on_chunk_complete =
				helpers::make_http_parser_callback<
					&initial_http_handler_t::on_chunk_complete_for_bodyless_method >();
			m_http_parser_settings.on_message_complete =
				helpers::make_http_parser_callback<
					&initial_http_handler_t::on_message_complete_for_bodyless_method >();
		}

		return 0;
	}

	int
	on_url( can_throw_t can_throw, const char * data, std::size_t length )
	{
		m_request_info.m_request_target.append( data, length );
		if( const auto lim =
				context().config().http_message_limits().m_max_request_target_length;
				lim < m_request_info.m_request_target.size() )
		{
			::arataga::logging::wrap_logging(
					proxy_logging_mode,
					spdlog::level::err,
					[this, can_throw, &lim]( auto level )
					{
						log_message_for_connection(
								can_throw,
								level,
								fmt::format(
										"request-target exceeds limit: size={}, limit={}",
										m_request_info.m_request_target.size(),
										lim )
							);
					} );

			return -1;
		}

		return 0;
	}

	int
	on_status( can_throw_t can_throw, const char *, std::size_t )
	{
		// Don't expect a status on incoming request.
		::arataga::logging::wrap_logging(
				proxy_logging_mode,
				spdlog::level::err,
				[this, can_throw]( auto level )
				{
					log_message_for_connection(
							can_throw,
							level,
							"HTTP status found in an incoming HTTP request" );
				} );

		return -1;
	}

	int
	on_header_field(
		can_throw_t can_throw, const char * data, std::size_t length )
	{
		if( const auto rc = complete_current_field_if_necessary( can_throw );
				0 != rc )
		{
			return rc;
		}

		m_current_http_field_name.append( data, length );
		if( const auto lim =
				context().config().http_message_limits().m_max_field_name_length;
				lim < m_current_http_field_name.size() )
		{
			::arataga::logging::wrap_logging(
					proxy_logging_mode,
					spdlog::level::err,
					[this, can_throw, &lim]( auto level )
					{
						log_message_for_connection(
								can_throw,
								level,
								fmt::format(
										"http-field name exceeds limit: "
										"size={}, limit={}",
										m_current_http_field_name.size(),
										lim )
							);
					} );

			return -1;
		}

		return 0;
	}

	int
	on_header_value(
		can_throw_t can_throw, const char * data, std::size_t length )
	{
		m_current_http_field_value.append( data, length );
		m_on_header_value_called = true;
		if( const auto lim =
				context().config().http_message_limits().m_max_field_value_length;
				lim < m_current_http_field_value.size() )
		{
			::arataga::logging::wrap_logging(
					proxy_logging_mode,
					spdlog::level::err,
					[this, can_throw, &lim]( auto level )
					{
						log_message_for_connection(
								can_throw,
								level,
								fmt::format(
										"http-field value exceeds limit: "
										"size={}, limit={}",
										m_current_http_field_value.size(),
										lim )
							);
					} );

			return -1;
		}

		return 0;
	}

	int
	on_headers_complete_for_bodyful_method(
		can_throw_t can_throw )
	{
		if( const auto rc = complete_current_field_if_necessary( can_throw );
				0 != rc )
		{
			return rc;
		}

		// Have to pause the parsing and start the analysis of
		// already parsed part of the HTTP-request.
		http_parser_pause( &(m_request_state->m_parser), 1 );

		// We can create the next handler for the request with a body.
		m_should_next_handler_be_created = true;

		return 0;
	}

	int
	on_headers_complete_for_bodyless_method(
		can_throw_t can_throw )
	{
		if( const auto rc = complete_current_field_if_necessary( can_throw );
				0 != rc )
		{
			return rc;
		}

		return 0;
	}

	int
	on_body_for_bodyful_method(
		can_throw_t can_throw, const char *, std::size_t )
	{
		// We shouldn't extract body on this stage of request processing.
		::arataga::logging::wrap_logging(
				proxy_logging_mode,
				spdlog::level::err,
				[this, can_throw]( auto level )
				{
					log_message_for_connection(
							can_throw,
							level,
							"unexpected failre: HTTP body extracted by "
							"initial_http_handler" );
				} );

		return -1;
	}

	int
	on_body_for_bodyless_method(
		can_throw_t can_throw, const char *, std::size_t )
	{
		// A body for bodyless method, this is an error.
		::arataga::logging::wrap_logging(
				proxy_logging_mode,
				spdlog::level::err,
				[this, can_throw]( auto level )
				{
					log_message_for_connection(
							can_throw,
							level,
							fmt::format( "unexpected failre: HTTP body for "
									"bodyless method {}",
									http_method_str( m_request_info.m_method ) )
						);
				} );

		return -1;
	}

	int
	on_message_complete_for_bodyful_method(
		can_throw_t can_throw )
	{
		// Don't expect the end of the HTTP-request for method with a body.
		::arataga::logging::wrap_logging(
				proxy_logging_mode,
				spdlog::level::err,
				[this, can_throw]( auto level )
				{
					log_message_for_connection(
							can_throw,
							level,
							"unexpected failre: HTTP message completed "
							"by initial_http_handler" );
				} );

		return -1;
	}

	int
	on_message_complete_for_bodyless_method( can_throw_t /*can_throw*/ )
	{
		// We can create the next handler for HTTP method without a body.
		m_should_next_handler_be_created = true;

		return 0;
	}

	int
	on_chunk_header_for_bodyful_method(
		can_throw_t can_throw )
	{
		// Don't expect chunks on that stage.
		::arataga::logging::wrap_logging(
				proxy_logging_mode,
				spdlog::level::err,
				[this, can_throw]( auto level )
				{
					log_message_for_connection(
							can_throw,
							level,
							"unexpected failre: HTTP body chunk extracted "
							"by initial_http_handler" );
				} );

		return -1;
	}

	int
	on_chunk_header_for_bodyless_method(
		can_throw_t can_throw )
	{
		// Don't expect a chunk for HTTP-method without a body.
		::arataga::logging::wrap_logging(
				proxy_logging_mode,
				spdlog::level::err,
				[this, can_throw]( auto level )
				{
					log_message_for_connection(
							can_throw,
							level,
							fmt::format( "unexpected failre: HTTP body chunk for "
									"bodyless method {}",
									http_method_str( m_request_info.m_method ) )
						);
				} );

		return -1;
	}

	int
	on_chunk_complete_for_bodyful_method(
		can_throw_t can_throw )
	{
		// Do not deal with chunks on that stage.
		::arataga::logging::wrap_logging(
				proxy_logging_mode,
				spdlog::level::err,
				[this, can_throw]( auto level )
				{
					log_message_for_connection(
							can_throw,
							level,
							"unexpected failre: HTTP body chunk completed "
							"by initial_http_handler" );
				} );

		return -1;
	}

	int
	on_chunk_complete_for_bodyless_method(
		can_throw_t can_throw )
	{
		// Don't expect chunks on that stage.
		::arataga::logging::wrap_logging(
				proxy_logging_mode,
				spdlog::level::err,
				[this, can_throw]( auto level )
				{
					log_message_for_connection(
							can_throw,
							level,
							fmt::format( "unexpected failre: HTTP body chunk for "
									"bodyless method {}",
									http_method_str( m_request_info.m_method ) )
						);
				} );

		return -1;
	}

	/*!
	 * @}
	 */

	void
	initialize_http_parser_settings()
	{
		http_parser_settings_init( &m_http_parser_settings );
		m_http_parser_settings.on_message_begin =
			helpers::make_http_parser_callback<
					&initial_http_handler_t::on_message_begin >();

		m_http_parser_settings.on_url =
			helpers::make_http_parser_callback<
					&initial_http_handler_t::on_url >();

		m_http_parser_settings.on_status =
			helpers::make_http_parser_callback<
					&initial_http_handler_t::on_status >();

		m_http_parser_settings.on_header_field =
			helpers::make_http_parser_callback<
					&initial_http_handler_t::on_header_field >();

		m_http_parser_settings.on_header_value =
			helpers::make_http_parser_callback<
					&initial_http_handler_t::on_header_value >();

		m_http_parser_settings.on_headers_complete =
			helpers::make_http_parser_callback<
					&initial_http_handler_t::on_headers_complete_for_bodyful_method >();

		m_http_parser_settings.on_body =
			helpers::make_http_parser_callback<
					&initial_http_handler_t::on_body_for_bodyful_method >();

		m_http_parser_settings.on_message_complete =
			helpers::make_http_parser_callback<
					&initial_http_handler_t::on_message_complete_for_bodyful_method >();

		m_http_parser_settings.on_chunk_header =
			helpers::make_http_parser_callback<
					&initial_http_handler_t::on_chunk_header_for_bodyful_method >();

		m_http_parser_settings.on_chunk_complete =
			helpers::make_http_parser_callback<
					&initial_http_handler_t::on_chunk_complete_for_bodyful_method >();
	}

	void
	try_handle_data_read(
		delete_protector_t delete_protector,
		can_throw_t can_throw )
	{
		const auto bytes_to_parse = m_request_state->m_incoming_data_size
				- m_request_state->m_next_execute_position;

		const auto bytes_parsed = http_parser_execute(
				&(m_request_state->m_parser),
				&m_http_parser_settings,
				&(m_request_state->m_incoming_data.at(
					m_request_state->m_next_execute_position)),
				bytes_to_parse );
		m_request_state->m_next_execute_position += bytes_parsed;

		if( HPE_OK != m_request_state->m_parser.http_errno &&
				HPE_PAUSED != m_request_state->m_parser.http_errno )
		{
			::arataga::logging::wrap_logging(
					proxy_logging_mode,
					spdlog::level::err,
					[this, can_throw]( auto level )
					{
						log_message_for_connection(
								can_throw,
								level,
								fmt::format( "http_parser returned an error: {}",
										http_errno_name( static_cast<http_errno>(
													m_request_state->m_parser.http_errno) ) )
							);
					} );

			// We encounter an error that doesn't allow us to continue
			// the processing.
			return send_negative_response_then_close_connection(
					delete_protector,
					can_throw,
					remove_reason_t::protocol_error,
					response_bad_request_parse_error_detected );
		}

		m_total_bytes_parsed += bytes_parsed;

		// Can we go to the next handler?
		if( m_should_next_handler_be_created )
		{
			return initiate_switch_to_next_handler(
					delete_protector,
					can_throw );
		}

		// If we're still here then there is no enough data in
		// the incoming buffer.
		// But check that again for the safety.

		// All the data have to be parsed. If not we have a problem.
		if( bytes_to_parse != bytes_parsed )
		{
			throw acl_handler_ex_t{
					fmt::format( "unexpected case: bytes_to_parse ({}) != "
							"bytes_parsed ({}), handling can't be continued",
							bytes_to_parse, bytes_parsed )
			};
		}

		// All that we can do is to initiate next read.
		m_request_state->m_incoming_data_size = 0u;
		// Use async_read_some to handle EOF by ourselves.
		auto buffer = asio::buffer(
				&(m_request_state->m_incoming_data[0]),
				m_request_state->m_incoming_data.size() );
		m_connection.async_read_some(
				buffer,
				with<const asio::error_code &, std::size_t>().make_handler(
					[this](
						delete_protector_t delete_protector,
						can_throw_t can_throw,
						const asio::error_code & ec, std::size_t bytes )
					{
						on_read_result( delete_protector, can_throw, ec, bytes );
					} )
			);
	}

	// Handling of Connection and Proxy-Connection header fields.
	std::optional< invalid_state_t >
	handle_connection_header(
		can_throw_t can_throw,
		std::string_view field_name )
	{
		std::optional< invalid_state_t > opt_error;

		using namespace restinio::http_field_parsers;

		// Collect all values of Connection into one place.
		connection_value_t aggregated;
		m_request_info.m_headers.for_each_value_of(
				field_name,
				[&]( const auto field_value ) {
					const auto r = connection_value_t::try_parse( field_value );
					if( r )
					{
						std::move( r->values.begin(), r->values.end(),
								std::back_inserter( aggregated.values ) );

						return restinio::http_header_fields_t::continue_enumeration();
					}
					else
					{
						// There is an error of parsing a header field.
						::arataga::logging::wrap_logging(
								proxy_logging_mode,
								spdlog::level::err,
								[this, can_throw, &field_name, &field_value, &r](
									auto level )
								{
									log_message_for_connection(
											can_throw,
											level,
											fmt::format(
													"unexpected case: unable to parse "
													"value of {} header: {}",
													field_name,
													make_error_description(
															r.error(), field_value )
											) );
								} );

						opt_error = invalid_state_t{
								response_bad_request_parse_error_detected
							};

						// There is no sense to continue.
						return restinio::http_header_fields_t::stop_enumeration();
					}
				} );

		// Now we can examine and handle collected values.
		for( const auto & v : aggregated.values )
		{
			if( "close" == v )
				// The connection should be closed after the processing.
				m_request_info.m_keep_user_end_alive = false;
			else
			{
				// All other values are treated as names of header fields
				// to be deleted.
				//
				// But the Transfer-Encoding field should be kept, because
				// we don't do the transformation of the request's body, but
				// just transfer the data as is.
				if( "transfer-encoding" != v )
					m_request_info.m_headers.remove_all_of( v );
			}
		}

		// The Connection header should also be deleted.
		m_request_info.m_headers.remove_all_of( field_name );

		return opt_error;
	}

	void
	remove_hop_by_hop_headers()
	{
		using namespace std::string_view_literals;

		// Remove all the fields those are hop-to-hop fields and should
		// not go from proxy to the target host.
		//
		// NOTE: some fields have to be kept. Thus, we kept:
		// - Proxy-Authorization, because it is required on the next
		// step and will be removed later;
		// - Transfer-Encoding, because we transfer the data in its source form.
		//
		// A list of hop-to-hop headers was found here:
		// https://nathandavison.com/blog/abusing-http-hop-by-hop-request-headers
		// https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Connection
		static constexpr std::initializer_list< std::string_view >
			hop_by_hop_headers{
					"Keep-Alive"sv, "TE"sv, "Trailer"sv, "Proxy-Authentificate"sv
			};

		for( const auto & h : hop_by_hop_headers )
			m_request_info.m_headers.remove_all_of( h );
	}

	// Performs the necessary modifications in header fields of
	// the HTTP-request.
	//
	// A value of invalid_state_t can be returned if some error
	// will be detected during the processing.
	std::optional< invalid_state_t >
	try_modify_request_headers( can_throw_t can_throw )
	{
		std::optional< invalid_state_t > opt_error;

		opt_error = handle_connection_header( can_throw, "Connection" );
		if( opt_error )
			return *opt_error;

		opt_error = handle_connection_header( can_throw, "Proxy-Connection" );
		if( opt_error )
			return *opt_error;

		remove_hop_by_hop_headers();

		return opt_error;
	}

	validity_check_result_t
	ensure_valid_state_before_switching_handler( can_throw_t can_throw )
	{
		// If we're handling HTTP CONNECT then we have to check that
		// incoming buffer is empty and there is nothing behind the
		// request itself.
		if( HTTP_CONNECT == m_request_info.m_method )
		{
			if( m_request_state->m_incoming_data_size
				!= m_request_state->m_next_execute_position )
			{
				::arataga::logging::wrap_logging(
						proxy_logging_mode,
						spdlog::level::err,
						[this, can_throw]( auto level )
						{
							log_message_for_connection(
									can_throw,
									level,
									fmt::format(
											"unexpected case: incoming buffer is not "
											"empty after parsing HTTP message with "
											"CONNECT request; buffer_size: {}, "
											"parsed_data_size: {}",
											m_request_state->m_incoming_data_size,
											m_request_state->m_next_execute_position )
								);
						} );

				return invalid_state_t{
						response_bad_request_unexpected_parsing_error
					};
			}
		}

		auto opt_error = try_modify_request_headers( can_throw );
		if( opt_error )
			return *opt_error;

		return valid_state_t{};
	}

	void
	initiate_switch_to_next_handler(
		delete_protector_t delete_protector,
		can_throw_t can_throw )
	{
		::arataga::logging::wrap_logging(
				proxy_logging_mode,
				spdlog::level::info,
				[this, can_throw]( auto level )
				{
					log_message_for_connection(
							can_throw,
							level,
							fmt::format( "incoming-request={}, request-target={}",
									http_method_str( m_request_info.m_method ),
									::arataga::utils::subview_of<100>(
											m_request_info.m_request_target )
							)
						);
				} );

		// Check the state before changing the connection-handler.
		std::visit(
			::arataga::utils::overloaded{
				[&]( const valid_state_t & ) {
					// Everything is fine, can delegate processing to the next
					// connection-handler.
					replace_handler(
							delete_protector,
							can_throw,
							[this]( can_throw_t )
							{
								return make_authentification_handler(
									std::move(m_ctx),
									m_id,
									std::move(m_connection),
									std::move(m_request_state),
									std::move(m_request_info) );
							} );
				},
				[&]( const invalid_state_t & err ) {
					send_negative_response_then_close_connection(
							delete_protector,
							can_throw,
							remove_reason_t::protocol_error,
							err.m_response );
				}
			},
			ensure_valid_state_before_switching_handler( can_throw ) );
	}

	void
	on_read_result(
		delete_protector_t delete_protector,
		can_throw_t can_throw,
		const asio::error_code & ec,
		std::size_t bytes_transferred )
	{
		if( ec )
		{
			remove_reason_t reason = remove_reason_t::io_error;

			// We have to delete ourselves anyway, but it is necessary
			// to select the right diagnostic.
			if( asio::error::operation_aborted == ec )
				reason = remove_reason_t::current_operation_canceled;
			else if( asio::error::eof == ec )
			{
				reason = remove_reason_t::user_end_closed_by_client;

				// If there is no any incoming data then the closed connection
				// isn't a problem. That can happen in keep-alive connections,
				// when a user sends a single request and then closes
				// the connection.
				if( m_total_bytes_parsed )
				{
					::arataga::logging::wrap_logging(
							proxy_logging_mode,
							spdlog::level::warn,
							[this, can_throw]( auto level )
							{
								log_message_for_connection(
										can_throw,
										level,
										fmt::format(
												"user_end closed by client after "
												"parsing {} byte(s) of incoming request",
												m_total_bytes_parsed ) );
							} );
				}
			}

			// If this is an I/O error then this fact should be logged
			// before removal of the connection-handler.
			if( remove_reason_t::io_error == reason )
				log_and_remove_connection_on_io_error(
						delete_protector,
						can_throw,
						ec,
						"reading incoming HTTP-request" );
			else
				// Just delete ourselves.
				remove_handler( delete_protector, reason );
		}
		else
		{
			// There is no errors. Can handle the data read.
			on_data_read( delete_protector, can_throw, bytes_transferred );
		}
	}

	void
	on_data_read(
		delete_protector_t delete_protector,
		can_throw_t can_throw,
		std::size_t bytes_transferred )
	{
		m_request_state->m_incoming_data_size = bytes_transferred;

		// The parsing should start from the beginning of the buffer
		// because all previous content was already parsed.
		m_request_state->m_next_execute_position = 0u;

		try_handle_data_read( delete_protector, can_throw );
	}
};

} /* namespace arataga::acl_handler */

[[nodiscard]]
connection_handler_shptr_t
make_http_handler(
	handler_context_holder_t ctx,
	handler_context_t::connection_id_t id,
	asio::ip::tcp::socket connection,
	first_chunk_for_next_handler_t first_chunk,
	std::chrono::steady_clock::time_point created_at )
{
	return std::make_shared< handlers::http::initial_http_handler_t >(
			std::move(ctx),
			id,
			std::move(connection),
//FIXME: should be replaced by a normal code!
			byte_sequence_t{},
			created_at );
}

} /* namespace handlers::http */

