/*!
 * @file
 * @brief Implementation of connection-hander for ordinary HTTP methods.
 */

#include <arataga/acl_handler/handlers/http/basics.hpp>
#include <arataga/acl_handler/handlers/http/factories.hpp>
#include <arataga/acl_handler/handlers/http/helpers.hpp>
#include <arataga/acl_handler/handlers/http/responses.hpp>

#include <arataga/acl_handler/handler_factories.hpp>
#include <arataga/acl_handler/out_data_piece.hpp>

#include <arataga/utils/subview_of.hpp>

#include <restinio/helpers/http_field_parsers/connection.hpp>

#include <noexcept_ctcheck/pub.hpp>

#include <list>
#include <iterator>

namespace arataga::acl_handler
{

namespace handlers::http
{

using namespace arataga::utils::string_literals;

//
// ordinary_method_handler_t
//
/*!
 * @brief Connection-handler for processing HTTP methods different
 * from CONNECT (like GET, POST, DELETE, and so on).
 */
class ordinary_method_handler_t final : public handler_with_out_connection_t
{
	//! Enumeration of possible stages of handling the respose from
	//! the target host.
	enum class status_line_processing_stage_t
	{
		not_started,
		status_code_written,
		completed
	};

	//! The state of the response processing.
	struct response_processing_state_t
	{
		//! Content of the status-line.
		/*!
		 * Cleaned up after sending to the user.
		 */
		std::string m_status_line;

		//! Stage of status-line processing.
		status_line_processing_stage_t m_status_line_stage{
				status_line_processing_stage_t::not_started
			};

		//! Name of the current HTTP header field.
		std::string m_last_header_name;
		//! Value of the current HTTP header field.
		std::string m_last_header_value;
		//! Flag that tells that the value of the current HTTP header field
		//! was extracted.
		bool m_on_header_value_called{ false };
		//! The total size of parsed HTTP header fields.
		std::size_t m_total_headers_size{ 0u };

		//! List of extracted HTTP header fields.
		restinio::http_header_fields_t m_headers;

		//! Flag that tells that the parsing of ordinary HTTP header fields
		//! has been completed.
		bool m_leading_headers_completed{ false };
	};

	//! Enumeration of possible states of handling incoming HTTP message.
	enum incoming_http_message_stage_t
	{
		//! The reading of the incoming HTTP message is in progress.
		in_progress,
		//! The reading of the incoming HTTP message completed, there is no
		//! need to read more.
		message_completed
	};

	//! Type of pointer to method that should be called when
	//! a write operation completes.
	using write_completed_handler_t =
		void (ordinary_method_handler_t::*)(
				delete_protector_t, can_throw_t);

	/*!
	 * @brief State of a single direction.
	 *
	 * Such an object is created after the primary processing and
	 * authentification of the user.
	 */
	struct direction_state_t
	{
		using out_piece_container_t = std::list< out_data_piece_t >;

		//! State of HTTP-parsing for that direction.
		http_handling_state_unique_ptr_t m_http_state;

		//! Settings for http_parser for the direction.
		http_parser_settings m_http_parser_settings;

		//! Socket that is used for this direction.
		asio::ip::tcp::socket & m_channel;

		//! Name of that direction (for logging).
		const arataga::utils::string_literal_t m_name;

		//! List of pending outgoing data blocks.
		out_piece_container_t m_pieces_read;

		//! traffic_limiter's specific type for the direction.
		traffic_limiter_t::direction_t m_traffic_direction;

		//! Flag that tells that the direction is still alive.
		/*!
		 * The direction is alive until its closure has been diagnosed.
		 */
		bool m_is_alive{ true };

		//! Flag that tells that traffic-limit has been exceeded.
		bool m_is_traffic_limit_exceeded{ false };

		//! The stage of incoming HTTP-message processing for the direction.
		incoming_http_message_stage_t m_incoming_message_stage{
				incoming_http_message_stage_t::in_progress
			};

		//! A handler that should be called after the completion
		//! of the current write operation.
		write_completed_handler_t m_on_write_completed;

		//! How many bytes were sent to this direction from the opposite
		//! direction.
		/*!
		 * If this is the used_end dir, then that value tells how many
		 * bytes read from the target_end dir were sent to the user_end dir.
		 *
		 * This is the counter of bytes sent. In reality there could be
		 * less data written because the current write operation can
		 * still be in progress.
		 */
		std::uint_least64_t m_bytes_from_opposite_dir{ 0u };

		direction_state_t(
			http_handling_state_unique_ptr_t http_state,
			asio::ip::tcp::socket & channel,
			arataga::utils::string_literal_t name,
			traffic_limiter_t::direction_t traffic_direction,
			write_completed_handler_t on_write_completed )
			:	m_http_state{ std::move(http_state) }
			,	m_channel{ channel }
			,	m_name{ name }
			,	m_traffic_direction{ traffic_direction }
			,	m_on_write_completed{ on_write_completed }
		{}

		[[nodiscard]]
		bool
		is_dead() const noexcept
		{
			return !m_is_alive;
		}
	};

	//! Brief description of the requist that is being processed.
	/*!
	 * This description is necessary for logging.
	 */
	struct brief_request_info_t
	{
		//! HTTP-method of the request.
		http_method m_method;

		//! Value of request-target for the request.
		std::string m_request_target;

		//! Value of Host header field for the request.
		std::string m_host_field_value;

		//! Flag that tells that the connection should be kept after
		//! the processing of the request.
		bool m_keep_user_end_alive;
	};

	//! traffic-limiter for the user.
	traffic_limiter_unique_ptr_t m_traffic_limiter;

	//! The state of user_end direction.
	/*!
	 * This is direction from the user to ACL.
	 */
	direction_state_t m_user_end;
	//! The state of target_end direction.
	/*!
	 * This is direction from ACL to the target host.
	 */
	direction_state_t m_target_end;

	//! Timepoint of the last successful read (from any direction).
	std::chrono::steady_clock::time_point m_last_read_at{
			std::chrono::steady_clock::now()
		};

	//! State of the processing of the response from the target host.
	response_processing_state_t m_response_processing_state;

	//! Brief description of HTTP-request that is beging processed.
	const brief_request_info_t m_brief_request_info;

public:
	ordinary_method_handler_t(
		handler_context_holder_t ctx,
		handler_context_t::connection_id_t id,
		asio::ip::tcp::socket in_connection,
		http_handling_state_unique_ptr_t request_state,
		request_info_t request_info,
		traffic_limiter_unique_ptr_t traffic_limiter,
		asio::ip::tcp::socket out_connection )
		:	handler_with_out_connection_t{
				std::move(ctx),
				id,
				std::move(in_connection),
				std::move(out_connection)
			}
		,	m_traffic_limiter{ std::move(traffic_limiter) }
		,	m_user_end{
				std::move(request_state),
				m_connection,
				"user_end"_static_str,
				traffic_limiter_t::direction_t::from_user,
				&ordinary_method_handler_t::
						user_end_default_write_completed_handler
			}
		,	m_target_end{
				std::make_unique< http_handling_state_t >(
						make_first_chunk_for_next_handler(
								first_chunk_t{ context().config().io_chunk_size() },
								0u,
								0u ) ),
				m_out_connection,
				"target_end"_static_str,
				traffic_limiter_t::direction_t::from_target,
				&ordinary_method_handler_t::
						target_end_default_write_completed_handler
			}
		,	m_brief_request_info{ make_brief_request_info( request_info ) }
	{
		// We can throw exceptions in the constructor.
		::arataga::utils::exception_handling_context_t exception_ctx;

		tune_http_settings( exception_ctx.make_can_throw_marker() );

		// It is not good to call this method in the constructor:
		// if an exception is thrown then this exception will be caught
		// something upper in the stack and the connection will be closed
		// without sending a negative response. It means that
		// the user will detect the closed connection instead of
		// "400 Bad Request" response.
		//
		// To fix that this call can be moved into on_start().
		// But this requires storing of request_info in the handler.
		//
		// But even the movement into on_start() doens't guarantee
		// the send of negative response in all the cases. Because there are
		// two main reasons of an exception:
		//
		// 1. Invalid data in the incoming stream. Those invalid data
		// can be detected in the input stream at any moment, not necessarly
		// at the begining. Thus, if we process chunked encoding then we
		// can successfully read and process several chunks, but only
		// then corrupted data can be found. In that case we can't send
		// a negative response because we are already in the process of
		// transferring the response from the target host to the user.
		// 
		// 2. No available memory or other low-level error during the parsing.
		// Such error can be detected after the start of transferring
		// the response from the target host to the user. In the case of
		// bad_alloc we can be in the situation where we can't make
		// a new response at all.
		//
		// So the call to make_user_end_outgoing_data() is kept here for now.
		make_user_end_outgoing_data(
				exception_ctx.make_can_throw_marker(),
				request_info );
	}

protected:
	void
	on_start_impl( delete_protector_t delete_protector ) override
	{
		wrap_action_and_handle_exceptions(
			delete_protector,
			[this]( delete_protector_t, can_throw_t can_throw )
			{
				::arataga::logging::wrap_logging(
						proxy_logging_mode,
						spdlog::level::info,
						[this, can_throw]( auto level )
						{
							log_message_for_connection(
									can_throw,
									level,
									fmt::format( "outgoing-request={}, host={}, "
											"request-target={}",
											http_method_str( m_brief_request_info.m_method ),
											::arataga::utils::subview_of<100>(
													m_brief_request_info.m_host_field_value ),
											::arataga::utils::subview_of<100>(
													m_brief_request_info.m_request_target )
									)
								);
						} );

				// There is data in user_end that should be sent into target_end.
				write_data_read_from( can_throw, m_user_end, m_target_end );

				// Now we can read incoming data from the target end.
				initiate_async_read_for_direction( can_throw, m_target_end );
			} );
	}

	void
	on_timer_impl( delete_protector_t delete_protector ) override
	{
		wrap_action_and_handle_exceptions(
			delete_protector,
			[this]( delete_protector_t delete_protector, can_throw_t can_throw ) {
			{
				// Don't expect this but let's make a check for safety...
				if( m_user_end.is_dead() && m_target_end.is_dead() )
				{
					return log_and_remove_connection(
							delete_protector,
							can_throw,
							remove_reason_t::unexpected_and_unsupported_case,
							spdlog::level::warn,
							"both connections are closed" );
				}
			}

			{
				// At least one of the directions is still alive.
				// We can check inactivity time.
				const auto now = std::chrono::steady_clock::now();

				if( m_last_read_at +
						context().config().idle_connection_timeout() < now )
				{
					return log_and_remove_connection(
							delete_protector,
							can_throw,
							remove_reason_t::no_activity_for_too_long,
							spdlog::level::warn,
							"no data read for long time" );
				}
			}

			// If bandwidth limit was exceeded we should recheck it again.
			// A special case related to HTTP: the limit is checked for
			// write operations, not for read ones.
			if( m_user_end.m_is_traffic_limit_exceeded )
			{
				initiate_write_outgoing_data_or_read_next_incoming_portion(
						can_throw, m_user_end, m_target_end );
			}
			if( m_target_end.m_is_traffic_limit_exceeded )
			{
				initiate_write_outgoing_data_or_read_next_incoming_portion(
						can_throw, m_target_end, m_user_end );
			}
		} );
	}

public:
	arataga::utils::string_literal_t
	name() const noexcept override
	{
		using namespace arataga::utils::string_literals;
		return "http-ordinary-method-handler"_static_str;
	}

private:
	[[nodiscard]]
	brief_request_info_t
	make_brief_request_info( const request_info_t & info )
	{
		brief_request_info_t result;

		result.m_method = info.m_method;
		result.m_request_target = info.m_request_target;

		// Now all servers expects to see port 80 in Host field.
		// So if the target port is 80 then Host won't have the port
		// specified, only the host name.
		// The target_port is added to Host only if it isn't 80.
		if( 80u == info.m_target_port )
			result.m_host_field_value = info.m_target_host;
		else
			result.m_host_field_value = fmt::format( "{}:{}",
							info.m_target_host,
							info.m_target_port );

		result.m_keep_user_end_alive = info.m_keep_user_end_alive;

		return result;
	}

	void
	tune_http_settings( can_throw_t /*can_throw*/ )
	{
		// http_parser for user_end direction is already initialized.
		// But it's paused and has old data.
		m_user_end.m_http_state->m_parser.data = this;
		http_parser_pause( &(m_user_end.m_http_state->m_parser), 0 );

		// http_parser for the target_end direction has to be initialized.
		http_parser_init( &(m_target_end.m_http_state->m_parser), HTTP_RESPONSE );
		m_target_end.m_http_state->m_parser.data = this;

		//
		// Handlers for data from the user.
		//
		http_parser_settings_init( &m_user_end.m_http_parser_settings );

		m_user_end.m_http_parser_settings.on_message_begin =
			helpers::make_http_parser_callback<
					&ordinary_method_handler_t::user_end__on_message_begin >();

		m_user_end.m_http_parser_settings.on_url =
			helpers::make_http_parser_callback<
					&ordinary_method_handler_t::user_end__on_url >();

		m_user_end.m_http_parser_settings.on_status =
			helpers::make_http_parser_callback<
					&ordinary_method_handler_t::user_end__on_status >();

		m_user_end.m_http_parser_settings.on_header_field =
			helpers::make_http_parser_callback<
					&ordinary_method_handler_t::user_end__on_header_field >();

		m_user_end.m_http_parser_settings.on_header_value =
			helpers::make_http_parser_callback<
					&ordinary_method_handler_t::user_end__on_header_value >();

		m_user_end.m_http_parser_settings.on_headers_complete =
			helpers::make_http_parser_callback<
					&ordinary_method_handler_t::user_end__on_headers_complete >();

		m_user_end.m_http_parser_settings.on_body =
			helpers::make_http_parser_callback<
					&ordinary_method_handler_t::user_end__on_body >();

		m_user_end.m_http_parser_settings.on_message_complete =
			helpers::make_http_parser_callback<
					&ordinary_method_handler_t::user_end__on_message_complete >();

		m_user_end.m_http_parser_settings.on_chunk_header =
			helpers::make_http_parser_callback<
					&ordinary_method_handler_t::user_end__on_chunk_header >();

		m_user_end.m_http_parser_settings.on_chunk_complete =
			helpers::make_http_parser_callback<
					&ordinary_method_handler_t::user_end__on_chunk_complete >();

		//
		// Handlers for data from the target host.
		//
		http_parser_settings_init( &m_target_end.m_http_parser_settings );

		m_target_end.m_http_parser_settings.on_message_begin =
			helpers::make_http_parser_callback<
					&ordinary_method_handler_t::target_end__on_message_begin >();

		m_target_end.m_http_parser_settings.on_url =
			helpers::make_http_parser_callback<
					&ordinary_method_handler_t::target_end__on_url >();

		m_target_end.m_http_parser_settings.on_status =
			helpers::make_http_parser_callback<
					&ordinary_method_handler_t::target_end__on_status >();

		m_target_end.m_http_parser_settings.on_header_field =
			helpers::make_http_parser_callback<
					&ordinary_method_handler_t::target_end__on_header_field >();

		m_target_end.m_http_parser_settings.on_header_value =
			helpers::make_http_parser_callback<
					&ordinary_method_handler_t::target_end__on_header_value >();

		m_target_end.m_http_parser_settings.on_headers_complete =
			helpers::make_http_parser_callback<
					&ordinary_method_handler_t::target_end__on_headers_complete >();

		m_target_end.m_http_parser_settings.on_body =
			helpers::make_http_parser_callback<
					&ordinary_method_handler_t::target_end__on_body >();

		m_target_end.m_http_parser_settings.on_message_complete =
			helpers::make_http_parser_callback<
					&ordinary_method_handler_t::target_end__on_message_complete >();

		m_target_end.m_http_parser_settings.on_chunk_header =
			helpers::make_http_parser_callback<
					&ordinary_method_handler_t::target_end__on_chunk_header >();

		m_target_end.m_http_parser_settings.on_chunk_complete =
			helpers::make_http_parser_callback<
					&ordinary_method_handler_t::target_end__on_chunk_complete >();
	}

	void
	make_user_end_outgoing_data(
		can_throw_t can_throw,
		const request_info_t & request_info )
	{
		// Collect the pieces of outgoing data into one buffer.
		fmt::memory_buffer out_data;

		// The start-line is going first.
		// We use HTTP/1.1 always.
		fmt::format_to(
				out_data,
				"{} {} HTTP/1.1\r\n",
				http_method_str(request_info.m_method),
				request_info.m_request_target );

		// The Host header field is going next.
		fmt::format_to(
				out_data,
				"Host: {}\r\n",
				m_brief_request_info.m_host_field_value );

		// Form the list of header fields that should go to the target host.
		fill_headers_for_outgoing_request( can_throw, request_info, out_data );

		// This the end of the header.
		fmt::format_to( out_data, "\r\n" );

		m_user_end.m_pieces_read.push_back( std::move(out_data) );

		try_complete_parsing_of_initial_user_end_data( can_throw );
	}

	static void
	fill_headers_for_outgoing_request(
		can_throw_t /*can_throw*/,
		const request_info_t & request_info,
		// Outgoing data should be written here.
		fmt::memory_buffer & out_data )
	{
		// Assume that all unnecessary fields were deleted earliers.
		// So just copy remaining fields as is.
		request_info.m_headers.for_each_field(
			[&]( const auto & field )
			{
				fmt::format_to(
						out_data,
						"{}: {}\r\n", field.name(), field.value() );
			} );
	}

	void
	try_complete_parsing_of_initial_user_end_data(
		can_throw_t /*can_throw*/ )
	{
		http_handling_state_t & http_state = *(m_user_end.m_http_state);

		// Try to parse data in the incoming buffer.
		const auto bytes_to_parse = http_state.m_incoming_data_size
				- http_state.m_next_execute_position;
		if( !bytes_to_parse )
			return;

		// Hope it's not a UB.
		const char * buffer_to_parse =
				reinterpret_cast<const char *>(http_state.m_first_chunk.buffer())
				+ http_state.m_next_execute_position;
		const auto bytes_parsed = http_parser_execute(
				&(http_state.m_parser),
				&(m_user_end.m_http_parser_settings),
				buffer_to_parse,
				bytes_to_parse );
		http_state.m_next_execute_position += bytes_parsed;

		// Handle the parsing result.
		if( const auto err = http_state.m_parser.http_errno;
				HPE_OK != err && HPE_PAUSED != err )
			throw acl_handler_ex_t{
					fmt::format( "unexpected error during parsing of "
							"remaining part of incoming request, errno: {}",
							static_cast<unsigned>(http_state.m_parser.http_errno) )
				};

		// NOTE: there was a check for the presence of unparsed data
		// initially. But this check was removed later.
		// If the parsing was paused inside user_end__on_message_complete
		// then it allows to handle request pipelining. And some unparsed
		// data will be present in the buffer.
		// If parsing wasn't paused inside user_end__on_message_complete
		// (it means that request pipelining isn't supported) then there
		// is no sense to check for unparsed data. Because if such data
		// is here then we'll get a parsing error later when we'll try
		// to parse the next incoming HTTP-message (an error will be
		// produced in user_end__on_message_begin).
	}

	// Handler for the completion of write of data read from the user_end.
	void
	user_end_default_write_completed_handler(
		delete_protector_t /*delete_protector*/,
		can_throw_t can_throw )
	{
		// If the incoming request wasn't read completely then we
		// have to read more.
		if( incoming_http_message_stage_t::in_progress ==
				m_user_end.m_incoming_message_stage )
		{
			initiate_async_read_for_direction( can_throw, m_user_end );
		}
	}

	// Default handler for the completion of write of data read from the
	// target_end.
	void
	target_end_default_write_completed_handler(
		delete_protector_t /*delete_protector*/,
		can_throw_t can_throw )
	{
		// This handler is used only while the whole HTTP-response isn't read.
		// That is why the only thing we can do here is to read more.
		initiate_async_read_for_direction( can_throw, m_target_end );
	}

	// The handler for the completion of write of data read from the
	// target_end that is used for finishing of writing of the HTTP-response
	// and switching for the normal procedure of connection-handler
	// completion.
	void
	target_end_normal_finilization_write_completed_handler(
		delete_protector_t delete_protector,
		can_throw_t can_throw)
	{
		// If there is no need to keep the connection then we can
		// simply delete the handler.
		// But in the opposite case we have to create a new
		// initial_http_handler.
		if( m_brief_request_info.m_keep_user_end_alive )
		{
			// If there is some unparsed data, it should be passed to a new
			// connection-handler.
			auto first_chunk_data = make_first_chunk_for_next_handler(
					std::move(m_user_end.m_http_state->m_first_chunk),
					m_user_end.m_http_state->m_next_execute_position,
					m_user_end.m_http_state->m_incoming_data_size );

			replace_handler(
					delete_protector,
					can_throw,
					[this, fcd = std::move(first_chunk_data)]( can_throw_t ) mutable
					{
						return make_http_handler(
								std::move(m_ctx),
								m_id,
								std::move(m_connection),
								std::move(fcd),
								std::chrono::steady_clock::now() );
					} );
		}
		else
		{
			remove_handler(
					delete_protector,
					remove_reason_t::normal_completion );
		}
	}


	// The handler for the completion of write of data read from the
	// target_end that is used in the case of forced deletion of
	// the current connection-handler.
	void
	target_end_destroy_handler_write_completed_handler(
		delete_protector_t delete_protector,
		can_throw_t )
	{
		remove_handler(
				delete_protector,
				remove_reason_t::http_response_before_completion_of_http_request );
	}

	int
	user_end__on_message_begin( can_throw_t can_throw )
	{
		::arataga::logging::wrap_logging(
				proxy_logging_mode,
				spdlog::level::err,
				[this, can_throw]( auto level )
				{
					log_message_for_connection(
							can_throw,
							level,
							"unexpected case: new message is found in data stream "
							"from client" );
				} );

		return -1;
	}

	int
	user_end__on_url( can_throw_t can_throw,
		const char *,
		std::size_t )
	{
		::arataga::logging::wrap_logging(
				proxy_logging_mode,
				spdlog::level::err,
				[this, can_throw]( auto level )
				{
					log_message_for_connection(
							can_throw,
							level,
							"unexpected case: URL is found in data stream "
							"from client" );
				} );

		return -1;
	}

	int
	user_end__on_status( can_throw_t can_throw,
		const char *,
		std::size_t )
	{
		::arataga::logging::wrap_logging(
				proxy_logging_mode,
				spdlog::level::err,
				[this, can_throw]( auto level )
				{
					log_message_for_connection(
							can_throw,
							level,
							"unexpected case: status-line is found in data "
							"stream from client" );
				} );

		return -1;
	}

	int
	user_end__on_header_field( can_throw_t /*can_throw*/,
		const char *,
		std::size_t )
	{
		// It can only be a trailing-header in chunked encoding.
		// Because we don't support trailing-headers just ignore it.
		return 0;
	}

	int
	user_end__on_header_value( can_throw_t /*can_throw*/,
		const char *,
		std::size_t )
	{
		// It can only be a trailing-header in chunked encoding.
		// Because we don't support trailing-headers just ignore it.
		return 0;
	}

	int
	user_end__on_headers_complete( can_throw_t can_throw )
	{
		::arataga::logging::wrap_logging(
				proxy_logging_mode,
				spdlog::level::err,
				[this, can_throw]( auto level )
				{
					log_message_for_connection(
							can_throw,
							level,
							"unexpected case: repeated call of "
							"on_headers_complete callback" );
				} );

		return -1;
	}

	int
	user_end__on_body( can_throw_t /*can_throw*/,
		const char * data,
		std::size_t size )
	{
		// It's necessarty to write the current piece of data to
		// the outgoing stream.
		m_user_end.m_pieces_read.push_back( 
				// It's safe to use string_view because the data is
				// in incoming buffer that remains its value until the
				// write completes.
				std::string_view{ data, size } );

		return 0;
	}

	int
	user_end__on_message_complete( can_throw_t /*can_throw*/ )
	{
		m_user_end.m_incoming_message_stage =
				incoming_http_message_stage_t::message_completed;

		// Pause the parsing.
		//
		// eao197: I suspect that this behavior will help to deal
		// with request pipelining.
		http_parser_pause( &(m_user_end.m_http_state->m_parser), 1 );

		return 0;
	}

	int
	user_end__on_chunk_header( can_throw_t /*can_throw*/ )
	{
		// At this moment http_parser.content_length contains the size
		// of the current chunk. Use that value to form a header
		// for that chunk by ourselves.
		m_user_end.m_pieces_read.push_back(
				fmt::format( "{:x}\r\n",
						m_user_end.m_http_state->m_parser.content_length ) );

		return 0;
	}

	int
	user_end__on_chunk_complete( can_throw_t /*can_throw*/ )
	{
		m_user_end.m_pieces_read.push_back( ("\r\n"_static_str).as_view() );

		return 0;
	}

	int
	target_end__on_message_begin( can_throw_t /*can_throw*/ )
	{
		// Nothing to do here.
		return 0;
	}

	int
	target_end__on_url( can_throw_t can_throw,
		const char *,
		std::size_t )
	{
		::arataga::logging::wrap_logging(
				proxy_logging_mode,
				spdlog::level::err,
				[this, can_throw]( auto level )
				{
					log_message_for_connection(
							can_throw,
							level,
							"unexpected case: URL extracted from HTTP "
							"response (when HTTP status is expected" );
				} );

		return -1;
	}

	int
	target_end__on_status( can_throw_t can_throw,
		const char * data,
		std::size_t size )
	{
		const std::string_view reason_phrase{ data, size };

		// status-line can arrive by small parts. So we have to understand
		// on that stage we are.
		switch( m_response_processing_state.m_status_line_stage )
		{
		case status_line_processing_stage_t::not_started:
			// The beginning of the status-line should be formed.
			m_response_processing_state.m_status_line =
					fmt::format( "HTTP/1.1 {} {}",
							static_cast<unsigned short>(
									m_target_end.m_http_state->m_parser.status_code),
							reason_phrase );
			m_response_processing_state.m_status_line_stage =
					status_line_processing_stage_t::status_code_written;

			::arataga::logging::wrap_logging(
					proxy_logging_mode,
					spdlog::level::info,
					[this, can_throw, &reason_phrase]( auto level )
					{
						log_message_for_connection(
								can_throw,
								level,
								fmt::format( "incoming-reply=HTTP/{}.{} {} {}",
										m_target_end.m_http_state->m_parser.http_major,
										m_target_end.m_http_state->m_parser.http_minor,
										static_cast<unsigned short>(
												m_target_end.m_http_state->m_parser.status_code),
										::arataga::utils::subview_of<100>( reason_phrase )
								)
							);
					} );
		break;

		case status_line_processing_stage_t::status_code_written:
			m_response_processing_state.m_status_line += reason_phrase;
		break;

		case status_line_processing_stage_t::completed:
			// Don't expect that case.
			throw acl_handler_ex_t{
					fmt::format( "target_end__on_status called when "
							"status-line is already completed" )
				};
		}

		// The status-line shouldn't be too long.
		if( const auto lim =
				context().config().http_message_limits().m_max_status_line_length;
				lim < m_response_processing_state.m_status_line.size() )
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
										"status-line exceeds limit: size={}, limit={}",
										m_response_processing_state.m_status_line.size(),
										lim )
							);
					} );

			return -1;
		}

		return 0;
	}

	int
	target_end__on_header_field( can_throw_t can_throw,
		const char * data,
		std::size_t size )
	{
		if( m_response_processing_state.m_leading_headers_completed )
		{
			// This is a trailing-header, we ignore them for now.
			return 0;
		}

		if( const auto rc = try_complete_response_last_header( can_throw );
				0 != rc )
		{
			return rc;
		}

		m_response_processing_state.m_last_header_name.append( data, size );

		// The size of header name shouldn't be too long.
		if( const auto lim =
				context().config().http_message_limits().m_max_field_name_length;
				lim < m_response_processing_state.m_last_header_name.size() )
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
										"http-field name exceeds limit: size={}, "
										"limit={}",
										m_response_processing_state
											.m_last_header_name.size(),
										lim )
							);
					} );

			return -1;
		}

		return 0;
	}

	int
	target_end__on_header_value( can_throw_t can_throw,
		const char * data,
		std::size_t size )
	{
		if( m_response_processing_state.m_leading_headers_completed )
		{
			// This is a trailing-header, we ignore them for now.
			return 0;
		}

		m_response_processing_state.m_on_header_value_called = true;
		m_response_processing_state.m_last_header_value.append( data, size );

		// The header value shouldn't be too long.
		if( const auto lim =
				context().config().http_message_limits().m_max_field_value_length;
				lim < m_response_processing_state.m_last_header_value.size() )
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
										"http-field value exceeds limit: size={}, "
										"limit={}",
										m_response_processing_state
											.m_last_header_value.size(),
										lim )
							);
					} );

			return -1;
		}

		return 0;
	}

	void
	handle_connection_header_for_response( can_throw_t /*can_throw*/ )
	{
		using namespace restinio::http_field_parsers;

		constexpr std::string_view header_name{ "Connection" };

		auto & headers = m_response_processing_state.m_headers;

		// Collect all occurences of Connection field.
		connection_value_t aggregated;
		headers.for_each_value_of(
				header_name,
				[&]( const auto field_value ) {
					const auto r = connection_value_t::try_parse( field_value );
					if( r )
					{
						std::move( r->values.begin(), r->values.end(),
								std::back_inserter( aggregated.values ) );
					}

					// Ignore errors.
					return restinio::http_header_fields_t::continue_enumeration();
				} );

		// Have to process collected value.
		for( const auto & v : aggregated.values )
		{
			// The "close" value in Connection has the special meaning.
			// All other values are names of headers to be removed.
			if( "close" != v )
			{
				// Transfer-Encoding should be kept because we don't
				// transform the body and just retranslate it as is.
				if( "transfer-encoding" != v )
					headers.remove_all_of( v );
			}
		}

		// The Connection header fields should be removed too.
		headers.remove_all_of( header_name );
	}

	void
	remove_hop_by_hop_headers_from_response( can_throw_t /*can_throw*/ )
	{
		// Remove all top-to-hop headers.
		//
		// NOTE: some headers should be kept, for example:
		// - Transfer-Encoding, becase we just retranslate the body as is.
		//
		// The list of hop-to-hop headers was found here:
		// https://nathandavison.com/blog/abusing-http-hop-by-hop-request-headers
		// https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Connection
		using namespace std::string_view_literals;
		static constexpr std::initializer_list< std::string_view >
			hop_by_hop_headers{
					"Keep-Alive"sv, "TE"sv, "Trailer"sv, "Proxy-Authentificate"sv
			};

		for( const auto & h : hop_by_hop_headers )
			m_response_processing_state.m_headers.remove_all_of( h );
	}

	void
	concat_response_headers_to(
		can_throw_t /*can_throw*/,
		fmt::memory_buffer & out_data )
	{
		const auto & headers = m_response_processing_state.m_headers;
		headers.for_each_field( [&out_data]( const auto & field ) {
				fmt::format_to(
						out_data,
						"{}: {}\r\n",
						field.name(),
						field.value() );
			} );
	}

	int
	target_end__on_headers_complete( can_throw_t can_throw )
	{
		// Set the flag that leading header fields are completed.
		// It allows us to ignore trailing-headers.
		m_response_processing_state.m_leading_headers_completed = true;

		if( const auto rc = try_complete_response_last_header( can_throw );
				0 != rc )
		{
			return rc;
		}

		// Use a single buffer for collecting small parts of response.
		fmt::memory_buffer out_data;

		complete_and_write_status_line( out_data );

		handle_connection_header_for_response( can_throw );
		remove_hop_by_hop_headers_from_response( can_throw );
		concat_response_headers_to( can_throw, out_data );

		// The separator between headers and the body.
		fmt::format_to( out_data, "\r\n" );

		// Send that all as one piece.
		m_target_end.m_pieces_read.push_back( std::move( out_data ) );

		return 0;
	}

	int
	target_end__on_body( can_throw_t /*can_throw*/,
		const char * data,
		std::size_t size )
	{
		// Have to write another part of the body.
		m_target_end.m_pieces_read.push_back( 
				// It's safe to use string_view because the data will be
				// kept in the incoming buffer until the write completes.
				std::string_view{ data, size } );

		return 0;
	}

	int
	target_end__on_message_complete( can_throw_t /*can_throw*/ )
	{
		m_target_end.m_incoming_message_stage =
				incoming_http_message_stage_t::message_completed;

		// Don't pause the parsing because don't expect additional
		// data from the target_end.

		return 0;
	}

	int
	target_end__on_chunk_header( can_throw_t /*can_throw*/ )
	{
		// At this moment http_parser.content_length contains the size
		// of the current chunk. Use that value to form a header
		// for that chunk by ourselves.
		m_target_end.m_pieces_read.push_back(
				fmt::format( "{:x}\r\n",
						m_target_end.m_http_state->m_parser.content_length ) );
		return 0;
	}

	int
	target_end__on_chunk_complete( can_throw_t /*can_throw*/ )
	{
		m_target_end.m_pieces_read.push_back( ("\r\n"_static_str).as_view() );

		return 0;
	}

	// The return value the same as for http_parser's callbacks.
	[[nodiscard]]
	int
	try_complete_response_last_header( can_throw_t can_throw )
	{
		if( m_response_processing_state.m_on_header_value_called )
		{
			m_response_processing_state.m_total_headers_size +=
					m_response_processing_state.m_last_header_name.size() +
					m_response_processing_state.m_last_header_value.size();

			if( const auto lim =
					context().config().http_message_limits().m_max_total_headers_size;
					lim < m_response_processing_state.m_total_headers_size )
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
											m_response_processing_state
												.m_total_headers_size,
											lim )
								);
						} );

				return -1;
			}

			m_response_processing_state.m_headers.add_field(
					std::move(m_response_processing_state.m_last_header_name),
					std::move(m_response_processing_state.m_last_header_value) );

			m_response_processing_state.m_last_header_name.clear();
			m_response_processing_state.m_last_header_value.clear();
			m_response_processing_state.m_on_header_value_called = false;
		}

		return 0;
	}

	void
	complete_and_write_status_line( fmt::memory_buffer & out_data )
	{
		if( status_line_processing_stage_t::completed !=
				m_response_processing_state.m_status_line_stage )
		{
			fmt::format_to( out_data, "{}\r\n", 
					m_response_processing_state.m_status_line );

			m_response_processing_state.m_status_line.clear();
			m_response_processing_state.m_status_line_stage =
					status_line_processing_stage_t::completed;
		}
	}

	void
	try_parse_data_read(
		delete_protector_t delete_protector,
		can_throw_t can_throw,
		direction_state_t & src_dir )
	{
		// Parse the data from the input buffer.
		const auto bytes_to_parse = src_dir.m_http_state->m_incoming_data_size
				- src_dir.m_http_state->m_next_execute_position;

		// Hope it's not a UB.
		const char * buffer_to_parse =
				reinterpret_cast<const char *>(src_dir.m_http_state->m_first_chunk.buffer())
				+ src_dir.m_http_state->m_next_execute_position;
		const auto bytes_parsed = http_parser_execute(
				&(src_dir.m_http_state->m_parser),
				&(src_dir.m_http_parser_settings),
				buffer_to_parse,
				bytes_to_parse );
		src_dir.m_http_state->m_next_execute_position += bytes_parsed;

		// Handle the parsing result.
		if( const auto err = src_dir.m_http_state->m_parser.http_errno;
				HPE_OK != err && HPE_PAUSED != err )
		{
			// The reaction to a failure depends on the direction and
			// amount of data written in the opposite direction.
			return react_to_direction_failure(
					delete_protector,
					can_throw,
					src_dir,
					remove_reason_t::protocol_error );
		}

		// Handle the result with the respect to the direction of data read.
		switch( src_dir.m_traffic_direction )
		{
		case traffic_limiter_t::direction_t::from_user:
			analyze_incoming_data_parsing_result_for_user_end( can_throw );
		break;

		case traffic_limiter_t::direction_t::from_target:
			analyze_incoming_data_parsing_result_for_target_end( can_throw );
		break;
		}
	}

	void
	react_to_direction_failure(
		delete_protector_t delete_protector,
		can_throw_t can_throw,
		const direction_state_t & src_dir,
		remove_reason_t remove_reason )
	{
		// A problem with the target_end direction should be handled
		// a special way: if nothing has been sent then "502 Bad Gateway"
		// should be sent.
		if( traffic_limiter_t::direction_t::from_target ==
				src_dir.m_traffic_direction )
		{
			if( 0u == m_user_end.m_bytes_from_opposite_dir )
			{
				return send_negative_response_then_close_connection(
						delete_protector,
						can_throw,
						remove_reason,
						response_bad_gateway_invalid_response );
			}
		}

		// In all other cases just close the connections.
		// We have read a garbage from the user_end or from the target_end
		// (but after sending something to the user).
		return remove_handler( delete_protector, remove_reason );
	}

	void
	analyze_incoming_data_parsing_result_for_user_end(
		can_throw_t can_throw )
	{
		// If HTTP-response hasn't read yet then we can send
		// outgoing data to the target_end. But if HTTP-response has been
		// read already, then we have to do nothing, because we
		// have to wait the completion of writing of the HTTP-response,
		// and then we should remove the current handler.
		switch( m_target_end.m_incoming_message_stage )
		{
		case incoming_http_message_stage_t::in_progress:
			// HTTP-response hasn't been read. So we can send
			// another part of the request to the target host.
			initiate_write_outgoing_data_or_read_next_incoming_portion(
					can_throw, m_user_end, m_target_end );
		break;

		case incoming_http_message_stage_t::message_completed:
			// Nothing to do. Just wait the completion of writing
			// the HTTP-response.
		break;
		}
	}

	void
	analyze_incoming_data_parsing_result_for_target_end(
		can_throw_t can_throw )
	{
		// We should write a part of HTTP-response in any case.
		// The question is: should we replace on_write_completed handler?
		switch( m_target_end.m_incoming_message_stage )
		{
		case incoming_http_message_stage_t::in_progress:
			/* Nothing to change */
		break;

		case incoming_http_message_stage_t::message_completed:
			// We depend on the status of HTTP-request:
			// if it isn't read yet than we have to remove handler after
			// writing the HTTP-response.
			switch( m_user_end.m_incoming_message_stage )
			{
			case incoming_http_message_stage_t::in_progress:
				m_target_end.m_on_write_completed =
					&ordinary_method_handler_t::
							target_end_destroy_handler_write_completed_handler;
			break;

			case incoming_http_message_stage_t::message_completed:
				m_target_end.m_on_write_completed =
					&ordinary_method_handler_t::
							target_end_normal_finilization_write_completed_handler;
			}
		break;
		}

		// Write the next part of HTTP-response.
		initiate_write_outgoing_data_or_read_next_incoming_portion(
				can_throw, m_target_end, m_user_end );
	}

	void
	initiate_write_outgoing_data_or_read_next_incoming_portion(
		can_throw_t can_throw,
		direction_state_t & src_dir,
		direction_state_t & dest_dir )
	{
		if( src_dir.m_pieces_read.empty() )
		{
			// There is no data read. Continue the reading.
			initiate_async_read_for_direction( can_throw, src_dir );
		}
		else
		{
			write_data_read_from( can_throw, src_dir, dest_dir );
		}
	}

	// This method shouldn't be called if src_dir.m_pieces_read is empty.
	void
	write_data_read_from(
		can_throw_t /*can_throw*/,
		direction_state_t & src_dir,
		direction_state_t & dest_dir )
	{
		if( src_dir.m_pieces_read.empty() )
			// We don't expect that case.
			throw acl_handler_ex_t{
					"a call to write_data_read_from for "
					"empty src_dir.m_pieces_read"
			};

		auto & piece_to_send = src_dir.m_pieces_read.front();

		// How many data we can send without exceeding the bandwidth limit.
		const auto reserved_capacity = m_traffic_limiter->reserve_read_portion(
				src_dir.m_traffic_direction,
				piece_to_send.remaining() );

		// If nothing to send then the bandwidth limit is exceeded.
		src_dir.m_is_traffic_limit_exceeded =
				( 0u == reserved_capacity.m_capacity );

		if( src_dir.m_is_traffic_limit_exceeded )
			// Have to wait for the next turn.
			return;

		asio::const_buffer data_to_write{
				piece_to_send.asio_buffer().data(),
				reserved_capacity.m_capacity
		};

		// Have to count the number of bytes sent.
		// This info will be used later to detect was something sent
		// to dest_dir or not.
		dest_dir.m_bytes_from_opposite_dir += data_to_write.size();

// Kept here for debugging purposes.
#if 0
		std::cout << "*** ougoing data: '"
				<< std::string_view{
							reinterpret_cast<const char *>(data_to_write.data()),
							data_to_write.size()
						}
				<< std::endl;
#endif

		asio::async_write(
				dest_dir.m_channel,
				data_to_write,
				with<const asio::error_code &, std::size_t>().make_handler(
					[this, &src_dir, &dest_dir, reserved_capacity](
						delete_protector_t delete_protector,
						can_throw_t can_throw,
						const asio::error_code & ec, std::size_t bytes )
					{
						reserved_capacity.release(
								*m_traffic_limiter,
								src_dir.m_traffic_direction,
								ec,
								bytes );

						on_write_result(
								delete_protector,
								can_throw,
								src_dir, dest_dir,
								ec,
								bytes );
					} )
			);
	}

	void
	initiate_async_read_for_direction(
		can_throw_t /*can_throw*/,
		// Source direction for reading.
		direction_state_t & src_dir )
	{
		auto buffer = asio::buffer(
				src_dir.m_http_state->m_first_chunk.buffer(),
				src_dir.m_http_state->m_first_chunk.capacity() );

		src_dir.m_channel.async_read_some(
				buffer,
				with<const asio::error_code &, std::size_t>().make_handler(
					[this, &src_dir](
						delete_protector_t delete_protector,
						can_throw_t can_throw,
						const asio::error_code & ec, std::size_t bytes )
					{
						on_read_result(
								delete_protector,
								can_throw,
								src_dir,
								ec,
								bytes );
					} )
			);
	}

	[[nodiscard]]
	remove_reason_t
	detect_remove_reason_from_read_result_error_code(
		can_throw_t can_throw,
		direction_state_t & src_dir,
		const asio::error_code & ec )
	{
		/*
		 * The current HTTP-message processing logic is: the reading
		 * from a direction is stopped as soon as the current HTTP-message
		 * is fully parsed. So, if we detect the EOF before the
		 * completion of the HTTP-message then it is abnormal case.
		 * It's true regardless of closed direction (user_end or target_end).
		 */

		// Mark the direction as closed regardless of the error.
		src_dir.m_is_alive = false;

		auto remove_reason = remove_reason_t::unexpected_and_unsupported_case;

		if( asio::error::eof == ec )
		{
			// The further actions depend on the direction type.
			if( traffic_limiter_t::direction_t::from_target ==
					src_dir.m_traffic_direction )
				remove_reason = remove_reason_t::target_end_broken;
			else
				remove_reason = remove_reason_t::user_end_broken;
		}
		else if( asio::error::operation_aborted == ec )
		{
			// Nothing to do.
			remove_reason = remove_reason_t::current_operation_canceled;
		}
		else
		{
			// There can be a case when we cancelled the operation but
			// Asio reports a error different from operation_aborted.
			if( src_dir.m_channel.is_open() )
			{
				// It's an I/O error.

				::arataga::logging::wrap_logging(
						proxy_logging_mode,
						spdlog::level::debug,
						[this, can_throw, &src_dir, &ec]( auto level )
						{
							log_message_for_connection(
									can_throw,
									level,
									fmt::format( "error reading data from {}: {}",
											src_dir.m_name,
											ec.message() ) );
						} );

				remove_reason = remove_reason_t::io_error;
			}
			else
				remove_reason = remove_reason_t::current_operation_canceled;
		}

		return remove_reason;
	}

	/*!
	 * Handling of reading result from src_dir.
	 *
	 * There are two important factors that should be taken into account:
	 *
	 * 1. If @a ec contains an error then @a bytes_transferred value can
	 * be ignored. It means that if error code is EOF then all previously
	 * read data has been processed in the earlier call of on_read_result
	 * (in that call @a ec contained no error).
	 *
	 * 2. There is no any pending data in src_dir that wasn't sent to dest_dir.
	 * It is because we don't read new data while the old data isn't written
	 * yet.
	 */
	void
	on_read_result(
		delete_protector_t delete_protector,
		can_throw_t can_throw,
		direction_state_t & src_dir,
		const asio::error_code & ec,
		std::size_t bytes_transferred )
	{
// Kept here for debugging purposes.
#if 0
		::arataga::logging::wrap_logging(
				proxy_logging_mode,
				spdlog::level::trace,
				[this, can_throw, &src_dir, ec, bytes_transferred]( auto level )
				{
					log_message_for_connection(
							can_throw,
							level,
							fmt::format( "on_read_result {}, ec: {}, bytes: {}",
									src_dir.m_name, ec.message(), bytes_transferred) );
				} );
#endif

		if( ec )
		{
			// We have to clode the connection or send "502 Bad Gateway"
			// response in dependency of the direction type.
			return react_to_direction_failure(
					delete_protector,
					can_throw,
					src_dir,
					detect_remove_reason_from_read_result_error_code(
							can_throw, src_dir, ec ) );
		}
		else
		{
			src_dir.m_http_state->m_incoming_data_size = bytes_transferred;
			src_dir.m_http_state->m_next_execute_position = 0u;

			// Last activity timepoint has to be updated.
			m_last_read_at = std::chrono::steady_clock::now();

			// We have to parse data read and send them into 
			// the opposite direction.
			try_parse_data_read( delete_protector, can_throw, src_dir );
		}
	}

	void
	on_write_result(
		delete_protector_t delete_protector,
		can_throw_t can_throw,
		direction_state_t & src_dir,
		direction_state_t & dest_dir,
		const asio::error_code & ec,
		std::size_t bytes_transferred )
	{
		// Just stop the work in the case of an error.
		if( ec )
		{
			log_and_remove_connection_on_io_error(
					delete_protector,
					can_throw, ec,
					fmt::format( "writting to {}", dest_dir.m_name ) );
		}
		else
		{
			if( src_dir.m_pieces_read.empty() )
				// Don't expect this, because it is the result of
				// writing the first item from src_dir.m_pieces_read.
				throw acl_handler_ex_t{
					fmt::format( "on_write_result is called for "
							"empty {}.m_pieces_read",
							src_dir.m_name )
				};

			auto & piece_to_send = src_dir.m_pieces_read.front();
			piece_to_send.increment_bytes_written( bytes_transferred );
			if( !piece_to_send.remaining() )
				src_dir.m_pieces_read.pop_front();

			// If there is some remaining data it has to be written.
			if( !src_dir.m_pieces_read.empty() )
				write_data_read_from( can_throw, src_dir, dest_dir );
			else
				// All pending data was written, so further actions
				// will be performed by completion handler.
				(this->*src_dir.m_on_write_completed)( delete_protector, can_throw );
		}
	}
};

//
// make_ordinary_method_handler
//
[[nodiscard]]
connection_handler_shptr_t
make_ordinary_method_handler(
	handler_context_holder_t ctx,
	handler_context_t::connection_id_t id,
	asio::ip::tcp::socket in_connection,
	http_handling_state_unique_ptr_t http_state,
	request_info_t request_info,
	traffic_limiter_unique_ptr_t traffic_limiter,
	asio::ip::tcp::socket out_connection )
{
	return std::make_shared< ordinary_method_handler_t >(
			std::move(ctx),
			id,
			std::move(in_connection),
			std::move(http_state),
			std::move(request_info),
			std::move(traffic_limiter),
			std::move(out_connection) );
}

} /* namespace arataga::acl_handler */

} /* namespace handlers::http */

