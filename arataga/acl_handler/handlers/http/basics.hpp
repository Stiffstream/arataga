/*!
 * @file
 * @brief Basic stuff for implementation of HTTP connection-handlers.
 */

#pragma once

#include <arataga/acl_handler/connection_handler_ifaces.hpp>
#include <arataga/acl_handler/buffers.hpp>

#include <arataga/acl_handler/exception.hpp>

#include <restinio/http_headers.hpp>

#include <nodejs/http_parser/http_parser.h>

#include <memory>
#include <vector>

namespace arataga::acl_handler
{

namespace handlers::http
{

/*!
 * @brief Storage for data required for parsing of a HTTP-request.
 *
 * This data includes:
 *
 * - http_parser object that holds the state of request parsing;
 * - buffer with incoming data to be parsed (including the size of
 *   the data in the buffer);
 * - the position in the buffer for the next parsing step.
 *
 * It's assumed that an instance of that type will be created when
 * a new request is received (or when a new outgoing connection is
 * created) and then will be transferred from one connection-handler
 * to another.
 *
 * @note
 * This object holds http_parser but doesn't contain http_parser_settings
 * because a particular http_parser_settings depends on connection-handler.
 * Every connection-handler that needs to parse HTTP-request will create
 * own instance of http_parser_settings.
 */
struct http_handling_state_t
{
	http_parser m_parser;

	std::vector< char > m_incoming_data;
	std::size_t m_incoming_data_size;

	std::size_t m_next_execute_position{};

	http_handling_state_t( const http_handling_state_t & ) = delete;
	http_handling_state_t( http_handling_state_t && ) = delete;

	http_handling_state_t(
		std::size_t io_chunk_size,
		byte_sequence_t whole_first_pdu )
	{
		if( io_chunk_size < whole_first_pdu.size() )
			throw acl_handler_ex_t{
					fmt::format( "first PDU is too big ({} bytes) to fit "
							"into io_buffer ({} bytes)",
							whole_first_pdu.size(),
							io_chunk_size )
			};

		m_incoming_data.resize( io_chunk_size );
		std::transform(
				std::begin(whole_first_pdu),
				std::end(whole_first_pdu),
				std::begin(m_incoming_data),
				[]( std::byte b ) { return static_cast<char>(b); } );
		m_incoming_data_size = whole_first_pdu.size();

		http_parser_init( &m_parser, HTTP_REQUEST );
	}
};

/*!
 * @brief Alias for unique_ptr to http_handling_state.
 */
using http_handling_state_unique_ptr_t = std::unique_ptr<
		http_handling_state_t
	>;

/*!
 * @brief Type of object for collecting additional info about HTTP-request.
 *
 * An instance of http_handling_state_t holds "raw" data related to
 * a HTTP-request. Various artefacts produced during the processing
 * of that "raw" data are collected inside an instance of
 * request_info_t type.
 */
struct request_info_t
{
	//! HTTP-method of the request.
	/*!
	 * It is stored here to be easily accessible.
	 */
	http_method m_method;

	//! The value of request-target from the start-line.
	std::string m_request_target;

	//! Parsed HTTP header fields from the incoming request.
	restinio::http_header_fields_t m_headers;

	//! The target-host value for the request.
	/*!
	 * This value is extracted from Host field or from request-target.
	 */
	std::string m_target_host;
	//! The target-port value for the request.
	/*!
	 * This value is extracted from Host field of from request-target.
	 */
	std::uint16_t m_target_port{ 80u };

	//! Should the connection be kept after the processing of the request.
	/*!
	 * Because we are working with HTTP/1.1 the connection should be kept
	 * by default.
	 */
	bool m_keep_user_end_alive{ true };
};

//
// basic_http_handler_t
//
/*!
 * @brief Base class for implementations of HTTP connection-handlers.
 *
 * Containts the stuff necessary for all other HTTP connection-handlers.
 */
class basic_http_handler_t : public connection_handler_t
{
public:
	using connection_handler_t::connection_handler_t;

protected:
	// ATTENTION: replaces the current connection_handler by a new one.
	// That new handler does the send of negative response.
	void
	send_negative_response_then_close_connection(
			delete_protector_t delete_protector,
			can_throw_t can_throw,
			remove_reason_t reason,
			arataga::utils::string_literal_t whole_response );
};

//
// handler_with_out_connection_t
//
/*!
 * @brief Base class for implementations of HTTP connection-handlers
 * that require an outgoing connection.
 *
 * Contains m_out_connection for outgoing connection.
 *
 * Reimplements release() for closing m_out_connection.
 */
class handler_with_out_connection_t : public basic_http_handler_t
{
protected:
	//! Outgoing connection to the target host.
	asio::ip::tcp::socket m_out_connection;

public:
	//! Constructor for the case when there is no outgoing connection yet.
	handler_with_out_connection_t(
		handler_context_holder_t ctx,
		handler_context_t::connection_id_t id,
		asio::ip::tcp::socket in_connection );

	//! Constructor for the case when an outgoing connection already exists.
	handler_with_out_connection_t(
		handler_context_holder_t ctx,
		handler_context_t::connection_id_t id,
		asio::ip::tcp::socket in_connection,
		asio::ip::tcp::socket out_connection );
	
	void
	release() noexcept override;
};

} /* namespace arataga::acl_handler */

} /* namespace handlers::http */

