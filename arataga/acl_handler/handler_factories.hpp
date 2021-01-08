/*!
 * @file
 * @brief Перечень фабрик для создания connection_handler-ов.
 */

#pragma once

#include <arataga/acl_handler/connection_handler_ifaces.hpp>
#include <arataga/acl_handler/byte_sequence.hpp>

namespace arataga::acl_handler
{

[[nodiscard]]
connection_handler_shptr_t
make_protocol_detection_handler(
	handler_context_holder_t ctx,
	handler_context_t::connection_id_t id,
	asio::ip::tcp::socket connection );

[[nodiscard]]
connection_handler_shptr_t
make_socks5_auth_method_detection_handler(
	handler_context_holder_t ctx,
	handler_context_t::connection_id_t id,
	asio::ip::tcp::socket connection,
	byte_sequence_t whole_first_pdu,
	std::chrono::steady_clock::time_point created_at );

[[nodiscard]]
connection_handler_shptr_t
make_http_handler(
	handler_context_holder_t ctx,
	handler_context_t::connection_id_t id,
	asio::ip::tcp::socket connection,
	byte_sequence_t whole_first_pdu,
	std::chrono::steady_clock::time_point created_at );

[[nodiscard]]
connection_handler_shptr_t
make_data_transfer_handler(
	handler_context_holder_t ctx,
	handler_context_t::connection_id_t id,
	asio::ip::tcp::socket in_connection,
	asio::ip::tcp::socket out_connection,
	traffic_limiter_unique_ptr_t traffic_limiter );

} /* arataga::acl_handler */

