/*!
 * @file
 * @brief A list of factories for HTTP connection-handlers.
 */
#pragma once

#include <arataga/acl_handler/handlers/http/basics.hpp>

namespace arataga::acl_handler
{

namespace handlers::http
{

[[nodiscard]]
connection_handler_shptr_t
make_negative_response_sender(
	handler_context_holder_t ctx,
	handler_context_t::connection_id_t id,
	asio::ip::tcp::socket connection,
	remove_reason_t remove_reason,
	arataga::utils::string_literal_t negative_response );

[[nodiscard]]
connection_handler_shptr_t
make_authentification_handler(
	handler_context_holder_t ctx,
	handler_context_t::connection_id_t id,
	asio::ip::tcp::socket connection,
	http_handling_state_unique_ptr_t http_handling_state,
	request_info_t request_info );

[[nodiscard]]
connection_handler_shptr_t
make_dns_lookup_handler(
	handler_context_holder_t ctx,
	handler_context_t::connection_id_t id,
	asio::ip::tcp::socket connection,
	http_handling_state_unique_ptr_t http_handling_state,
	request_info_t request_info,
	traffic_limiter_unique_ptr_t traffic_limiter );

[[nodiscard]]
connection_handler_shptr_t
make_target_connector_handler(
	handler_context_holder_t ctx,
	handler_context_t::connection_id_t id,
	asio::ip::tcp::socket connection,
	http_handling_state_unique_ptr_t http_handling_state,
	request_info_t request_info,
	asio::ip::tcp::endpoint target_endpoint,
	traffic_limiter_unique_ptr_t traffic_limiter );

//
// Note: factories make_connect_method_handler and
// make_ordinary_method_handler have the same prototypes.
// It was made intentionaly. That allows to use them via
// a common type of pointer to function.
//
[[nodiscard]]
connection_handler_shptr_t
make_connect_method_handler(
	handler_context_holder_t ctx,
	handler_context_t::connection_id_t id,
	asio::ip::tcp::socket connection,
	http_handling_state_unique_ptr_t http_state,
	request_info_t request_info,
	traffic_limiter_unique_ptr_t traffic_limiter,
	asio::ip::tcp::socket out_connection );

[[nodiscard]]
connection_handler_shptr_t
make_ordinary_method_handler(
	handler_context_holder_t ctx,
	handler_context_t::connection_id_t id,
	asio::ip::tcp::socket in_connection,
	http_handling_state_unique_ptr_t http_state,
	request_info_t request_info,
	traffic_limiter_unique_ptr_t traffic_limiter,
	asio::ip::tcp::socket out_connection );

} /* namespace arataga::acl_handler */

} /* namespace handlers::http */

