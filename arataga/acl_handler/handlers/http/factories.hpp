/*!
 * @file
 * @brief Перечень фабрик для создания HTTP connection-handler-ов.
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
	std::string_view negative_response );

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
// Примечание: у фабрик make_connect_method_handler и
// make_ordinary_method_handler специально сделан одинаковый
// интерфейс для того, чтобы можно было использовать один
// и тот же тип указателя на функцию.
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

