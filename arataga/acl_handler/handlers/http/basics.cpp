/*!
 * @file
 * @brief Basic stuff for implementation of HTTP connection-handlers.
 */

#include <arataga/acl_handler/handlers/http/basics.hpp>
#include <arataga/acl_handler/handlers/http/factories.hpp>

namespace arataga::acl_handler
{

namespace handlers::http
{

//
// basic_http_handler_t
//
void
basic_http_handler_t::send_negative_response_then_close_connection(
	can_throw_t can_throw,
	remove_reason_t reason,
	arataga::utils::string_literal_t whole_response )
{
	replace_handler(
			can_throw,
			[&]( can_throw_t )
			{
				return make_negative_response_sender(
					std::move(m_ctx),
					m_id,
					std::move(m_connection),
					reason,
					whole_response );
			} );
}

//
// handler_with_out_connection_t
//
handler_with_out_connection_t::handler_with_out_connection_t(
	handler_context_holder_t ctx,
	handler_context_t::connection_id_t id,
	asio::ip::tcp::socket in_connection )
	:	basic_http_handler_t{
			std::move(ctx), id, std::move(in_connection)
		}
	,	m_out_connection{ m_connection.get_executor() }
{}

handler_with_out_connection_t::handler_with_out_connection_t(
	handler_context_holder_t ctx,
	handler_context_t::connection_id_t id,
	asio::ip::tcp::socket in_connection,
	asio::ip::tcp::socket out_connection )
	:	basic_http_handler_t{
			std::move(ctx), id, std::move(in_connection)
		}
	,	m_out_connection{ std::move(out_connection) }
{}

void
handler_with_out_connection_t::release() noexcept
{
	// Ignore errors.
	asio::error_code ec;
	m_out_connection.shutdown( asio::ip::tcp::socket::shutdown_both, ec );
	m_out_connection.close( ec );

	// Let's the base class completes the release.
	basic_http_handler_t::release();
}

} /* namespace arataga::acl_handler */

} /* namespace handlers::http */

