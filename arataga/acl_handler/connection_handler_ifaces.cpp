/*!
 * @file
 * @brief Interfaces for connection_handlers.
 */

#include <arataga/acl_handler/connection_handler_ifaces.hpp>

#include <noexcept_ctcheck/pub.hpp>

namespace arataga::acl_handler
{

//
// config_t
//
config_t::~config_t() {}

//
// handler_context_t
//
handler_context_t::~handler_context_t() {}

//
// traffic_limiter_t
//
void
traffic_limiter_t::reserved_capacity_t::release(
	traffic_limiter_t & limiter,
	direction_t dir,
	const asio::error_code & ec,
	std::size_t bytes_transferred ) const noexcept
{
	if( ec )
		// Assume that 0 bytes have been read in the case on error.
		bytes_transferred = 0u;

	NOEXCEPT_CTCHECK_ENSURE_NOEXCEPT_STATEMENT(
		limiter.release_reserved_capacity( dir, *this, bytes_transferred )
	);
}

traffic_limiter_t::traffic_limiter_t() = default;
traffic_limiter_t::~traffic_limiter_t() {}

//
// connection_handler_t
//
connection_handler_t::connection_handler_t(
	handler_context_holder_t ctx,
	handler_context_t::connection_id_t id,
	asio::ip::tcp::socket connection )
	:	m_ctx{ std::move(ctx) }
	,	m_id{ id }
	,	m_connection{ std::move(connection) }
	,	m_status{ status_t::active }
{
//Kept here for a case of debugging.
//std::cout << this << ": constructed" << std::endl;
}

connection_handler_t::~connection_handler_t()
{
//Kept here for a case of debugging.
//std::cout << this << ": destroyed" << std::endl;
}

void
connection_handler_t::on_start()
{
	// ATTENTION: it's very important for protection from deletion
	// during replace_connection_handler or remove_connection_handler.
	auto self = shared_from_this();
	wrap_action_and_handle_exceptions( [this]() { on_start_impl(); } );
}

void
connection_handler_t::on_timer()
{
	// ATTENTION: it's very important for protection from deletion
	// during replace_connection_handler or remove_connection_handler.
	auto self = shared_from_this();
	wrap_action_and_handle_exceptions( [this]() { on_timer_impl(); } );
}

void
connection_handler_t::release() noexcept
{
	m_status = status_t::released;

	if( m_connection.is_open() )
	{
		// Suppress exceptions because it's noexcept method and we have
		// no possibility to handle an exception.
		asio::error_code ec;
		m_connection.shutdown( asio::ip::tcp::socket::shutdown_both, ec );
		m_connection.close( ec );
	}
}

} /* namespace arataga::acl_handler */

