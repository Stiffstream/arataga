/*!
 * @file
 * @brief Интерфейсы, необходимые для обработчиков подключений.
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
		// Считаем, что в случае ошибки ничего не прочитано.
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
//Оставлено здесь на случай, если эта отладочная печать потребуется.
//std::cout << this << ": constructed" << std::endl;
}

connection_handler_t::~connection_handler_t()
{
//Оставлено здесь на случай, если эта отладочная печать потребуется.
//std::cout << this << ": destroyed" << std::endl;
}

void
connection_handler_t::on_start()
{
	auto self = shared_from_this();
	on_start_impl( details::delete_protector_maker_t{ self }.make() );
}

void
connection_handler_t::on_timer()
{
	auto self = shared_from_this();
	on_timer_impl( details::delete_protector_maker_t{ self }.make() );
}

void
connection_handler_t::release() noexcept
{
	m_status = status_t::released;

	if( m_connection.is_open() )
	{
		// Подавляем все исключения поскольку это noexcept метод и
		// у нас нет возможности как-то исключения обработать.
		asio::error_code ec;
		m_connection.shutdown( asio::ip::tcp::socket::shutdown_both, ec );
		m_connection.close( ec );
	}
}

} /* namespace arataga::acl_handler */

