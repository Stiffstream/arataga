/*!
 * @file
 * @brief Реализация negative_response_sender-а.
 */

#include <arataga/acl_handler/handlers/http/basics.hpp>

namespace arataga::acl_handler
{

namespace handlers::http
{

//
// negative_response_sender_handler_t
//
/*!
 * @brief Реализация connection_handler-а которая только отсылает
 * отрицательный ответ и закрывает соединение.
 */
class negative_response_send_handler_t : public connection_handler_t
{
	//! Время, когда этот обработчик был создан.
	const std::chrono::steady_clock::time_point m_created_at;

	//! Причина, по которой соединение закрывается.
	const remove_reason_t m_remove_reason;

	//! Буфер, который будет использоваться для отсылки
	//! отрицательного ответа.
	/*!
	 * Используется тот факт, что все отрицательные ответы на данный
	 * момент представлены строками в статической памяти.
	 */
	out_string_view_buffer_t m_negative_response_buffer;

public:
	negative_response_send_handler_t(
		handler_context_holder_t ctx,
		handler_context_t::connection_id_t id,
		asio::ip::tcp::socket connection,
		remove_reason_t remove_reason,
		std::string_view negative_response )
		:	connection_handler_t{ std::move(ctx), id, std::move(connection) }
		,	m_created_at{ std::chrono::steady_clock::now() }
		,	m_remove_reason{ remove_reason }
		,	m_negative_response_buffer{ negative_response }
	{
	}

protected:
	void
	on_start_impl( delete_protector_t delete_protector ) override
	{
		wrap_action_and_handle_exceptions(
				delete_protector,
				[&]( delete_protector_t, can_throw_t can_throw )
				{
					write_whole(
							can_throw,
							m_connection,
							m_negative_response_buffer,
							[this](
								delete_protector_t delete_protector,
								can_throw_t /*can_throw*/ )
							{
								remove_handler( delete_protector, m_remove_reason );
							} );
				} );
	}

	void
	on_timer_impl( delete_protector_t delete_protector ) override
	{
		if( std::chrono::steady_clock::now() >= m_created_at +
				context().config().http_negative_response_timeout() )
		{
			wrap_action_and_handle_exceptions(
				delete_protector,
				[this]( delete_protector_t delete_protector, can_throw_t can_throw )
				{
					::arataga::logging::wrap_logging(
							proxy_logging_mode,
							spdlog::level::warn,
							[this, can_throw]( auto level )
							{
								log_message_for_connection(
										can_throw,
										level,
										"http_negative_response timed out" );
							} );

					remove_handler(
							delete_protector,
							remove_reason_t::current_operation_timed_out );
				} );
		}
	}

public:
	std::string_view
	name() const noexcept override
	{
		return "http-negative-response-send-handler";
	}
};

//
// make_negative_response_sender
//
[[nodiscard]]
connection_handler_shptr_t
make_negative_response_sender(
	handler_context_holder_t ctx,
	handler_context_t::connection_id_t id,
	asio::ip::tcp::socket connection,
	remove_reason_t remove_reason,
	std::string_view negative_response )
{
	return std::make_shared< negative_response_send_handler_t >(
			std::move(ctx),
			id,
			std::move(connection),
			remove_reason,
			negative_response );
}

} /* namespace arataga::acl_handler */

} /* namespace handlers::http */

