/*!
 * @file
 * @brief Реализация connect_method_handler-а.
 */

#include <arataga/acl_handler/handlers/http/basics.hpp>
#include <arataga/acl_handler/handlers/http/factories.hpp>
#include <arataga/acl_handler/handlers/http/helpers.hpp>
#include <arataga/acl_handler/handlers/http/responses.hpp>

#include <arataga/acl_handler/handler_factories.hpp>

namespace arataga::acl_handler
{

namespace handlers::http
{

//
// connect_method_handler_t
//
/*!
 * @brief Обработчик соединения, который обрабатывает метод CONNECT.
 */
class connect_method_handler_t final : public handler_with_out_connection_t
{
	//! Описание целевого узла.
	/*!
	 * Необходимо для выполнения логирования.
	 */
	const std::string m_connection_target;

	//! Ограничитель трафика для этого клиента.
	traffic_limiter_unique_ptr_t m_traffic_limiter;

	//! Буфер для отсылки клиенту положительного ответа.
	/*!
	 * После отсылки ответа будет произведен перевод подключения в режим
	 * простой передачи данных.
	 */
	out_string_view_buffer_t m_positive_response;

	//! Время когда данный объект был создан.
	/*!
	 * Используется для органичения длительности операции записи
	 * положительного ответа клиенту.
	 */
	std::chrono::steady_clock::time_point m_created_at;

public:
	connect_method_handler_t(
		handler_context_holder_t ctx,
		handler_context_t::connection_id_t id,
		asio::ip::tcp::socket in_connection,
		request_info_t request_info,
		traffic_limiter_unique_ptr_t traffic_limiter,
		asio::ip::tcp::socket out_connection )
		:	handler_with_out_connection_t{
				std::move(ctx),
				id,
				std::move(in_connection),
				std::move(out_connection)
			}
		,	m_connection_target{
				fmt::format( "{}:{}",
					request_info.m_target_host,
					request_info.m_target_port )
			}
		,	m_traffic_limiter{ std::move(traffic_limiter) }
		,	m_positive_response{ response_ok_for_connect_method }
		,	m_created_at{ std::chrono::steady_clock::now() }
	{
	}

protected:
	void
	on_start_impl( delete_protector_t delete_protector ) override
	{
		wrap_action_and_handle_exceptions(
			delete_protector,
			[this]( delete_protector_t, can_throw_t can_throw ) {
				// Для того, чтобы проще затем было анализировать логи.
				::arataga::logging::wrap_logging(
						proxy_logging_mode,
						spdlog::level::info,
						[this, can_throw]( auto level )
						{
							log_message_for_connection(
									can_throw,
									level,
									"serving-request=CONNECT " + m_connection_target );
						} );

				// Нужно отослать положительный ответ клиенту.
				write_whole( can_throw,
						m_connection,
						m_positive_response,
						[this]( delete_protector_t delete_protector,
							can_throw_t can_throw )
						{
							// Клиент получил наш ответ, так что мы теперь
							// можем просто перейти к data-transfer-handler.
							replace_handler(
									delete_protector,
									can_throw,
									[this]( can_throw_t )
									{
										return make_data_transfer_handler(
												std::move(m_ctx),
												m_id,
												std::move(m_connection),
												std::move(m_out_connection),
												std::move(m_traffic_limiter) );
									} );
						} );
			} );
	}

	void
	on_timer_impl( delete_protector_t delete_protector ) override
	{
		wrap_action_and_handle_exceptions(
			delete_protector,
			[this]( delete_protector_t delete_protector, can_throw_t can_throw )
			{
				// В качестве лимита времени будем использовать
				// idle_connection_timeout.
				const auto now = std::chrono::steady_clock::now();
				if( m_created_at +
						context().config().idle_connection_timeout() < now )
				{
					return log_and_remove_connection(
							delete_protector,
							can_throw,
							remove_reason_t::no_activity_for_too_long,
							spdlog::level::warn,
							"timeout writing positive response to CONNECT method" );
				}
			} );
	}

public:
	std::string_view
	name() const noexcept override
	{
		return "http-connect-method-handler";
	}
};

//
// make_connect_method_handler
//
[[nodiscard]]
connection_handler_shptr_t
make_connect_method_handler(
	handler_context_holder_t ctx,
	handler_context_t::connection_id_t id,
	asio::ip::tcp::socket in_connection,
	// Эта информация передается в функцию-фабрику, но для
	// connect_method_handler-а она не нужна.
	// Поэтому она здесь будет просто выброшена.
	http_handling_state_unique_ptr_t /*http_state*/,
	request_info_t request_info,
	traffic_limiter_unique_ptr_t traffic_limiter,
	asio::ip::tcp::socket out_connection )
{
	return std::make_shared< connect_method_handler_t >(
			std::move(ctx),
			id,
			std::move(in_connection),
			std::move(request_info),
			std::move(traffic_limiter),
			std::move(out_connection) );
}

} /* namespace arataga::acl_handler */

} /* namespace handlers::http */

