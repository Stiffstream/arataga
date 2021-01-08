/*!
 * @file
 * @brief Реализация target_connector-а.
 */

#include <arataga/acl_handler/handlers/http/basics.hpp>
#include <arataga/acl_handler/handlers/http/factories.hpp>
#include <arataga/acl_handler/handlers/http/helpers.hpp>
#include <arataga/acl_handler/handlers/http/responses.hpp>

namespace arataga::acl_handler
{

namespace handlers::http
{

//
// target_connector_handler_t
//
/*!
 * @brief Обработчик соединения, который производит подключение
 * к удаленному узлу.
 */
class target_connector_handler_t final : public handler_with_out_connection_t
{
	//! Состояние разбора исходного запроса.
	http_handling_state_unique_ptr_t m_request_state;

	//! Дополнительная информация о запросе.
	request_info_t m_request_info;

	//! Адрес, на который нужно подключаться.
	asio::ip::tcp::endpoint m_target_endpoint;

	//! Ограничитель трафика для этого клиента.
	traffic_limiter_unique_ptr_t m_traffic_limiter;

	//! Время, когда DNS lookup начался.
	std::chrono::steady_clock::time_point m_created_at;

public:
	target_connector_handler_t(
		handler_context_holder_t ctx,
		handler_context_t::connection_id_t id,
		asio::ip::tcp::socket connection,
		http_handling_state_unique_ptr_t request_state,
		request_info_t request_info,
		asio::ip::tcp::endpoint target_endpoint,
		traffic_limiter_unique_ptr_t traffic_limiter )
		:	handler_with_out_connection_t{
				std::move(ctx), id, std::move(connection)
			}
		,	m_request_state{ std::move(request_state) }
		,	m_request_info{ std::move(request_info) }
		,	m_target_endpoint{ target_endpoint }
		,	m_traffic_limiter{ std::move(traffic_limiter) }
		,	m_created_at{ std::chrono::steady_clock::now() }
	{}

protected:
	void
	on_start_impl( delete_protector_t delete_protector ) override
	{
		wrap_action_and_handle_exceptions(
			delete_protector,
			[this]( delete_protector_t delete_protector, can_throw_t can_throw )
			{
				initiate_connect( delete_protector, can_throw );
			} );
	}

	void
	on_timer_impl( delete_protector_t delete_protector ) override
	{
		if( std::chrono::steady_clock::now() >= m_created_at +
				context().config().connect_target_timeout() )
		{
			wrap_action_and_handle_exceptions(
				delete_protector,
				[this]( delete_protector_t delete_protector, can_throw_t can_throw )
				{
					// Осталось только отослать ответ и закрыть соединение.
					send_negative_response_then_close_connection(
							delete_protector,
							can_throw,
							remove_reason_t::current_operation_timed_out,
							response_bad_gateway_connect_timeout );
				} );
		}
	}

public:
	std::string_view
	name() const noexcept override
	{
		return "http-target-connect-handler";
	}

private:
	void
	initiate_connect(
		delete_protector_t delete_protector,
		can_throw_t can_throw )
	{
		try
		{
			asio::error_code ec;

			// Вспомогательная локальная функция для того, чтобы не дублировать
			// одно и тоже по несколько раз.
			const auto finish_on_failure =
				[this, &delete_protector, &can_throw](
					std::string_view message ) -> void
				{
					log_problem_then_send_negative_response(
							delete_protector,
							can_throw,
							remove_reason_t::io_error,
							spdlog::level::err,
							message,
							response_internal_server_error );
				};

			m_out_connection.open( m_target_endpoint.protocol(), ec );
			if( ec )
			{
				return finish_on_failure( fmt::format(
						"unable open outgoing socket: {}",
						ec.message() ) );
			}

			// Новый сокет должен начать работать в неблокирующем режиме.
			m_out_connection.non_blocking( true, ec );
			if( ec )
			{
				return finish_on_failure( fmt::format(
						"unable switch outgoing socket to non-blocking mode: {}",
						ec.message() ) );
			}

			// Подключаться нужно с внешнего IP, поэтому привяжем исходящий сокет
			// к этому IP.
			m_out_connection.bind(
					// Указываем 0 в качестве номера порта для того,
					// чтобы порт выделила ОС.
					asio::ip::tcp::endpoint{ context().config().out_addr(), 0u },
					ec );
			if( ec )
			{
				return finish_on_failure( fmt::format(
						"unable to bind outgoing socket to address {}: {}",
						context().config().out_addr(),
						ec.message() ) );
			}

			::arataga::logging::wrap_logging(
					proxy_logging_mode,
					spdlog::level::trace,
					[this, can_throw]( auto level )
					{
						log_message_for_connection(
								can_throw,
								level,
								fmt::format( "trying to connect {} from {}",
										m_target_endpoint,
										m_out_connection.local_endpoint() ) );
					} );

			// Осталось только выполнить подключение.
			m_out_connection.async_connect(
					m_target_endpoint,
					with<const asio::error_code &>().make_handler(
						[this](
							delete_protector_t delete_protector,
							can_throw_t can_throw,
							const asio::error_code & ec )
						{
							on_async_connect_result(
									delete_protector, can_throw, ec );
						} )
				);
		}
		catch( const std::exception & x ) 
		{
			log_problem_then_send_negative_response(
					delete_protector,
					can_throw,
					remove_reason_t::unhandled_exception,
					spdlog::level::err,
					fmt::format( "an exception during the creation of "
							"outgoing connection from {} to {}: {}",
							context().config().out_addr(),
							m_target_endpoint,
							x.what() ),
					response_internal_server_error );
		}
	}

	void
	log_problem_then_send_negative_response(
		delete_protector_t delete_protector,
		can_throw_t can_throw,
		remove_reason_t remove_reason,
		spdlog::level::level_enum log_level,
		std::string_view log_message,
		std::string_view negative_response )
	{
		::arataga::logging::wrap_logging(
				proxy_logging_mode,
				log_level,
				[this, can_throw, log_message]( auto level )
				{
					log_message_for_connection(
							can_throw,
							level,
							log_message );
				} );

		send_negative_response_then_close_connection(
				delete_protector,
				can_throw,
				remove_reason,
				negative_response );
	}

	void
	on_async_connect_result(
		delete_protector_t delete_protector,
		can_throw_t can_throw,
		const asio::error_code & ec )
	{
		if( ec )
		{
			// Если это не отмена операции, то проблему нужно залогировать,
			// а клиенту следует отослать отрицательный ответ.
			if( asio::error::operation_aborted != ec )
			{
				log_problem_then_send_negative_response(
						delete_protector,
						can_throw,
						remove_reason_t::io_error,
						spdlog::level::warn,
						fmt::format( "can't connect to target host {}: {}",
								m_target_endpoint,
								ec.message() ),
						response_bad_gateway_connect_failure );
			}
		}
		else
		{
			::arataga::logging::wrap_logging(
					proxy_logging_mode,
					spdlog::level::debug,
					[this, can_throw]( auto level )
					{
						log_message_for_connection(
								can_throw,
								level,
								fmt::format(
										"outgoing connection to {} from {} established",
										m_target_endpoint,
										m_out_connection.local_endpoint() ) );
					} );

			// Создадим обработчик для запроса в соответствии с методом
			// в HTTP-запросе. Особого внимания на данный момент требует
			// метод CONNECT, все остальные обрабатываются обычным образом.
			const auto factory = (HTTP_CONNECT == m_request_info.m_method ?
					&make_connect_method_handler :
					&make_ordinary_method_handler);

			replace_handler(
					delete_protector,
					can_throw,
					[this, &factory]( can_throw_t )
					{
						return (*factory)(
								std::move(m_ctx),
								m_id,
								std::move(m_connection),
								std::move(m_request_state),
								std::move(m_request_info),
								std::move(m_traffic_limiter),
								std::move(m_out_connection) );
					} );
		}
	}
};

//
// make_target_connector_handler
//
[[nodiscard]]
connection_handler_shptr_t
make_target_connector_handler(
	handler_context_holder_t ctx,
	handler_context_t::connection_id_t id,
	asio::ip::tcp::socket connection,
	http_handling_state_unique_ptr_t request_state,
	request_info_t request_info,
	asio::ip::tcp::endpoint target_endpoint,
	traffic_limiter_unique_ptr_t traffic_limiter )
{
	return std::make_shared< target_connector_handler_t >(
			std::move(ctx),
			id,
			std::move(connection),
			std::move(request_state),
			std::move(request_info),
			target_endpoint,
			std::move(traffic_limiter) );
}

} /* namespace arataga::acl_handler */

} /* namespace handlers::http */

