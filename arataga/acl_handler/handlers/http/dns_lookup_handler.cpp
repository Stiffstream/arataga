/*!
 * @file
 * @brief Реализация dns_lookup_handler-а.
 */

#include <arataga/acl_handler/handlers/http/basics.hpp>
#include <arataga/acl_handler/handlers/http/factories.hpp>
#include <arataga/acl_handler/handlers/http/helpers.hpp>
#include <arataga/acl_handler/handlers/http/responses.hpp>

#include <arataga/utils/overloaded.hpp>

namespace arataga::acl_handler
{

namespace handlers::http
{

//
// dns_lookup_handler_t
//
/*!
 * @brief Обработчик соединения, который производит DNS lookup.
 */
class dns_lookup_handler_t final : public basic_http_handler_t
{
	//! Состояние разбора исходного запроса.
	http_handling_state_unique_ptr_t m_request_state;

	//! Дополнительная информация об исходном запросе.
	request_info_t m_request_info;

	//! Ограничитель трафика для этого клиента.
	traffic_limiter_unique_ptr_t m_traffic_limiter;

	//! Время, когда DNS lookup начался.
	std::chrono::steady_clock::time_point m_created_at;

public:
	dns_lookup_handler_t(
		handler_context_holder_t ctx,
		handler_context_t::connection_id_t id,
		asio::ip::tcp::socket connection,
		http_handling_state_unique_ptr_t request_state,
		request_info_t request_info,
		traffic_limiter_unique_ptr_t traffic_limiter )
		:	basic_http_handler_t{ std::move(ctx), id, std::move(connection) }
		,	m_request_state{ std::move(request_state) }
		,	m_request_info{ std::move(request_info) }
		,	m_traffic_limiter{ std::move(traffic_limiter) }
		,	m_created_at{ std::chrono::steady_clock::now() }
	{}

protected:
	void
	on_start_impl( delete_protector_t delete_protector ) override
	{
		wrap_action_and_handle_exceptions(
				delete_protector,
				[this]( delete_protector_t, can_throw_t )
				{
					context().async_resolve_hostname(
							m_id,
							m_request_info.m_target_host,
							with<const dns_resolving::hostname_result_t &>()
							.make_handler(
								[this](
									delete_protector_t delete_protector,
									can_throw_t can_throw,
									const dns_resolving::hostname_result_t & result )
								{
									on_hostname_result(
											delete_protector,
											can_throw,
											result );
								} )
					);
				} );
	}

	void
	on_timer_impl( delete_protector_t delete_protector ) override
	{
		if( std::chrono::steady_clock::now() >= m_created_at +
				context().config().dns_resolving_timeout() )
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
										"DNS-lookup timed out" );
							} );

					// Осталось только отослать ответ и закрыть соединение.
					send_negative_response_then_close_connection(
							delete_protector,
							can_throw,
							remove_reason_t::current_operation_timed_out,
							response_request_timeout_dns_lookup_timeout );
				} );
		}
	}

public:
	std::string_view
	name() const noexcept override
	{
		return "http-dns-lookup-handler";
	}

private:
	void
	on_hostname_result(
		delete_protector_t delete_protector,
		can_throw_t can_throw,
		const dns_resolving::hostname_result_t & result )
	{
		std::visit( ::arataga::utils::overloaded{
				[&]( const dns_resolving::hostname_found_t & info )
				{
					// Теперь мы точно знаем куда подключаться.
					// Пусть этим занимается следующий обработчик.
					const asio::ip::tcp::endpoint target_endpoint{
							info.m_ip,
							m_request_info.m_target_port
						};

					replace_handler(
							delete_protector,
							can_throw,
							[this, &target_endpoint]( can_throw_t )
							{
								return make_target_connector_handler(
										std::move(m_ctx),
										m_id,
										std::move(m_connection),
										std::move(m_request_state),
										std::move(m_request_info),
										target_endpoint,
										std::move(m_traffic_limiter) );
							} );
				},
				[&]( const dns_resolving::hostname_not_found_t & info )
				{
					// Информация о хосте не найдена.
					// Осталось только залогировать этот факт, отослать
					// отрицательный результат и закрыть подключение.
					::arataga::logging::wrap_logging(
							proxy_logging_mode,
							spdlog::level::warn,
							[this, can_throw, &info]( auto level )
							{
								log_message_for_connection(
										can_throw,
										level,
										fmt::format( "DNS resolving failure: {}",
												info.m_error_desc ) );
							} );

					send_negative_response_then_close_connection(
							delete_protector,
							can_throw,
							remove_reason_t::unresolved_target,
							response_bad_gateway_dns_lookup_failure );
				}
			},
			result );
	}
};

//
// make_dns_lookup_handler
//
[[nodiscard]]
connection_handler_shptr_t
make_dns_lookup_handler(
	handler_context_holder_t ctx,
	handler_context_t::connection_id_t id,
	asio::ip::tcp::socket connection,
	http_handling_state_unique_ptr_t request_state,
	request_info_t request_info,
	traffic_limiter_unique_ptr_t traffic_limiter )
{
	return std::make_shared< dns_lookup_handler_t >(
			std::move(ctx),
			id,
			std::move(connection),
			std::move(request_state),
			std::move(request_info),
			std::move(traffic_limiter) );
}

} /* namespace arataga::acl_handler */

} /* namespace handlers::http */

