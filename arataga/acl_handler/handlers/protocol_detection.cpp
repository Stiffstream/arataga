/*!
 * @file
 * @brief connection_handler, который определяет тип протокола клиента.
 */

#include <arataga/acl_handler/connection_handler_ifaces.hpp>
#include <arataga/acl_handler/buffers.hpp>
#include <arataga/acl_handler/handler_factories.hpp>

#include <arataga/utils/overloaded.hpp>

namespace arataga::acl_handler
{

namespace handlers::protocol_detection
{

class handler_t : public connection_handler_t
{
	//! Время, когда соединение было принято.
	std::chrono::steady_clock::time_point m_created_at;

	//! Буфер в который будет происходить чтение первой порции данных.
	in_buffer_fixed_t< 512 > m_in_buffer;

public :
	handler_t(
		handler_context_holder_t ctx,
		handler_context_t::connection_id_t id,
		asio::ip::tcp::socket connection )
		:	connection_handler_t{ std::move(ctx), id, std::move(connection) }
		,	m_created_at{ std::chrono::steady_clock::now() }
	{}

protected:
	void
	on_start_impl( delete_protector_t delete_protector ) override
	{
		wrap_action_and_handle_exceptions(
			delete_protector,
			[this]( delete_protector_t, can_throw_t can_throw ) {
				// Отмечаем в статистике появление еще одного подключения.
				context().stats_inc_connection_count( connection_type_t::generic );

				// Нужно прочитать и проанализировать первую порцию данных.
				read_some(
						can_throw,
						m_connection,
						m_in_buffer,
						[this]( delete_protector_t delete_protector,
							can_throw_t can_throw )
						{
							analyze_data_read( delete_protector, can_throw );
						} );
			} );
	}

	void
	on_timer_impl( delete_protector_t delete_protector ) override
	{
		if( std::chrono::steady_clock::now() >= m_created_at +
				context().config().protocol_detection_timeout() )
		{
			wrap_action_and_handle_exceptions(
				delete_protector,
				[this](
					delete_protector_t delete_protector,
					can_throw_t can_throw )
				{
					log_and_remove_connection(
							delete_protector,
							can_throw,
							remove_reason_t::current_operation_timed_out,
							spdlog::level::warn,
							"protocol-detection timed out" );
				} );
		}
	}

public:
	std::string_view
	name() const noexcept override
	{
		return "protocol-detector";
	}

private:
	struct unknown_protocol_t {};

	struct connection_accepted_t
	{
		connection_type_t m_connection_type;
		connection_handler_shptr_t m_handler;
	};

	// Тип, который должен использоваться методами try_accept_*_connection
	// в качестве возвращаемого значения.
	using detection_result_t = std::variant<
			unknown_protocol_t,
			connection_accepted_t
		>;

	void
	analyze_data_read(
		delete_protector_t delete_protector,
		can_throw_t can_throw )
	{
		detection_result_t detection_result{ unknown_protocol_t{} };

		// Запускаем только те try_accept_*_connection(), которые разрешены
		// для этого типа ACL.
		const auto acl_protocol = context().config().acl_protocol();
		if( acl_protocol_t::autodetect == acl_protocol )
		{
			detection_result = try_accept_socks_connection( can_throw );
			if( std::holds_alternative< unknown_protocol_t >( detection_result ) )
			{
				detection_result = try_accept_http_connection( can_throw );
			}
		}
		else if( acl_protocol_t::socks == acl_protocol )
		{
			detection_result = try_accept_socks_connection( can_throw );
		}
		else if( acl_protocol_t::http == acl_protocol )
		{
			detection_result = try_accept_http_connection( can_throw );
		}

		// Осталось понять, приняли ли мы что-нибудь.
		std::visit( ::arataga::utils::overloaded{
				[this, delete_protector, can_throw]
				( connection_accepted_t & accepted )
				{
					// Обновляем статистику. Делать это нужно сейчас,
					// поскольку в случае HTTP может использоваться
					// keep-alive соединение, которое должно быть подсчитано
					// всего лишь один раз (а если делать это в
					// http::initial_http_handler, то статистика будет обновляться
					// каждый раз при создании initial_http_handler (т.е. при
					// обработке нового входящего запроса).
					context().stats_inc_connection_count(
							accepted.m_connection_type );

					// Теперь можно заменять обработчик.
					replace_handler(
							delete_protector,
							can_throw,
							[&]( can_throw_t ) {
								return std::move(accepted.m_handler);
							} );
				},
				[this, delete_protector, can_throw]
				( const unknown_protocol_t & )
				{
					// Соединение нужно закрыть, т.к. мы не знаем,
					// что это за протокол.
					log_and_remove_connection(
							delete_protector,
							can_throw,
							remove_reason_t::unsupported_protocol,
							spdlog::level::warn,
							"unsupported protocol in the connection" );
				} },
				detection_result );
	}

	detection_result_t
	try_accept_socks_connection( can_throw_t /*can_throw*/ )
	{
		constexpr std::byte socks5_protocol_first_byte{ 5u };

		buffer_read_trx_t read_trx{ m_in_buffer };

		if( socks5_protocol_first_byte == m_in_buffer.read_byte() )
		{
			// Нужно создавать обработчик для SOCKS5.
			return {
					connection_accepted_t{
							connection_type_t::socks5,
							make_socks5_auth_method_detection_handler(
									m_ctx,
									m_id,
									std::move(m_connection),
									m_in_buffer.whole_data_as_sequence(),
									m_created_at )
					}
			};
		}

		return { unknown_protocol_t{} };
	}

	detection_result_t
	try_accept_http_connection( can_throw_t can_throw )
	{
		(void)can_throw;

		buffer_read_trx_t read_trx{ m_in_buffer };

		// Считаем, что к нам подключаются по HTTP, если первый символ
		// это заглавная латинская буква (потому что методы в HTTP
		// записываются заглавными буквами).
		//
		// Даже если это не так, то затем выскочит ошибка парсинга
		// HTTP-заголовка и соединение все равно будет закрыто.
		//
		const auto first_byte = m_in_buffer.read_byte();
		if( std::byte{'A'} <= first_byte && first_byte <= std::byte{'Z'} )
		{
			// Нужно создавать обработчик для HTTP.
			return {
					connection_accepted_t{
							connection_type_t::http,
							make_http_handler(
									m_ctx,
									m_id,
									std::move(m_connection),
									m_in_buffer.whole_data_as_sequence(),
									m_created_at )
					}
			};
		}

		return { unknown_protocol_t{} };
	}
};

} /* namespace handlers::protocol_detection */

[[nodiscard]]
connection_handler_shptr_t
make_protocol_detection_handler(
	handler_context_holder_t ctx,
	handler_context_t::connection_id_t id,
	asio::ip::tcp::socket connection )
{
	using namespace handlers::protocol_detection;

	return std::make_shared< handler_t >(
			std::move(ctx), id, std::move(connection) );
}

} /* namespace arataga::acl_handler */

