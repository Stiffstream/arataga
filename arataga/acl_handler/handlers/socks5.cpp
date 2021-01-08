/*!
 * @file
 * @brief connection_handler-ы для работы с SOCKS5.
 */

#include <arataga/acl_handler/connection_handler_ifaces.hpp>
#include <arataga/acl_handler/handler_factories.hpp>
#include <arataga/acl_handler/buffers.hpp>

#include <arataga/utils/overloaded.hpp>

#include <variant>

namespace arataga::acl_handler
{

namespace handlers::socks5
{

//
// Фабрики, которые будут реализованы ниже по тексту.
// Но которые могут начать использоваться в коде еще до того, как они
// будут определены.
//
[[nodiscard]]
connection_handler_shptr_t
make_username_password_auth_stage_handler(
	handler_context_holder_t ctx,
	handler_context_t::connection_id_t id,
	asio::ip::tcp::socket connection,
	std::chrono::steady_clock::time_point created_at );

[[nodiscard]]
connection_handler_shptr_t
make_no_authentification_stage_handler(
	handler_context_holder_t ctx,
	handler_context_t::connection_id_t id,
	asio::ip::tcp::socket connection,
	std::chrono::steady_clock::time_point created_at );

[[nodiscard]]
connection_handler_shptr_t
make_command_stage_handler(
	handler_context_holder_t ctx,
	handler_context_t::connection_id_t id,
	asio::ip::tcp::socket connection,
	std::optional<std::string> username,
	std::optional<std::string> password,
	std::chrono::steady_clock::time_point created_at );

[[nodiscard]]
connection_handler_shptr_t
make_command_stage_handler(
	handler_context_holder_t ctx,
	handler_context_t::connection_id_t id,
	asio::ip::tcp::socket connection,
	byte_sequence_t first_bytes,
	std::chrono::steady_clock::time_point created_at );

[[nodiscard]]
connection_handler_shptr_t
make_connect_command_handler(
	handler_context_holder_t ctx,
	handler_context_t::connection_id_t id,
	asio::ip::tcp::socket connection,
	std::optional<std::string> username,
	std::optional<std::string> password,
	std::byte atype_value,
	byte_sequence_t dst_addr,
	std::uint16_t dst_port );

[[nodiscard]]
connection_handler_shptr_t
make_bind_command_handler(
	handler_context_holder_t ctx,
	handler_context_t::connection_id_t id,
	asio::ip::tcp::socket connection,
	std::optional<std::string> username,
	std::optional<std::string> password,
	std::byte atype_value,
	byte_sequence_t dst_addr,
	std::uint16_t dst_port );

constexpr std::byte version_byte{ 0x5u };
constexpr std::byte no_authentification_method{ 0x0u };
constexpr std::byte username_password_auth_method{ 0x2u };
constexpr std::byte no_acceptable_methods{ 0xffu };

constexpr std::byte atype_ipv4{ 0x1u };
constexpr std::byte atype_domainname{ 0x3u };
constexpr std::byte atype_ipv6{ 0x4u };

constexpr std::byte command_reply_successed{ 0x0u };
constexpr std::byte command_reply_general_server_failure{ 0x1u };
constexpr std::byte command_reply_connection_not_allowed{ 0x2u };
constexpr std::byte command_reply_host_unreachable{ 0x4u };
constexpr std::byte command_reply_command_not_supported{ 0x7u };
constexpr std::byte command_reply_atype_not_supported{ 0x8u };

//
// make_negative_command_reply
//
//! Вспомогательная функция для формирования отрицательного ответа
//! на command PDU.
template< typename Buffer >
void
make_negative_command_reply(
	Buffer & buffer,
	std::byte reply_code )
{
	buffer.write_byte( version_byte );
	buffer.write_byte( reply_code );
	buffer.write_byte( std::byte{0x0} ); // RSV
	buffer.write_byte( std::byte{0x0} ); // ATYPE.
}

class auth_method_detection_handler_t final : public connection_handler_t
{
	//! Максимальный размер первого PDU от клиента.
	static constexpr std::size_t first_pdu_max_size =
			1 /* VER */
			+ 1 /* method count */
			+ 255 /* methods */
			;

	//! Первый PDU от клиента.
	/*!
	 * Здесь должен быть перечень способов аутентификации.
	 */
	in_buffer_fixed_t< first_pdu_max_size > m_first_pdu;

	//! Исходящий буфер для ответа на первый PDU.
	/*
	 * В ответе всего два байта.
	 */
	out_buffer_fixed_t< 2u > m_response;

	//! Время, когда соединение было принято.
	std::chrono::steady_clock::time_point m_created_at;

	//! Итоговый метод аутентификации, который мы приняли.
	/*!
	 * Будет пустым, если подходящего метода не нашли.
	 */
	std::optional< std::byte > m_accepted_method{ std::nullopt };

	[[nodiscard]]
	static byte_sequence_t
	ensure_valid_size( byte_sequence_t whole_first_pdu )
	{
		if( whole_first_pdu.size() > first_pdu_max_size )
			throw acl_handler_ex_t{
					fmt::format( "invalid first PDU size for socks5: {} bytes, "
							"up to {} bytes expected",
							whole_first_pdu.size(),
							first_pdu_max_size )
				};

		return whole_first_pdu;
	}

public:
	auth_method_detection_handler_t(
		handler_context_holder_t ctx,
		handler_context_t::connection_id_t id,
		asio::ip::tcp::socket connection,
		byte_sequence_t whole_first_pdu,
		std::chrono::steady_clock::time_point created_at )
		:	connection_handler_t{ std::move(ctx), id, std::move(connection) }
		,	m_first_pdu{ ensure_valid_size( whole_first_pdu ) }
		,	m_created_at{ created_at }
	{}

protected:
	void
	on_start_impl( delete_protector_t delete_protector ) override
	{
		wrap_action_and_handle_exceptions(
			delete_protector,
			[this]( delete_protector_t delete_protector, can_throw_t can_throw )
			{
				// Пытаемся разобраться со способом аутентификации.
				handle_data_already_read_or_read_more(
						delete_protector, can_throw );
			} );
	}

	void
	on_timer_impl( delete_protector_t delete_protector ) override
	{
		if( std::chrono::steady_clock::now() >= m_created_at +
				context().config().socks_handshake_phase_timeout() )
		{
			wrap_action_and_handle_exceptions(
				delete_protector,
				[this]( delete_protector_t delete_protector, can_throw_t can_throw )
				{
					log_and_remove_connection(
							delete_protector,
							can_throw,
							remove_reason_t::current_operation_timed_out,
							spdlog::level::warn,
							"socks5: handshake phase timed out" );
				} );
		}
	}

public:
	std::string_view
	name() const noexcept override
	{
		return "socks5-auth-method-detector";
	}

private:
	void
	handle_data_already_read_or_read_more(
		delete_protector_t delete_protector,
		can_throw_t can_throw )
	{
		if( const auto read_result = try_handle_data_read(
				delete_protector, can_throw );
				data_parsing_result_t::need_more == read_result )
		{
			// Нужно читать следующий кусок данных.
			read_some(
					can_throw,
					m_connection,
					m_first_pdu,
					[this](
						delete_protector_t delete_protector,
						can_throw_t can_throw )
					{
						handle_data_already_read_or_read_more(
								delete_protector, can_throw );
					} );
		}
	}

	[[nodiscard]]
	data_parsing_result_t
	try_handle_data_read(
		delete_protector_t delete_protector,
		can_throw_t can_throw )
	{
		buffer_read_trx_t read_trx{ m_first_pdu };

		(void)m_first_pdu.read_byte(); // Пропускаем байт с версией.

		if( m_first_pdu.remaining() > 0u )
		{
			std::size_t methods = std::to_integer< std::size_t >(
					m_first_pdu.read_byte() );
			if( methods == m_first_pdu.remaining() )
			{
				read_trx.commit();

				handle_auth_methods( can_throw );

				return data_parsing_result_t::success;
			}
			else if( methods < m_first_pdu.remaining() )
			{
				log_and_remove_connection(
						delete_protector,
						can_throw,
						remove_reason_t::protocol_error,
						spdlog::level::err,
						fmt::format(
								"socks5: PDU with auth methods too long, methods: {}, "
								"bytes read: {}",
								methods,
								m_first_pdu.total_size() )
					);

				return data_parsing_result_t::invalid_data;
			}
		}

		return data_parsing_result_t::need_more;
	}

	// Этот метод использует предположение о том, что в m_first_pdu
	// находится полный список поддерживаемых пользователем методов
	// аутентификации.
	void
	handle_auth_methods( can_throw_t can_throw )
	{
		// Для упрощения диагностики по ходу анализа собираем идентификаторы
		// тех методов, которые поддерживаются клиентом.
		std::string found_method_ids = collect_method_ids( can_throw );

		::arataga::logging::wrap_logging(
				proxy_logging_mode,
				spdlog::level::trace,
				[this, can_throw, &found_method_ids]( auto level )
				{
					log_message_for_connection( can_throw, level,
							fmt::format( "socks5: auth methods from client: {}",
									found_method_ids ) );
				} );

		// Ищем метод username/password.
		try_find_specific_auth_method( username_password_auth_method );
		if( !m_accepted_method )
			try_find_specific_auth_method( no_authentification_method );

		if( m_accepted_method )
		{
			::arataga::logging::wrap_logging(
					proxy_logging_mode,
					spdlog::level::trace,
					[this, can_throw]( auto level )
					{
						log_message_for_connection(
								can_throw,
								level,
								fmt::format( "socks5: auth method to be used: {:#x}",
										*m_accepted_method ) );
					} );

			m_response.write_byte( version_byte );
			m_response.write_byte( *m_accepted_method );

			write_whole(
					can_throw,
					m_connection,
					m_response,
					[this]
					( delete_protector_t delete_protector, can_throw_t can_throw )
					{
						replace_handler(
								delete_protector,
								can_throw,
								[this]( can_throw_t can_throw ) {
									return make_appropriate_handler( can_throw );
								} );
					} );
		}
		else
		{
			m_response.write_byte( version_byte );
			m_response.write_byte( no_acceptable_methods );

			write_whole(
					can_throw,
					m_connection,
					m_response,
					[this, method_ids = std::move(found_method_ids)]
					( delete_protector_t delete_protector, can_throw_t can_throw )
					{
						log_and_remove_connection(
								delete_protector,
								can_throw,
								remove_reason_t::protocol_error,
								spdlog::level::err,
								fmt::format( "socks5: no supported auth methods "
										"(client methods: {})",
										method_ids ) );
					} );
		}
	}

	[[nodiscard]]
	std::string
	collect_method_ids( can_throw_t )
	{
		std::string result;

		// Будем читать все оставшееся содержимое m_first_pdu,
		// а затем вернем текущую позицию в буфере обратно.
		buffer_read_trx_t read_trx{ m_first_pdu };

		while( m_first_pdu.remaining() )
		{
			const auto method = m_first_pdu.read_byte();

			if( !result.empty() )
				result += ", ";
			result += fmt::format( "{:#x}", method );
		}

		return result;
	}

	void
	try_find_specific_auth_method( const std::byte expected_method ) noexcept
	{
		// Будем читать все оставшееся содержимое m_first_pdu,
		// а затем вернем текущую позицию в буфере обратно.
		buffer_read_trx_t read_trx{ m_first_pdu };

		while( m_first_pdu.remaining() )
		{
			const auto method = m_first_pdu.read_byte();
			if( expected_method == method )
			{
				m_accepted_method = method;
				break;
			}
		}
	}

	connection_handler_shptr_t
	make_appropriate_handler( can_throw_t )
	{
		if( no_authentification_method == m_accepted_method.value() )
			return make_no_authentification_stage_handler(
				m_ctx,
				m_id,
				std::move(m_connection),
				m_created_at );
		else
			return make_username_password_auth_stage_handler(
				m_ctx,
				m_id,
				std::move(m_connection),
				m_created_at );
	}
};

//
// username_password_auth_handler_t
//
class username_password_auth_handler_t final : public connection_handler_t
{
	static constexpr std::byte expected_version{ 0x1u };
	static constexpr std::byte access_denied{ 0x1u };
	static constexpr std::byte access_granted{ 0x0u };

	//! Буфер для чтения PDU с аутентификационными данными.
	/*!
	 * https://tools.ietf.org/html/rfc1929
	 */
	in_buffer_fixed_t<
			1 // VER
			+ 1 // ULEN
			+ 255 // UNAME
			+ 1 // PLEN
			+ 255 // PASSWD
		> m_auth_pdu;

	//! Буфер для ответного PDU.
	out_buffer_fixed_t< 2 > m_response;

	//! Время, когда соединение было принято.
	std::chrono::steady_clock::time_point m_created_at;

public:
	username_password_auth_handler_t(
		handler_context_holder_t ctx,
		handler_context_t::connection_id_t id,
		asio::ip::tcp::socket connection,
		std::chrono::steady_clock::time_point created_at )
		:	connection_handler_t{ std::move(ctx), id, std::move(connection) }
		,	m_created_at{ created_at }
	{}

protected:
	void
	on_start_impl( delete_protector_t delete_protector ) override
	{
		wrap_action_and_handle_exceptions(
			delete_protector,
			[this]( delete_protector_t, can_throw_t can_throw )
			{
				read_some(
						can_throw,
						m_connection,
						m_auth_pdu,
						[this]
						( delete_protector_t delete_protector,
						 	can_throw_t can_throw )
						{
							handle_data_already_read_or_read_more(
									delete_protector, can_throw );
						} );
			} );
	}

	void
	on_timer_impl( delete_protector_t delete_protector ) override
	{
		if( std::chrono::steady_clock::now() >= m_created_at +
				context().config().socks_handshake_phase_timeout() )
		{
			wrap_action_and_handle_exceptions(
				delete_protector,
				[this]( delete_protector_t delete_protector, can_throw_t can_throw )
				{
					log_and_remove_connection(
							delete_protector,
							can_throw,
							remove_reason_t::current_operation_timed_out,
							spdlog::level::warn,
							"socks5: handshake phase timed out" );
				} );
		}
	}

public:
	std::string_view
	name() const noexcept override
	{
		return "socks5-username-password-auth-handler";
	}

private:
	void
	handle_data_already_read_or_read_more(
		delete_protector_t delete_protector,
		can_throw_t can_throw )
	{
		if( const auto read_result = try_handle_data_read(
				delete_protector, can_throw );
				data_parsing_result_t::need_more == read_result )
		{
			// Нужно читать следующий кусок данных.
			read_some(
					can_throw,
					m_connection,
					m_auth_pdu,
					[this]
					( delete_protector_t delete_protector, can_throw_t can_throw )
					{
						handle_data_already_read_or_read_more(
								delete_protector, can_throw );
					} );
		}
	}

	[[nodiscard]]
	data_parsing_result_t
	try_handle_data_read(
		delete_protector_t delete_protector,
		can_throw_t can_throw )
	{
		buffer_read_trx_t read_trx{ m_auth_pdu };

		const auto version = m_auth_pdu.read_byte();
		if( expected_version != version )
		{
			log_and_remove_connection(
					delete_protector,
					can_throw,
					remove_reason_t::protocol_error,
					spdlog::level::err,
					fmt::format( "unsupported version of socks5 username/password "
							"auth PDU: {}, expected version: {}",
							version, expected_version )
				);

			return data_parsing_result_t::invalid_data;
		}

		if( !m_auth_pdu.remaining() )
			return data_parsing_result_t::need_more;

		const auto uname_len = std::to_integer< std::size_t >(
				m_auth_pdu.read_byte() );
		if( uname_len > m_auth_pdu.remaining() )
			return data_parsing_result_t::need_more;

		std::string username = m_auth_pdu.read_bytes_as_string( uname_len );

		if( !m_auth_pdu.remaining() )
			return data_parsing_result_t::need_more;

		const auto passwd_len = std::to_integer< std::size_t >(
				m_auth_pdu.read_byte() );
		if( passwd_len > m_auth_pdu.remaining() )
			return data_parsing_result_t::need_more;

		std::string password = m_auth_pdu.read_bytes_as_string( passwd_len );

		if( m_auth_pdu.remaining() )
		{
			log_and_remove_connection(
					delete_protector,
					can_throw,
					remove_reason_t::protocol_error,
					spdlog::level::err,
					fmt::format( "some garbage in auth PDU after reading "
							"username/password, remaining bytes: {}",
							m_auth_pdu.remaining() )
				);

			return data_parsing_result_t::invalid_data;
		}

		// Все прочитано и ничего в буфере не осталось.
		read_trx.commit();

		// Можно переходить к следующему шагу.
		send_positive_response_then_replace_handler(
				can_throw,
				std::move(username),
				std::move(password) );

		return data_parsing_result_t::success;
	}

	void
	send_positive_response_then_replace_handler(
		can_throw_t can_throw,
		std::string username,
		std::string password )
	{
		m_response.write_byte( expected_version );
		m_response.write_byte( access_granted );
		write_whole(
				can_throw,
				m_connection,
				m_response,
				[this, uname = std::move(username), passwd = std::move(password)]
				( delete_protector_t delete_protector, can_throw_t can_throw )
				{ 
					replace_handler(
							delete_protector,
							can_throw,
							[&]( can_throw_t )
							{
								return make_command_stage_handler(
										m_ctx,
										m_id,
										std::move(m_connection),
										std::move(uname),
										std::move(passwd),
										m_created_at );
							} );
				} );
	}
};

//
// no_authentification_handler_t
//
class no_authentification_handler_t final : public connection_handler_t
{
	static constexpr std::byte expected_version{ 0x1u };
	static constexpr std::byte access_granted{ 0x0u };

	//! Буфер для чтения PDU с аутентификационными данными.
	/*!
	 * https://tools.ietf.org/html/rfc1929
	 */
	in_buffer_fixed_t<
			1 // VER
			+ 1 // ULEN, должен быть 0.
			+ 1 // PLEN, должен быть 0.
		> m_auth_pdu;

	//! Буфер для ответного PDU.
	out_buffer_fixed_t< 2 > m_response;

	//! Время, когда соединение было принято.
	std::chrono::steady_clock::time_point m_created_at;

public:
	no_authentification_handler_t(
		handler_context_holder_t ctx,
		handler_context_t::connection_id_t id,
		asio::ip::tcp::socket connection,
		std::chrono::steady_clock::time_point created_at )
		:	connection_handler_t{ std::move(ctx), id, std::move(connection) }
		,	m_created_at{ created_at }
	{}

protected:
	void
	on_start_impl( delete_protector_t delete_protector ) override
	{
		wrap_action_and_handle_exceptions(
			delete_protector,
			[this]( delete_protector_t, can_throw_t can_throw )
			{
				read_some(
						can_throw,
						m_connection,
						m_auth_pdu,
						[this]
						( delete_protector_t delete_protector,
							can_throw_t can_throw )
						{
							handle_data_already_read_or_read_more(
									delete_protector,
									can_throw );
						} );
			} );
	}

	void
	on_timer_impl( delete_protector_t delete_protector ) override
	{
		if( std::chrono::steady_clock::now() >= m_created_at +
				context().config().socks_handshake_phase_timeout() )
		{
			wrap_action_and_handle_exceptions(
				delete_protector,
				[this]( delete_protector_t delete_protector, can_throw_t can_throw )
				{
					log_and_remove_connection(
							delete_protector,
							can_throw,
							remove_reason_t::current_operation_timed_out,
							spdlog::level::warn,
							"socks5: handshake phase timed out" );
				} );
		}
	}

public:
	std::string_view
	name() const noexcept override
	{
		return "socks5-no-authentification-handler";
	}

private:
	void
	handle_data_already_read_or_read_more(
		delete_protector_t delete_protector,
		can_throw_t can_throw )
	{
		if( const auto read_result = try_handle_data_read(
				delete_protector, can_throw );
				data_parsing_result_t::need_more == read_result )
		{
			// Нужно читать следующий кусок данных.
			read_some(
					can_throw,
					m_connection,
					m_auth_pdu,
					[this]
					( delete_protector_t delete_protector, can_throw_t can_throw )
					{
						handle_data_already_read_or_read_more(
								delete_protector, can_throw );
					} );
		}
	}

	[[nodiscard]]
	data_parsing_result_t
	try_handle_data_read(
		delete_protector_t delete_protector,
		can_throw_t can_throw )
	{
		buffer_read_trx_t read_trx{ m_auth_pdu };

		const auto version = m_auth_pdu.read_byte();

		// Здесь может быть такой фокус: curl присылает auth PDU с
		// пустыми username/password, а вот Firefox вообще не присылает
		// auth PDU и шлет сразу command PDU.
		// 
		// Поэтому, если номер версии соответствует SOCKS5, то сразу
		// переходим к другому connection-handler-у.
		if( version_byte == version )
		{
			replace_handler(
					delete_protector,
					can_throw,
					[this]( can_throw_t )
					{
						return make_command_stage_handler(
								m_ctx,
								m_id,
								std::move(m_connection),
								// Все, что было прочитано, передается
								// следующему connection-handler-у.
								m_auth_pdu.whole_data_as_sequence(),
								m_created_at );
					} );

			return data_parsing_result_t::success;
		}

		if( expected_version != version )
		{
			log_and_remove_connection(
					delete_protector,
					can_throw,
					remove_reason_t::protocol_error,
					spdlog::level::err,
					fmt::format( "unsupported version of socks5 username/password "
							"auth PDU: {}, expected version: {}",
							version, expected_version )
				);

			return data_parsing_result_t::invalid_data;
		}

		if( !m_auth_pdu.remaining() )
			return data_parsing_result_t::need_more;

		const auto uname_len = std::to_integer< std::size_t >(
				m_auth_pdu.read_byte() );
		if( uname_len != 0u )
		{
			log_and_remove_connection(
					delete_protector,
					can_throw,
					remove_reason_t::protocol_error,
					spdlog::level::err,
					fmt::format( "expected 0 as username length, read {}",
							uname_len )
				);

			return data_parsing_result_t::invalid_data;
		}

		if( !m_auth_pdu.remaining() )
			return data_parsing_result_t::need_more;

		const auto passwd_len = std::to_integer< std::size_t >(
				m_auth_pdu.read_byte() );
		if( passwd_len != 0 )
		{
			log_and_remove_connection(
					delete_protector,
					can_throw,
					remove_reason_t::protocol_error,
					spdlog::level::err,
					fmt::format( "expected 0 as password length, read {}",
							passwd_len )
				);

			return data_parsing_result_t::invalid_data;
		}

		// Все прочитано и ничего в буфере не осталось.
		read_trx.commit();

		// Можно переходить к следующему шагу.
		send_positive_response_then_replace_handler( can_throw );

		return data_parsing_result_t::success;
	}

	void
	send_positive_response_then_replace_handler( can_throw_t can_throw )
	{
		m_response.write_byte( expected_version );
		m_response.write_byte( access_granted );

		write_whole(
				can_throw,
				m_connection,
				m_response,
				[this]
				( delete_protector_t delete_protector, can_throw_t can_throw )
				{ 
					replace_handler(
							delete_protector,
							can_throw,
							[this]( can_throw_t ) 
							{
								return make_command_stage_handler(
									m_ctx,
									m_id,
									std::move(m_connection),
									std::nullopt,
									std::nullopt,
									m_created_at );
							} );
				} );
	}
};

//
// command_handler_t
//
class command_handler_t final : public connection_handler_t
{
	static constexpr std::byte connect_cmd{ 0x1u };
	static constexpr std::byte bind_cmd{ 0x2u };

	//! Буфер для чтения PDU с командной.
	/*!
	 * https://tools.ietf.org/html/rfc1928
	 */
	in_buffer_fixed_t<
			1 // VER
			+ 1 // CMD
			+ 1 // RESERVED
			+ 1 // ATYP
			+ 256 // DST.ADDR (это максимальная возможная длина).
			+ 2 // DST.PORT
		> m_command_pdu;

	//! Буфер для хранения значения отрицательного ответа.
	/*!
	 * Положительные ответы на command PDU будут формировать обработчики
	 * конкретных комманд.
	 */
	out_buffer_fixed_t<
			1 // VER
			+ 1 // REPLY
			+ 1 // RESERVED
			+ 1 // ATYP
		> m_negative_reply_pdu;

	//! Имя пользователя.
	/*!
	 * Если отсутствует, значит аутентификация должна быть по IP.
	 */
	std::optional<std::string> m_username;
	//! Пароль пользователя.
	std::optional<std::string> m_password;

	//! Время, когда соединение было принято.
	std::chrono::steady_clock::time_point m_created_at;

public:
	// Конструктор для случая, когда сперва извлекли PDU
	// с аутентификационной информацией.
	command_handler_t(
		handler_context_holder_t ctx,
		handler_context_t::connection_id_t id,
		asio::ip::tcp::socket connection,
		std::optional<std::string> username,
		std::optional<std::string> password,
		std::chrono::steady_clock::time_point created_at )
		:	connection_handler_t{ std::move(ctx), id, std::move(connection) }
		,	m_username{ std::move(username) }
		,	m_password{ std::move(password) }
		,	m_created_at{ created_at }
	{}

	// Конструктор для случая, когда ждали auth PDU с пустыми
	// username/password (такой PDU для no-auth присылает curl),
	// но вместо этого прилетел command PDU.
	command_handler_t(
		handler_context_holder_t ctx,
		handler_context_t::connection_id_t id,
		asio::ip::tcp::socket connection,
		byte_sequence_t first_bytes,
		std::chrono::steady_clock::time_point created_at )
		:	connection_handler_t{ std::move(ctx), id, std::move(connection) }
		,	m_command_pdu{ first_bytes }
		,	m_created_at{ created_at }
	{}

protected:
	void
	on_start_impl( delete_protector_t delete_protector ) override
	{
		wrap_action_and_handle_exceptions(
			delete_protector,
			[this]( delete_protector_t, can_throw_t can_throw )
			{
				read_some(
					can_throw,
					m_connection,
					m_command_pdu,
					[this]
					( delete_protector_t delete_protector, can_throw_t can_throw )
					{
						handle_data_already_read_or_read_more(
								delete_protector, can_throw );
					} );
			} );
	}

	void
	on_timer_impl( delete_protector_t delete_protector ) override
	{
		if( std::chrono::steady_clock::now() >= m_created_at +
				context().config().socks_handshake_phase_timeout() )
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
										"socks5_command timed out" );
							} );

					log_and_remove_connection(
							delete_protector,
							can_throw,
							remove_reason_t::current_operation_timed_out,
							spdlog::level::warn,
							"socks5: handshake phase timed out" );
				} );
		}
	}

public:
	std::string_view
	name() const noexcept override
	{
		return "socks5-command-handler";
	}

private:
	void
	handle_data_already_read_or_read_more(
		delete_protector_t delete_protector,
		can_throw_t can_throw )
	{
		if( const auto read_result = try_handle_data_read(
				delete_protector, can_throw );
				data_parsing_result_t::need_more == read_result )
		{
			// Нужно читать следующий кусок данных.
			read_some(
					can_throw,
					m_connection,
					m_command_pdu,
					[this]
					( delete_protector_t delete_protector, can_throw_t can_throw )
					{
						handle_data_already_read_or_read_more(
								delete_protector,
								can_throw );
					} );
		}
	}

	[[nodiscard]]
	data_parsing_result_t
	try_handle_data_read(
		delete_protector_t delete_protector,
		can_throw_t can_throw )
	{
		buffer_read_trx_t read_trx{ m_command_pdu };

		const auto version = m_command_pdu.read_byte();
		if( version_byte != version )
		{
			log_and_remove_connection(
					delete_protector,
					can_throw,
					remove_reason_t::protocol_error,
					spdlog::level::err,
					fmt::format( "unsupported version of socks5 command PDU: "
							"{}, expected version: {}",
							version, version_byte )
				);

			return data_parsing_result_t::invalid_data;
		}

		// Далее нам нужно прочитать не менее 3-х байт:
		// CMD, RSV, ATYP.
		if( m_command_pdu.remaining() < 3u )
			return data_parsing_result_t::need_more;

		const auto cmd = m_command_pdu.read_byte();
		(void)m_command_pdu.read_byte();
		const auto atype = m_command_pdu.read_byte();

		// Содержимое DST.ADDR будет зависеть от значения atype.
		data_parsing_result_t success_flag;
		byte_sequence_t dst_addr_bytes;
		std::tie(success_flag, dst_addr_bytes) = try_extract_dst_addr(
				delete_protector, can_throw, atype );
		if( success_flag != data_parsing_result_t::success )
			return success_flag;

		// Осталось прочитать DST.PORT.
		if( m_command_pdu.remaining() < 2u )
			return data_parsing_result_t::need_more;

		std::uint16_t dst_port =
				(std::to_integer<std::uint16_t>(m_command_pdu.read_byte()) << 8u) |
				std::to_integer<std::uint16_t>(m_command_pdu.read_byte());

		// В PDU больше ничего не должно оставаться.
		if( m_command_pdu.remaining() )
		{
			log_and_remove_connection(
					delete_protector,
					can_throw,
					remove_reason_t::protocol_error,
					spdlog::level::err,
					fmt::format( "some garbage in command PDU after reading "
							"all the data, remaining bytes: {}",
							m_command_pdu.remaining() )
				);

			return data_parsing_result_t::invalid_data;
		}

		// Все прочитано и ничего в буфере не осталось.
		read_trx.commit();

		if( connect_cmd == cmd )
		{
			// Эту команду должен обрабатывать другой handler.
			// Он же и вернет ответ на запрос.
			replace_handler(
					delete_protector,
					can_throw,
					[&]( can_throw_t )
					{
						return make_connect_command_handler(
							m_ctx,
							m_id,
							std::move(m_connection),
							std::move(m_username), std::move(m_password),
							atype, dst_addr_bytes, dst_port );
					} );
		}
		else if( bind_cmd == cmd )
		{
			// Эту команду должен обрабатывать другой handler.
			// Он же и вернет ответ на запрос.
			replace_handler(
					delete_protector,
					can_throw,
					[&]( can_throw_t )
					{
						return make_bind_command_handler(
							m_ctx,
							m_id,
							std::move(m_connection),
							std::move(m_username), std::move(m_password),
							atype, dst_addr_bytes, dst_port );
					} );
		}
		else
		{
			// Другие команды не поддерживаются, поэтому сразу же
			// отсылаем отрицательный результат.
			make_negative_command_reply( m_negative_reply_pdu,
					command_reply_command_not_supported );
			send_negative_reply_then_close_connection(
					can_throw, remove_reason_t::protocol_error );
		}

		return data_parsing_result_t::success;
	}

	/*!
	 * @attention
	 * В случае успеха возвращается byte_sequence_t, который не содержит
	 * отдельной копии данных, а указывает на область памяти внутри
	 * m_command_pdu.
	 *
	 * @note
	 * Может принудительно закрыть соединение, если обнаружит какие-то
	 * недопустимые значения (например, нулевую длину доменного имени).
	 */
	[[nodiscard]]
	std::tuple< data_parsing_result_t, byte_sequence_t >
	try_extract_dst_addr(
		delete_protector_t delete_protector,
		can_throw_t can_throw,
		std::byte atype )
	{
		if( atype_ipv4 == atype )
		{
			constexpr std::size_t addr_len = 4u;
			if( m_command_pdu.remaining() >= addr_len )
				return {
						data_parsing_result_t::success,
						m_command_pdu.read_bytes_as_sequence( addr_len )
				};
		}
		else if( atype_ipv6 == atype )
		{
			constexpr std::size_t addr_len = 16u;
			if( m_command_pdu.remaining() >= addr_len )
				return {
						data_parsing_result_t::success,
						m_command_pdu.read_bytes_as_sequence( addr_len )
				};
		}
		else if( atype_domainname == atype )
		{
			if( m_command_pdu.remaining() )
			{
				const std::size_t name_len = std::to_integer<std::size_t>(
						m_command_pdu.read_byte() );
				// Длина доменного имени не может быть нулевой!
				if( !name_len )
				{
					log_and_remove_connection(
							delete_protector,
							can_throw,
							remove_reason_t::protocol_error,
							spdlog::level::warn,
							"domainname length is zero in SOCKS5 command PDU" );
					return {
							data_parsing_result_t::invalid_data,
							byte_sequence_t{}
					};
				}
				else if( m_command_pdu.remaining() >= name_len )
					return {
							data_parsing_result_t::success,
							m_command_pdu.read_bytes_as_sequence( name_len )
					};
			}
		}
		else
		{
			make_negative_command_reply(
					m_negative_reply_pdu,
					command_reply_atype_not_supported );

			send_negative_reply_then_close_connection(
					can_throw, remove_reason_t::protocol_error );
		}

		return { data_parsing_result_t::need_more, byte_sequence_t{} };
	}

	void
	send_negative_reply_then_close_connection(
		can_throw_t can_throw,
		remove_reason_t reason )
	{
		write_whole(
				can_throw,
				m_connection,
				m_negative_reply_pdu,
				[this, reason]
				( delete_protector_t delete_protector, can_throw_t )
				{
					remove_handler( delete_protector, reason );
				} );
	}
};

//
// connect_and_bind_handler_base_t
//
/*!
 * @brief Вспомогательный класс, который содержит функциональность,
 * необходимую для реализации команд CONNECT и BIND.
 */
class connect_and_bind_handler_base_t : public connection_handler_t
{
protected:
	//! Буфер для ответного PDU.
	out_buffer_fixed_t< 
			1 // VER
			+ 1 // REP
			+ 1 // RESERVED
			+ 1 // ATYP
			+ 16 // BIND.ADDR (это максимальная длина для IPv6, DOMAINNAME мы
				// здесь не используем).
			+ 2 // BIND.PORT
		> m_response;

	//! Имя пользователя.
	std::optional<std::string> m_username;
	//! Пароль пользователя.
	std::optional<std::string> m_password;

	//! Тип адреса на который мы должны подключиться.
	using destination_addr_t = std::variant<
			asio::ip::address_v4,
			asio::ip::address_v6,
			std::string
		>;

	//! Адрес целевого хоста.
	/*!
	 * Это может быть IPv4 или IPv6 адрес, или же доменное имя
	 * в виде строки.
	 */
	destination_addr_t m_dst_addr;
	//! Порт целевого хоста.
	std::uint16_t m_dst_port;	

	//! Итоговое имя хоста, к которому нужно подключаться.
	/*!
	 * Имеет значение для аутентификации клиента.
	 */
	std::string m_target_host;

	//! Итоговый адрес, на который нужно подключаться.
	/*!
	 * В случае, если пользователь передал доменное имя,
	 * значение здесь получается в результате резолвинга
	 * доменного имени.
	 */
	std::optional< asio::ip::tcp::endpoint > m_target_endpoint;

	//! Ограничитель трафика для этого подключения.
	/*!
	 * Появляется только в результате успешной аутентификации.
	 */
	traffic_limiter_unique_ptr_t m_traffic_limiter;

	//! Когда именно началась операция, время которой нужно
	//! контролировать.
	std::chrono::steady_clock::time_point m_last_op_started_at;

	//! Тип указателя на метод, который контролирует длительность
	//! последней начатой операции.
	using timeout_handler_t = void (*)(
			connect_and_bind_handler_base_t &,
			delete_protector_t,
			can_throw_t);

	//! Указатель на метод, который контролирует длительность
	//! последней начатой операции.
	timeout_handler_t m_last_op_timeout_handler{
			&connect_and_bind_handler_base_t::authentification_timeout_handler
		};

	/*!
	 * @attention
	 * Реализация этого метода исходит из того, что для случаев IPv4 и IPv6
	 * в dst_addr_bytes будет находится ровно такое количество байт,
	 * какое нам необходимо.
	 */
	[[nodiscard]]
	static destination_addr_t
	make_destination_addr(
		std::byte atype_value,
		byte_sequence_t dst_addr_bytes )
	{
		const auto byte_to_uch = []( std::byte b ) {
				return std::to_integer<unsigned char>(b);
			};

		if( atype_ipv4 == atype_value )
		{
			asio::ip::address_v4::bytes_type raw_bytes;
			std::transform(
					dst_addr_bytes.begin(), dst_addr_bytes.end(),
					raw_bytes.begin(),
					byte_to_uch );
			return asio::ip::address_v4{ raw_bytes };
		}
		else if( atype_ipv6 == atype_value )
		{
			asio::ip::address_v6::bytes_type raw_bytes;
			std::transform(
					dst_addr_bytes.begin(), dst_addr_bytes.end(),
					raw_bytes.begin(),
					byte_to_uch );
			return asio::ip::address_v6{ raw_bytes };
		}
		else if( atype_domainname == atype_value )
		{
			return dst_addr_bytes.to_string();
		}

		throw acl_handler_ex_t{
				fmt::format( "unsupported ATYP value: {}", atype_value )
			};
	}

public:
	connect_and_bind_handler_base_t(
		handler_context_holder_t ctx,
		handler_context_t::connection_id_t id,
		asio::ip::tcp::socket connection,
		std::optional<std::string> username,
		std::optional<std::string> password,
		std::byte atype_value,
		byte_sequence_t dst_addr,
		std::uint16_t dst_port )
		:	connection_handler_t{ std::move(ctx), id, std::move(connection) }
		,	m_username{ std::move(username) }
		,	m_password{ std::move(password) }
		,	m_dst_addr{ make_destination_addr( atype_value, dst_addr ) }
		,	m_dst_port{ dst_port }
		,	m_last_op_started_at{ std::chrono::steady_clock::now() }
	{}

protected:
	void
	on_start_impl( delete_protector_t delete_protector ) override
	{
		wrap_action_and_handle_exceptions(
			delete_protector,
			[this]( delete_protector_t, can_throw_t can_throw ) {
				// Начальные действия зависят от того, что нам
				// передали в dst_addr.
				std::visit( ::arataga::utils::overloaded{
					[this, can_throw]( const asio::ip::address_v4 & ipv4 ) {
						try_start_with_direct_address( can_throw, ipv4 );
					},
					[this, can_throw]( const asio::ip::address_v6 & ipv6 ) {
						try_start_with_direct_address( can_throw, ipv6 );
					},
					[this, can_throw]( const std::string & hostname ) {
						// Имя целевого узла известно сразу.
						// Сохраняем его для использования затем в процедуре
						// аутентификации.
						m_target_host = hostname;

						// Поскольку процедура DNS lookup может быть достаточно
						// дорогой, то сперва проводим аутентификацию пользователя.
						// И только если если пользователю разрешается доступ
						// к целевому узлу, тогда инициируем DNS lookup.
						initiate_authentification( can_throw );
					} },
					m_dst_addr );
			} );
	}

	void
	on_timer_impl( delete_protector_t delete_protector ) override
	{
		wrap_action_and_handle_exceptions(
			delete_protector,
			[this]( delete_protector_t delete_protector, can_throw_t can_throw )
			{
				(*m_last_op_timeout_handler)(
						*this,
						delete_protector,
						can_throw );
			} );
	}

	//! Начать выполнение основной логики после успешной аутентификации
	//! и DNS-resolving-а.
	/*!
	 * Должен быть переопределен у наследника.
	 */
	virtual void
	initiate_next_step( can_throw_t ) = 0;

	static void
	dns_resolving_timeout_handler(
		connect_and_bind_handler_base_t & self,
		delete_protector_t,
		can_throw_t can_throw )
	{
		if( std::chrono::steady_clock::now() >= self.m_last_op_started_at +
				self.context().config().dns_resolving_timeout() )
		{
			self.send_negative_command_reply_then_close_connection(
					can_throw,
					remove_reason_t::current_operation_timed_out,
					spdlog::level::warn,
					"socks5: DNS resolving timed out",
					command_reply_host_unreachable );
		}
	}

	static void
	authentification_timeout_handler(
		connect_and_bind_handler_base_t & self,
		delete_protector_t,
		can_throw_t can_throw )
	{
		if( std::chrono::steady_clock::now() >= self.m_last_op_started_at +
				self.context().config().authentification_timeout() )
		{
			self.send_negative_command_reply_then_close_connection(
					can_throw,
					remove_reason_t::current_operation_timed_out,
					spdlog::level::warn,
					"socks5: authentification timed out",
					command_reply_connection_not_allowed );
		}
	}

	void
	set_operation_started_markers(
		timeout_handler_t timeout_handler )
	{
		m_last_op_started_at = std::chrono::steady_clock::now();
		m_last_op_timeout_handler = timeout_handler;
	}

	void
	try_start_with_direct_address(
		can_throw_t can_throw,
		asio::ip::address_v4 ipv4 )
	{
		// Актуальный target-endpoint будет зависеть от того, смотрит
		// ли ACL наружу как IPv4 или IPv6.
		if( context().config().out_addr().is_v6() )
			m_target_endpoint = asio::ip::tcp::endpoint{
					asio::ip::address{ ipv4 }.to_v6(),
					m_dst_port 
				};
		else
			m_target_endpoint = asio::ip::tcp::endpoint{ ipv4, m_dst_port };

		m_target_host = ipv4.to_string();

		initiate_authentification( can_throw );
	}

	void
	try_start_with_direct_address(
		can_throw_t can_throw,
		asio::ip::address_v6 ipv6 )
	{
		// Если ACL смотрит наружу как IPv4, то мы не можем обработать
		// подключение на IPv6 адрес.
		if( context().config().out_addr().is_v4() )
		{
			send_negative_command_reply_then_close_connection(
					can_throw,
					remove_reason_t::ip_version_mismatch,
					spdlog::level::warn,
					fmt::format( "target with IPv6 address can't be served by "
							"ACL with IPv4 out address, target_addr: {}",
							ipv6 ),
					command_reply_atype_not_supported );
		}
		else
		{
			m_target_endpoint = asio::ip::tcp::endpoint{ ipv6, m_dst_port };

			m_target_host = ipv6.to_string();

			initiate_authentification( can_throw );
		}
	}

	void
	initiate_hostname_resolving(
		can_throw_t /*can_throw*/,
		const std::string & hostname )
	{
		set_operation_started_markers(
				&connect_and_bind_handler_base_t::dns_resolving_timeout_handler );

		context().async_resolve_hostname(
				m_id,
				hostname,
				with<const dns_resolving::hostname_result_t &>().make_handler(
					[this](
						delete_protector_t,
						can_throw_t can_throw,
						const dns_resolving::hostname_result_t & result )
					{
						on_hostname_result( can_throw, result );
					} )
			);
	}

	void
	initiate_authentification(
		can_throw_t /*can_throw*/ )
	{
		set_operation_started_markers(
				&connect_and_bind_handler_base_t::authentification_timeout_handler );

		context().async_authentificate(
				m_id,
				authentification::request_params_t {
					// Пока работаем только с IPv4 адресами на входе,
					// поэтому не ждем ничего другого.
					m_connection.remote_endpoint().address().to_v4(),
					m_username,
					m_password,
					m_target_host,
					m_dst_port
				},
				with<authentification::result_t>().make_handler(
					[this]( delete_protector_t /*delete_protector*/,
						can_throw_t can_throw,
						authentification::result_t result )
					{
						on_authentification_result( can_throw, result );
					} )
			);
	}

	void
	on_hostname_result(
		can_throw_t can_throw,
		const dns_resolving::hostname_result_t & result )
	{
		std::visit( ::arataga::utils::overloaded{
				[this, can_throw]
				( const dns_resolving::hostname_found_t & info )
				{
					// Теперь мы точно знаем куда подключаться.
					m_target_endpoint = asio::ip::tcp::endpoint{
							info.m_ip, m_dst_port
						};

					initiate_next_step( can_throw );
				},
				[this, can_throw]
				( const dns_resolving::hostname_not_found_t & info )
				{
					// Информация о хосте не найдена.
					// Осталось только залогировать этот факт, отослать
					// отрицательный результат и закрыть подключение.
					send_negative_command_reply_then_close_connection(
							can_throw,
							remove_reason_t::unresolved_target,
							spdlog::level::warn,
							fmt::format( "DNS resolving failure: {}",
									info.m_error_desc ),
							command_reply_host_unreachable );
				}
			},
			result );
	}

	void
	on_authentification_result(
		can_throw_t can_throw,
		authentification::result_t & result )
	{
		std::visit( ::arataga::utils::overloaded{
				[this, can_throw]( authentification::success_t & info ) {
					m_traffic_limiter = std::move(info.m_traffic_limiter);

					// Если был указан hostname, то сперва нужно
					// выполнить DNS lookup. Но если использовались
					// прямые IP-адреса, то остается только подключаться
					// к целевому узлу.
					if( auto * hostname = std::get_if< std::string >(
							&m_dst_addr ) )
						initiate_hostname_resolving( can_throw, *hostname );
					else
						initiate_next_step( can_throw );
				},
				[this, can_throw]( const authentification::failure_t & info ) {
					// Пользователю не разрешено обращаться к целевому узлу.
					// Осталось только залогировать этот факт, отослать
					// отрицательный результат и закрыть подключение.
					send_negative_command_reply_then_close_connection(
							can_throw,
							remove_reason_t::access_denied,
							spdlog::level::warn,
							fmt::format( "user is not authentificated, reason: {}",
									authentification::to_string_view(
											info.m_reason ) ),
							command_reply_connection_not_allowed );
				}
			},
			result );
	}

	// Вспомогательный метод для упрощения процедуры закрытия
	// входящего подключения в случаях, когда работа не может быть
	// продолжена.
	void
	send_negative_command_reply_then_close_connection(
		can_throw_t can_throw,
		remove_reason_t reason,
		spdlog::level::level_enum log_level,
		std::string_view log_message,
		std::byte reply_code )
	{
		::arataga::logging::wrap_logging(
				proxy_logging_mode,
				log_level,
				[this, can_throw, log_message]( auto level )
				{
					log_message_for_connection( can_throw, level, log_message );
				} );

		make_negative_command_reply( m_response, reply_code );

		write_whole(
				can_throw,
				m_connection,
				m_response,
				[this, reason]( delete_protector_t delete_protector, can_throw_t )
				{
					remove_handler( delete_protector, reason );
				} );
	}

	template< typename Out_Buffer >
	static void
	make_positive_response_content(
		Out_Buffer & to,
		const asio::ip::tcp::endpoint & endpoint_to_report ) noexcept
	{
		// Готовим ответ, который должен уйти клиенту.
		to.write_byte( version_byte );
		to.write_byte( command_reply_successed );
		to.write_byte( std::byte{0x0} ); // RSV
		
		const auto & address = endpoint_to_report.address();
		if( address.is_v4() )
		{
			to.write_byte( atype_ipv4 ); // ATYPE.
			to.write_bytes_from( address.to_v4().to_bytes() );
		}
		else
		{
			to.write_byte( atype_ipv6 ); // ATYPE.
			to.write_bytes_from( address.to_v6().to_bytes() );
		}
		const auto port = endpoint_to_report.port();

		to.write_byte( to_byte( port >> 8 ) );
		to.write_byte( to_byte( port & 0xffu ) );
	}

};

//
// connect_command_handler_t
//
class connect_command_handler_t final
	:	public connect_and_bind_handler_base_t
{
	//! Сокет, который будет использоваться для создания исходящего
	//! подключения.
	asio::ip::tcp::socket m_out_connection;

public:
	connect_command_handler_t(
		handler_context_holder_t ctx,
		handler_context_t::connection_id_t id,
		asio::ip::tcp::socket connection,
		std::optional<std::string> username,
		std::optional<std::string> password,
		std::byte atype_value,
		byte_sequence_t dst_addr,
		std::uint16_t dst_port )
		:	connect_and_bind_handler_base_t{
				std::move(ctx), id, std::move(connection),
				std::move(username),
				std::move(password),
				atype_value,
				dst_addr,
				dst_port
			}
		// Исходящий сокет привязываем к тому же io_context-у, к которому
		// привязан и входящий сокет.
		,	m_out_connection{ m_connection.get_executor() }
	{}

	// Т.к. экземпляр может быть уничтожен в процессе выполнения
	// async_connect, то в своей реализации release() нужно закрывать
	// out_connection.
	void
	release() noexcept override
	{
		// Проглатываем возможные ошибки.
		asio::error_code ec;
		m_out_connection.close( ec );

		// И позволяем очисить ресурсы базовому классу.
		connect_and_bind_handler_base_t::release();
	}

	std::string_view
	name() const noexcept override
	{
		return "socks5-connect-command-handler";
	}

private:
	static void
	connect_target_timeout_handler(
		connect_and_bind_handler_base_t & self,
		delete_protector_t,
		can_throw_t can_throw )
	{
		// Просто так обращаться к содержимому базового класса нельзя,
		// поэтому используем тот факт, что self указывает на экземпляр
		// производного класса.
		// Если это не так, то выскочит исключение.
		auto & this_class = dynamic_cast< connect_command_handler_t & >( self );

		if( std::chrono::steady_clock::now() >=
				this_class.m_last_op_started_at +
				this_class.context().config().connect_target_timeout() )
		{
			this_class.send_negative_command_reply_then_close_connection(
					can_throw,
					remove_reason_t::current_operation_timed_out,
					spdlog::level::warn,
					"socks5: connect target-host timed out",
					command_reply_host_unreachable );
		}
	}

	void
	initiate_next_step( can_throw_t can_throw ) override
	{
		set_operation_started_markers(
				&connect_command_handler_t::connect_target_timeout_handler );

		try
		{
			// К этому моменту m_target_endpoint должен быть заполнен.
			// Специально это не контролируем, но обращение к его содержимому
			// делаем через std::optional::value().
			auto & target_endpoint = m_target_endpoint.value();

			asio::error_code ec;

			m_out_connection.open( target_endpoint.protocol(), ec );
			if( ec )
			{
				send_negative_command_reply_then_close_connection(
						can_throw,
						remove_reason_t::io_error,
						spdlog::level::err,
						fmt::format( "unable open outgoing socket: {}",
								ec.message() ),
						command_reply_general_server_failure );

				return;
			}

			// Новый сокет должен начать работать в неблокирующем режиме.
			m_out_connection.non_blocking( true, ec );
			if( ec )
			{
				send_negative_command_reply_then_close_connection(
						can_throw,
						remove_reason_t::io_error,
						spdlog::level::err,
						fmt::format( "unable switch outgoing socket to "
								"non-blocking mode: {}",
								ec.message() ),
						command_reply_general_server_failure );

				return;
			}

			// Подключаться нужно с внешнего IP, поэтому привяжем исходящий сокет
			// к этому IP.
			m_out_connection.bind(
					// Указываем 0 в качестве номера порта для того,
					// чтобы пор выделила ОС.
					asio::ip::tcp::endpoint{ context().config().out_addr(), 0u },
					ec );
			if( ec )
			{
				send_negative_command_reply_then_close_connection(
						can_throw,
						remove_reason_t::io_error,
						spdlog::level::critical,
						fmt::format( "unable to bind outgoing socket to address "
								"{}: {}",
								context().config().out_addr(),
								ec.message() ),
						command_reply_general_server_failure );

				return;
			}

			::arataga::logging::wrap_logging(
					proxy_logging_mode,
					spdlog::level::trace,
					[this, can_throw, &target_endpoint]( auto level )
					{
						log_message_for_connection(
								can_throw,
								level,
								fmt::format( "trying to connect {} from {}",
										target_endpoint,
										m_out_connection.local_endpoint() ) );
					} );

			// Осталось только выполнить подключение.
			m_out_connection.async_connect(
					target_endpoint,
					with<const asio::error_code &>().make_handler(
						[this](
							delete_protector_t /*delete_protector*/,
							can_throw_t can_throw,
							const asio::error_code & ec )
						{
							on_async_connect_result( can_throw, ec );
						} )
				);
		}
		catch( const std::exception & x ) 
		{
			send_negative_command_reply_then_close_connection(
					can_throw,
					remove_reason_t::unhandled_exception,
					spdlog::level::err,
					fmt::format( "an exception during the creation of "
							"outgoing connection from {} to {}: {}",
							context().config().out_addr(),
							m_target_endpoint.value(),
							x.what() ),
					command_reply_general_server_failure );
		}
	}

	void
	on_async_connect_result(
		can_throw_t can_throw,
		const asio::error_code & ec )
	{
		if( ec )
		{
			// Если это не отмена операции, то проблему нужно залогировать,
			// а клиенту следует отослать отрицательный ответ.
			if( asio::error::operation_aborted != ec )
			{
				send_negative_command_reply_then_close_connection(
						can_throw,
						remove_reason_t::io_error,
						spdlog::level::warn,
						fmt::format( "can't connect to target host {}: {}",
								m_target_endpoint.value(),
								ec.message() ),
						command_reply_connection_not_allowed );
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
										m_target_endpoint.value(),
										m_out_connection.local_endpoint() ) );
					} );

			make_and_send_positive_response_then_switch_handler( can_throw );
		}
	}

	void
	make_and_send_positive_response_then_switch_handler(
		can_throw_t can_throw )
	{
		// Готовим ответ, который должен уйти клиенту.
		make_positive_response_content(
				m_response, m_out_connection.local_endpoint() );

		// Теперь пишем ответ и ждем его отправки...
		write_whole(
				can_throw,
				m_connection,
				m_response,
				[this]( delete_protector_t delete_protector, can_throw_t can_throw )
				{
					// ...ответ отправлен, можно менять обработчика.
					replace_handler(
							delete_protector,
							can_throw,
							[this]( can_throw_t )
							{
								return make_data_transfer_handler(
									m_ctx,
									m_id,
									std::move(m_connection),
									std::move(m_out_connection),
									std::move(m_traffic_limiter) );
							} );
				} );
	}
};

//
// bind_command_handler_t
//
class bind_command_handler_t final
	:	public connect_and_bind_handler_base_t
{
	//! Сокет, который будет использоваться для приема входящих соединений.
	asio::ip::tcp::acceptor m_acceptor;

public:
	bind_command_handler_t(
		handler_context_holder_t ctx,
		handler_context_t::connection_id_t id,
		asio::ip::tcp::socket connection,
		std::optional<std::string> username,
		std::optional<std::string> password,
		std::byte atype_value,
		byte_sequence_t dst_addr,
		std::uint16_t dst_port )
		:	connect_and_bind_handler_base_t{
				std::move(ctx), id, std::move(connection),
				std::move(username),
				std::move(password),
				atype_value,
				dst_addr,
				dst_port
			}
		// Acceptor-а привязываем к тому же io_context-у, к которому
		// привязан и входящий сокет.
		,	m_acceptor{ m_connection.get_executor() }
	{}

	// Т.к. экземпляр может быть уничтожен в процессе выполнения
	// async_accept, то в своей реализации release() нужно закрывать
	// acceptor-а.
	void
	release() noexcept override
	{
		// Проглатываем возможные ошибки.
		asio::error_code ec;
		m_acceptor.close( ec );

		// И позволяем очисить ресурсы базовому классу.
		connect_and_bind_handler_base_t::release();
	}

	std::string_view
	name() const noexcept override
	{
		return "socks5-bind-command-handler";
	}

private:
	static void
	accept_incoming_timeout_handler(
		connect_and_bind_handler_base_t & self,
		delete_protector_t,
		can_throw_t can_throw )
	{
		// Просто так обращаться к содержимому базового класса нельзя,
		// поэтому используем тот факт, что self указывает на экземпляр
		// производного класса.
		// Если это не так, то выскочит исключение.
		auto & this_class = dynamic_cast< bind_command_handler_t & >( self );

		if( std::chrono::steady_clock::now() >=
				this_class.m_last_op_started_at +
				this_class.context().config().socks_bind_timeout() )
		{
			this_class.send_negative_command_reply_then_close_connection(
					can_throw,
					remove_reason_t::current_operation_timed_out,
					spdlog::level::warn,
					"socks5: accepting an incoming connection timed out",
					command_reply_host_unreachable );
		}
	}

	void
	initiate_next_step( can_throw_t can_throw ) override
	{
		set_operation_started_markers(
				&bind_command_handler_t::accept_incoming_timeout_handler );

		// Вспомогательная функция для того, чтобы уменьшить объем кода
		// по выполнению однотипных действий в случае ошибки.
		const auto finish_on_failure =
			[this, can_throw]( std::string message ) -> void {
				send_negative_command_reply_then_close_connection(
						can_throw,
						remove_reason_t::io_error,
						spdlog::level::err,
						message,
						command_reply_general_server_failure );
			};

		try
		{
			// Формируем адрес, на котором мы должны ждать подключения.
			const asio::ip::tcp::acceptor::endpoint_type new_entry_endpoint{
					context().config().out_addr(),
					0u // Просим операционку выдать нам номер порта.
			};

			asio::error_code ec;

			m_acceptor.open( new_entry_endpoint.protocol(), ec );
			if( ec )
			{
				return finish_on_failure(
						fmt::format( "unable make new entry point: {}",
								ec.message() ) );
			}

			m_acceptor.non_blocking( true, ec );
			if( ec )
			{
				return finish_on_failure(
						fmt::format( "unable switch outgoing socket to "
								"non-blocking mode: {}",
								ec.message() ) );
			}

			m_acceptor.set_option(
					asio::ip::tcp::acceptor::reuse_address( true ), ec );
			if( ec )
			{
				return finish_on_failure(
						fmt::format( "unable to sent REUSEADDR option: {}",
								ec.message() ) );
			}

			// Подключаться нужно с внешнего IP, поэтому привяжем точку
			// входа к этому IP.
			m_acceptor.bind( new_entry_endpoint, ec );
			if( ec )
			{
				return finish_on_failure(
						fmt::format( "unable to bind outgoing socket to address "
								"{}: {}",
								new_entry_endpoint.address(),
								ec.message() ) );
			}

			// Ждем всего одного подключения.
			m_acceptor.listen( 1, ec );
			if( ec )
			{
				return finish_on_failure(
						fmt::format( "call to acceptor's listen failed: {}",
								ec.message() ) );
			}

			// Клиент должен получить от нас информацию о том,
			// что мы уже готовы принимать входящие подключения.
			// А когда этот ответ будет записан, можно будет начать
			// принимать новые соединения.
			make_and_send_first_positive_response_then_initiate_accept(
					can_throw );
		}
		catch( const std::exception & x ) 
		{
			send_negative_command_reply_then_close_connection(
					can_throw,
					remove_reason_t::unhandled_exception,
					spdlog::level::err,
					fmt::format( "an exception during the creation of "
							"outgoing connection from {} to {}: {}",
							context().config().out_addr(),
							m_target_endpoint.value(),
							x.what() ),
					command_reply_general_server_failure );
		}
	}

	void
	initiate_async_accept(
		can_throw_t can_throw )
	{
		::arataga::logging::wrap_logging(
				proxy_logging_mode,
				spdlog::level::debug,
				[this, can_throw]( auto level ) {
					log_message_for_connection(
							can_throw,
							level,
							fmt::format( "accepting incomming connection on {}",
									m_acceptor.local_endpoint() ) );
				} );

		m_acceptor.async_accept(
				with<const asio::error_code &, asio::ip::tcp::socket>()
				.make_handler(
					[this]( delete_protector_t /*delete_protector*/,
						can_throw_t can_throw,
						const asio::error_code & ec,
						asio::ip::tcp::socket connection )
					{
						on_async_accept_result( can_throw, ec, std::move(connection) );
					} )
			);
	}

	void
	on_async_accept_result(
		can_throw_t can_throw,
		const asio::error_code & ec,
		asio::ip::tcp::socket connection )
	{
		if( ec )
		{
			// Если это не отмена операции, то проблему нужно залогировать,
			// а клиенту следует отослать отрицательный ответ.
			if( asio::error::operation_aborted != ec )
			{
				send_negative_command_reply_then_close_connection(
						can_throw,
						remove_reason_t::io_error,
						spdlog::level::warn,
						fmt::format( "can't accept a new connection on {}: {}",
								m_acceptor.local_endpoint(),
								ec.message() ),
						command_reply_general_server_failure );
			}
		}
		else
		{
			const auto & in_connection_endpoint = connection.remote_endpoint();

			::arataga::logging::wrap_logging(
					proxy_logging_mode,
					spdlog::level::trace,
					[this, can_throw, &in_connection_endpoint]( auto level )
					{
						log_message_for_connection(
								can_throw,
								level,
								fmt::format(
										"incoming connection from {} accepted on {}",
										in_connection_endpoint,
										m_acceptor.local_endpoint() ) );
					} );

			// Новое подключение должно прийти именно с того адреса,
			// который был изначально указан в команде bind.
			if( in_connection_endpoint.address() !=
					m_target_endpoint.value().address() )
			{
				// Это какое-то левое подключение, закрываем его.
				connection.close();

				// Инициируем прием нового подключения.
				initiate_async_accept( can_throw );
			}
			else
			{
				// Дождались нормального подключения. Отсылаем
				// второй результат и ждем возможности поменять обработчик.
				make_send_second_positive_response_then_switch_handler(
						can_throw,
						in_connection_endpoint,
						std::move(connection) );
			}
		}
	}

	void
	make_and_send_first_positive_response_then_initiate_accept(
		can_throw_t can_throw )
	{
		// Готовим ответ, который должен уйти клиенту.
		make_positive_response_content(
				m_response,
				m_acceptor.local_endpoint() );

		// Теперь пишем ответ.
		write_whole(
				can_throw,
				m_connection,
				m_response,
				[this]( delete_protector_t, can_throw_t can_throw )
				{
					// ...ответ отправлен, можно принимать входящие подключения.
					initiate_async_accept( can_throw );
				} );
	}

	void
	make_send_second_positive_response_then_switch_handler(
		can_throw_t can_throw,
		asio::ip::tcp::endpoint in_connection_endpoint,
		asio::ip::tcp::socket connection )
	{
		// К этому моменту в m_response уже ничего важного
		// не должно было остаться.
		m_response.reset();
		make_positive_response_content(
				m_response,
				in_connection_endpoint );

		// Теперь пишем ответ и ждем его отправки...
		write_whole(
				can_throw,
				m_connection,
				m_response,
				[this, in_conn = std::move(connection)](
					delete_protector_t delete_protector,
					can_throw_t can_throw ) mutable
				{
					// ...ответ отправлен, можно менять обработчика.
					replace_handler(
							delete_protector,
							can_throw,
							[this, &in_conn]( can_throw_t )
							{
								return make_data_transfer_handler(
									m_ctx,
									m_id,
									std::move(m_connection),
									std::move(in_conn),
									std::move(m_traffic_limiter) );
							} );
				} );
	}
};

//
// make_username_password_auth_stage_handler
//

[[nodiscard]]
connection_handler_shptr_t
make_username_password_auth_stage_handler(
	handler_context_holder_t ctx,
	handler_context_t::connection_id_t id,
	asio::ip::tcp::socket connection,
	std::chrono::steady_clock::time_point created_at )
{
	return std::make_shared< username_password_auth_handler_t >(
			std::move(ctx), id, std::move(connection), created_at );
}

//
// make_no_authentification_stage_handler
//
[[nodiscard]]
connection_handler_shptr_t
make_no_authentification_stage_handler(
	handler_context_holder_t ctx,
	handler_context_t::connection_id_t id,
	asio::ip::tcp::socket connection,
	std::chrono::steady_clock::time_point created_at )
{
	return std::make_shared< no_authentification_handler_t >(
			std::move(ctx), id, std::move(connection), created_at );
}

//
// make_command_stage_handler
//

[[nodiscard]]
connection_handler_shptr_t
make_command_stage_handler(
	handler_context_holder_t ctx,
	handler_context_t::connection_id_t id,
	asio::ip::tcp::socket connection,
	std::optional<std::string> username,
	std::optional<std::string> password,
	std::chrono::steady_clock::time_point created_at )
{
	return std::make_shared< command_handler_t >(
			std::move(ctx), id, std::move(connection),
			std::move(username), std::move(password),
			created_at );
}

[[nodiscard]]
connection_handler_shptr_t
make_command_stage_handler(
	handler_context_holder_t ctx,
	handler_context_t::connection_id_t id,
	asio::ip::tcp::socket connection,
	byte_sequence_t first_bytes,
	std::chrono::steady_clock::time_point created_at )
{
	return std::make_shared< command_handler_t >(
			std::move(ctx), id, std::move(connection),
			first_bytes,
			created_at );
}

//
// make_connect_command_handler
//
[[nodiscard]]
connection_handler_shptr_t
make_connect_command_handler(
	handler_context_holder_t ctx,
	handler_context_t::connection_id_t id,
	asio::ip::tcp::socket connection,
	std::optional<std::string> username,
	std::optional<std::string> password,
	std::byte atype_value,
	byte_sequence_t dst_addr,
	std::uint16_t dst_port )
{
	return std::make_shared< connect_command_handler_t >(
			std::move(ctx), id, std::move(connection),
			std::move(username), std::move(password),
			atype_value, dst_addr, dst_port );
}

//
// make_bind_command_handler
//
[[nodiscard]]
connection_handler_shptr_t
make_bind_command_handler(
	handler_context_holder_t ctx,
	handler_context_t::connection_id_t id,
	asio::ip::tcp::socket connection,
	std::optional<std::string> username,
	std::optional<std::string> password,
	std::byte atype_value,
	byte_sequence_t dst_addr,
	std::uint16_t dst_port )
{
	return std::make_shared< bind_command_handler_t >(
			std::move(ctx), id, std::move(connection),
			std::move(username), std::move(password),
			atype_value, dst_addr, dst_port );
}

} /* namespace handlers::socks5 */

//
// make_socks5_auth_method_detection_handler
//
[[nodiscard]]
connection_handler_shptr_t
make_socks5_auth_method_detection_handler(
	handler_context_holder_t ctx,
	handler_context_t::connection_id_t id,
	asio::ip::tcp::socket connection,
	byte_sequence_t whole_first_pdu,
	std::chrono::steady_clock::time_point created_at )
{
	using namespace handlers::socks5;

	return std::make_shared< auth_method_detection_handler_t >(
			std::move(ctx), id, std::move(connection),
			whole_first_pdu, created_at );
}

} /* namespace arataga::acl_handler */

