/*!
 * @file
 * @brief Средства для работы с конфигурацией.
 */

#pragma once

#include <arataga/exception.hpp>

#include <arataga/bandlim_config.hpp>

#include <spdlog/spdlog.h>

#include <asio/ip/address.hpp>

#include <algorithm>
#include <chrono>
#include <memory>
#include <ostream>
#include <string_view>
#include <tuple>
#include <variant>

namespace arataga
{

//
// denied_ports_config_t
//
/*!
 * @brief Конфигурация TCP-портов, обращения по которым для клиентов
 * запрещены.
 */
struct denied_ports_config_t
{
	//! Тип для представления номера порта.
	using port_t = std::uint16_t;

	//! Случай, когда блокируется единственный порт.
	struct single_port_case_t
	{
		port_t m_port;

		// Для отладочных целей.
		[[nodiscard]]
		bool
		operator==( const single_port_case_t & b ) const noexcept
		{
			return this->m_port == b.m_port;
		}
	};

	//! Случай, когда блокируется диапазон портов.
	/*!
	 * Хранит диапазон вида [low, high].
	 */
	struct ports_range_case_t
	{
		port_t m_low;
		port_t m_high;

		// Для отладочных целей.
		[[nodiscard]]
		bool
		operator==( const ports_range_case_t & b ) const noexcept
		{
			return this->m_low == b.m_low && this->m_high == b.m_high;
		}
	};

	//! Описание одной блокировки.
	using denied_case_t = std::variant<
			single_port_case_t, ports_range_case_t >;

	//! Тип хранилища описаний блокировок.
	using case_container_t = std::vector< denied_case_t >;

	//! Заданные блокировки.
	/*!
	 * Список блокировок может быть пустым, в этом случае клиент
	 * может обращаться по любым портам.
	 */
	case_container_t m_cases;

	//! Вспомогательная функция для проверки того, что порт заблокирован.
	[[nodiscard]]
	bool
	is_denied( port_t port ) const noexcept
	{
		struct checker_t {
			port_t m_port;

			bool
			operator()( const single_port_case_t & c ) const noexcept
			{
				return c.m_port == m_port;
			}

			bool
			operator()( const ports_range_case_t & c ) const noexcept
			{
				return c.m_low <= m_port && m_port <= c.m_high;
			}
		};

		return std::any_of( m_cases.begin(), m_cases.end(),
				[port]( const auto & c ) noexcept {
					return std::visit( checker_t{ port }, c );
				} );
	}
};

//
// acl_protocol_t
//
/*!
 * @brief Тип протокола, который должен обслуживать ACL (http, socks и пр.).
 */
enum class acl_protocol_t
{
	//! ACL должен автоматически определить тип протокола.
	autodetect,
	//! ACL должен использовать протокол SOCKS.
	socks,
	//! ACL должен использовать протокол HTTP.
	http
};

// Для отладочных целей.
std::ostream &
operator<<( std::ostream & to, acl_protocol_t proto );

//
// acl_config_t
//
/*!
 * @brief Конфигурация для одного ACL.
 */
struct acl_config_t
{
	//! Тип для представления номера порта.
	using port_t = std::uint16_t;

	//! Тип протокола, который должен обслуживать ACL.
	acl_protocol_t m_protocol;

	//! TCP-порт для входа в ACL.
	/*!
	 * Этот TCP-порт будет открыт ACL и на него ACL будет принимать
	 * входящие подключения от клиентов.
	 */
	port_t m_port;

	//! IP-адрес для подключения к ACL.
	/*!
	 * На этот IP-адрес будут подключаться клиенты.
	 *
	 * Пока на входе поддерживаются только IPv4 адреса.
	 */
	asio::ip::address_v4 m_in_addr;

	//! IP-адрес, с которого ACL будет подключаться к удаленным хостам.
	/*!
	 * Этот IP-адрес ACL будет использовать для того, чтобы подключаться
	 * к удаленным хостам для обслуживания запросов клиентов.
	 */
	asio::ip::address m_out_addr;

	//! Инициализирующий конструктор.
	acl_config_t(
		acl_protocol_t protocol,
		port_t port,
		asio::ip::address_v4 in_addr,
		asio::ip::address out_addr )
		:	m_protocol{ protocol }
		,	m_port{ port }
		,	m_in_addr{ std::move(in_addr) }
		,	m_out_addr{ std::move(out_addr) }
	{}

	// Для отладочных целей.
	[[nodiscard]]
	bool
	operator==( const acl_config_t & b ) const noexcept
	{
		const auto tup = []( const auto & v ) {
			return std::tie( v.m_protocol, v.m_port,
					v.m_in_addr, v.m_out_addr );
		};
		return tup( *this ) == tup( b );
	}
};

// Для отладочных целей.
std::ostream &
operator<<( std::ostream & to, const acl_config_t & acl );

//
// http_message_value_limits_t
//
/*!
 * @brief Набор ограничений для сообщений в HTTP-протоколе.
 */
struct http_message_value_limits_t
{
	//! Длина значения request-target в start-line HTTP-запроса.
	std::size_t m_max_request_target_length{ 8u*1024u };
	//! Длина имени HTTP-заголовка.
	std::size_t m_max_field_name_length{ 2u*1024u };
	//! Длина значения HTTP-заголовка.
	std::size_t m_max_field_value_length{ 10u*1024u };
	//! Общий размер всех HTTP-заголовков.
	std::size_t m_max_total_headers_size{ 80u*1024u };
	//! Длина status-line HTTP-ответа.
	std::size_t m_max_status_line_length{ 1u*1024u };
};

//
// common_acl_params_t
//
/*!
 * @brief Набор общих для всех ACL параметров.
 */
struct common_acl_params_t
{
	/*!
	 * @brief Максимальное количество одновременных подключений
	 * к одному ACL.
	 */
	unsigned int m_maxconn{ 100u };

	/*!
	 * @brief Ограничения на трафик клиента по умолчанию.
	 *
	 * Эти органичения применяются, если для клиента не задано
	 * индивидуальных лимитов.
	 */
	bandlim_config_t m_client_bandlim;

	/*!
	 * @brief Тайм-аут перед отдачей ответа о неудачной аутентификации.
	 */
	std::chrono::milliseconds m_failed_auth_reply_timeout{ 750 };

	/*!
	 * @name Различные тайм-ауты при обработке подключений клиентов.
	 * @{
	 */
	std::chrono::milliseconds m_protocol_detection_timeout{ 3'000 };
	std::chrono::milliseconds m_socks_handshake_phase_timeout{ 5'000 };
	std::chrono::milliseconds m_dns_resolving_timeout{ 4'000 };
	std::chrono::milliseconds m_authentification_timeout{ 1'500 };
	std::chrono::milliseconds m_connect_target_timeout{ 5'000 };
	std::chrono::milliseconds m_socks_bind_timeout{ 20'000 };
	std::chrono::milliseconds m_idle_connection_timeout{ 300'000 };
	std::chrono::milliseconds m_http_headers_complete_timeout{ 5'000 };
	std::chrono::milliseconds m_http_negative_response_timeout{ 2'000 };
	/*!
	 * @}
	 */

	/*!
	 * @brief Размер одного буфера для выполнения операций ввода-вывода.
	 *
	 * Этот размер учитывается для соединений, которые уже полностью
	 * прошли стадию handshake и аутентификации пользователя. В процессе
	 * handshaking-а могут использоваться буфера другого размера.
	 */
	std::size_t m_io_chunk_size{ 8 * 1024 };

	/*!
	 * @brief Различные ограничения на размеры сущностей в HTTP-протоколе.
	 */
	http_message_value_limits_t m_http_message_limits{};
};

/*!
 * @brief Конфигурация всего arataga.
 */
struct config_t
{
	/*!
	 * @brief Уровень логирования, который должен использоваться.
	 *
	 * Значение spdlog::level::off означает, что логирование
	 * должно быть отключено.
	 */
	spdlog::level::level_enum m_log_level{ spdlog::level::info };

	/*!
	 * @brief Период очистки кэша DNS.
	 */
	std::chrono::milliseconds m_dns_cache_cleanup_period{ 30*1000 };

	/*!
	 * @brief Заблокированные для клиента TCP-порты.
	 *
	 * Клиент не может подключаться на эти порты на целевых хостах.
	 */
	denied_ports_config_t m_denied_ports;

	/*!
	 * @brief Набор общих для всех ACL параметров.
	 */
	common_acl_params_t m_common_acl_params;

	/*!
	 * @brief Тип хранилища описаний ACL.
	 */
	using acl_container_t = std::vector< acl_config_t >;

	/*!
	 * @brief Список ACL.
	 *
	 * Может быть пустым. В этом случае ни один ACL не будет работать
	 * внутри arataga.
	 */
	acl_container_t m_acls;
};

//
// config_parser_t
//
/*!
 * @brief Класс для разбора содержимого конфига arataga.
 *
 * Предполагается, что экземпляр этого класса создается один раз
 * в начале работы программы, а затем переиспользуется.
 */
class config_parser_t
{
public:
	//! Тип исключения, которое может выбрасывать парсер конфига.
	struct parser_exception_t : public exception_t
	{
	public:
		parser_exception_t( const std::string & what );
	};

	config_parser_t();
	~config_parser_t();

	//! Разобрать содержимое конфига.
	/*!
	 * @throw parser_exception_t в случае возникновения ошибки.
	 */
	[[nodiscard]]
	config_t
	parse( std::string_view content );

private:
	struct impl_t;

	std::unique_ptr<impl_t> m_impl;
};

} /* namespace arataga */

