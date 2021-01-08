/*!
 * @file
 * @brief Публичный интерфейс админстративного HTTP-входа.
 */

#pragma once

#include <arataga/exception.hpp>

#include <asio/ip/address.hpp>

#include <memory>
#include <optional>
#include <string>

namespace arataga::admin_http_entry
{

//
// running_entry_instance_t
//
/*!
 * @brief Интерфейс объекта, который отвечает за останов
 * запущенного HTTP-входа.
 */
class running_entry_instance_t
{
public:
	virtual ~running_entry_instance_t();

	//! Выдача команды на принудительный останов HTTP-входа.
	virtual void
	stop() = 0;
};

//
// running_entry_handle_t
//
//! Псевдоним unique_ptr для running_entry_instance.
using running_entry_handle_t = std::unique_ptr< running_entry_instance_t >;

//
// status_t
//
//! Специальный тип для хранения кода ответа на HTTP-запрос.
class status_t
{
	std::uint16_t m_code;
	const char * m_reason_phrase;

public:
	constexpr explicit status_t(
		std::uint16_t code,
		const char * reason_phrase ) noexcept
		:	m_code{ code }
		,	m_reason_phrase{ reason_phrase }
	{}

	[[nodiscard]]
	constexpr auto
	code() const noexcept { return m_code; }

	[[nodiscard]]
	constexpr auto
	reason_phrase() const noexcept { return m_reason_phrase; }

	[[nodiscard]]
	constexpr bool
	operator<( const status_t & o ) const noexcept
	{
		return this->m_code < o.m_code;
	}

	[[nodiscard]]
	constexpr bool
	operator==( const status_t & o ) const noexcept
	{
		return this->m_code == o.m_code;
	}
};

// Статусы, которые определены для arataga.
inline constexpr status_t status_ok{
		200u,
		"Ok"
};

inline constexpr status_t status_bad_request{
		400u,
		"Bad Request"
};

inline constexpr status_t status_internal_server_error{
		500u,
		"Internal Server Error"
};

inline constexpr status_t status_config_processor_failure{
		520u,
		"config_processor Failure"
};

inline constexpr status_t status_user_list_processor_failure{
		521u,
		"user_list_processor Failure"
};

//
// replier_t
//
/*!
 * @brief Интерфейс объекта для ответа на ранее полученный запрос.
 */
class replier_t
{
public:
	virtual ~replier_t();

	//! Параметры для ответа в виде структуры.
	struct reply_params_t
	{
		//! Код ответа.
		status_t m_status;
		//! Основная часть ответа.
		std::string m_body;
	};

	virtual void
	reply(
		//! Числовой код ответа.
		status_t status,
		//! Основная часть ответа.
		std::string body ) = 0;

	void
	reply( reply_params_t params )
	{
		this->reply(
				params.m_status,
				std::move(params.m_body) );
	}
};

//
// replier_shptr_t
//
/*!
 * @brief Тип умного указателя для replier.
 */
using replier_shptr_t = std::shared_ptr< replier_t >;

namespace debug_requests
{

//! Тестовый запрос на аутентификацию клиента.
struct authentificate_t
{
	asio::ip::address_v4 m_proxy_in_addr;
	std::uint16_t m_proxy_port;

	asio::ip::address_v4 m_user_ip;

	std::optional< std::string > m_username;
	std::optional< std::string > m_password;

	std::string m_target_host;
	std::uint16_t m_target_port;
};

//! Тестовый запрос на разрешение доменного имени.
struct dns_resolve_t
{
	asio::ip::address_v4 m_proxy_in_addr;
	std::uint16_t m_proxy_port;

	std::string m_target_host;
	std::string m_ip_version;
};

} /* namespace debug_requests */

//
// requests_mailbox_t
//
/*!
 * @brief Интерфейс, с помощью которого HTTP-вход сможет отдавать
 * полученные запросы на обработку в SObjectizer-овскую часть.
 */
class requests_mailbox_t
{
public:
	virtual ~requests_mailbox_t();

	//! Передать запрос на обновление конфигурации.
	virtual void
	new_config(
		//! Объект для формирования ответа на этот запрос.
		replier_shptr_t replier,
		//! Содержимое нового конфига.
		std::string_view content ) = 0;

	//! Передать запрос на получение списка известных ACL.
	virtual void
	get_acl_list(
		//! Объект для формирования ответа на этот запрос.
		replier_shptr_t replier ) = 0;

	//! Передать запрос на обновление списка пользователей.
	virtual void
	new_user_list(
		//! Объект для формирования ответа на этот запрос.
		replier_shptr_t replier,
		//! Содержимое списка пользователей.
		std::string_view content ) = 0;

	//! Передать запрос на получение текущей статистики.
	virtual void
	get_current_stats(
		//! Объект для формирования ответа на этот запрос.
		replier_shptr_t replier ) = 0;

	//! Передать тестовый запрос на аутентификацию клиента.
	virtual void
	debug_authentificate(
		//! Объект для формирования ответа на этот запрос.
		replier_shptr_t replier,
		//! Параметры запроса.
		debug_requests::authentificate_t request ) = 0;

	//! Передать тестовый запрос на разршение доменного имени.
	virtual void
	debug_dns_resolve(
		//! Объект для формирования ответа на этот запрос.
		replier_shptr_t replier,
		//! Параметры запроса.
		debug_requests::dns_resolve_t request ) = 0;
};

//
// start_entry
//
/*!
 * @brief Функция для запуска административной HTTP-точки входа.
 *
 * Возвращает либо действительный running_entry_handle_t, либо порождает
 * исключение в случае проблем с запуском HTTP-точки входа.
 */
[[nodiscard]]
running_entry_handle_t
start_entry(
	//! IP-адрес, на котором должна работать точка входа.
	asio::ip::address entry_ip,
	//! TCP-порт, на котором должна работать точка входа.
	std::uint16_t entry_port,
	//! Значение токена, который должен присутствовать во
	//! входящих запросах для того, чтобы эти запросы принимались
	//! на обработку.
	std::string admin_token,
	//! Интерфейс, посредством которого HTTP-вход сможет общаться
	//! c SObjectizer-овской частью.
	//! Эта ссылка должна оставаться валидной на протяжении всего
	//! времени жизни точки входа.
	requests_mailbox_t & mailbox );

} /* namespace arataga::admin_http_entry */

