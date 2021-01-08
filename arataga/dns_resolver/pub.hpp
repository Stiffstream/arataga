/*!
 * @file
 * @brief Публичная часть интерфейса агента dns_resolver.
 */

#pragma once

#include <arataga/application_context.hpp>
#include <arataga/utils/acl_req_id.hpp>
#include <arataga/utils/overloaded.hpp>

#include <asio/io_context.hpp>
#include <asio/ip/tcp.hpp>

#include <variant>

namespace arataga::dns_resolver
{

//! Идентификатор запроса на разрешение доменного имени.
using resolve_req_id_t = ::arataga::utils::acl_req_id_t;

//
// params_t
//
/*!
 * @brief Параметры, необходимые агенту для начала его работы.
 */
struct params_t
{
	//! Объект io_context, который должен использовать dns_resolver.
	asio::io_context & m_io_ctx;

	//! Уникальное имя, которое должно использоваться этим агентом
	//! для логирования.
	std::string m_name;

	//! Период, с которым нужно очищать кэш.
	std::chrono::milliseconds m_cache_cleanup_period;
};

namespace forward
{

//
// successful_resolve_t
//
//!
struct successful_resolve_t
{
	asio::ip::address m_address;
};

//
// failed_resolve_t
//
//!
struct failed_resolve_t
{
	std::string m_error_desc;
};

//
// resolve_result_t
//

using resolve_result_t = std::variant<
	failed_resolve_t,
	successful_resolve_t>;


inline std::ostream &
operator<<( std::ostream & to, const resolve_result_t & result )
{
	std::visit( ::arataga::utils::overloaded
		{
			[&to]( const failed_resolve_t & info )
			{
				to << "(failed: " << info.m_error_desc << ")";
			},
			[&to]( const successful_resolve_t & info )
			{
				to << "(successful: address=" <<
					info.m_address.to_string() << ")";
			}
		},
		result );

	return to;
}

//
// completion_token_t
//
/*!
 * @brief Интерфейс объекта, который передается в запросе на
 * разрешение имени и который должен вернуться в ответе на запрос.
 *
 * Предполагается, что объект, реализующий данный интерфейс,
 * будет упрощать обработку ответов в каких-то случаях.
 */
class completion_token_t
{
public:
	virtual ~completion_token_t() = default;

	virtual void
	complete( const resolve_result_t & result ) = 0;
};

//
// completion_token_shptr_t
//
//! Тип умного указателья для completion_token.
using completion_token_shptr_t = std::shared_ptr< completion_token_t >;

} // namespace forward

//! Перечисление, определяющее версию IP адреса.
enum class ip_version_t
{
	ip_v4,
	ip_v6
};

/*!
 * @brief Функция конвертации строки в версию IP адреса.
 *
 * @param ip Строковое представление версии IP адреса.
 * @return ip_version_t Версия IP адреса в формате элемента ip_version_t-
 */
[[nodiscard]]
inline ip_version_t
from_string( const std::string & ip )
{
	if( ip == "IPv4" )
		return ip_version_t::ip_v4;
	else if( ip == "IPv6" )
		return ip_version_t::ip_v6;
	else
		throw std::runtime_error(
			"Invalid ip version value: '" + ip +
			"'. Correct values are 'IPv4' and 'IPv6'." );
}

//
// resolve_request_t
//
/*!
 * @brief Сообщение с запросом на разрешение доменного имени.
 */
struct resolve_request_t final : public so_5::message_t
{
	//! Идетификатор запроса.
	resolve_req_id_t m_req_id;

	//! Имя ресурса, для которого нужно получить адрес.
	std::string m_name;

	//! В каком виде требуется представить ответ.
	ip_version_t m_ip_version = ip_version_t::ip_v4;

	//! Токен для завершения обработки запроса.
	/*!
	 * @note
	 * Может быть нулевым указателем.
	 */
	forward::completion_token_shptr_t m_completion_token;

	//! Mbox, на который нужно отправить ответ.
	so_5::mbox_t m_reply_to;

	resolve_request_t(
		resolve_req_id_t req_id,
		std::string name,
		forward::completion_token_shptr_t completion_token,
		so_5::mbox_t reply_to )
		:	m_req_id{ req_id }
		,	m_name{ std::move(name) }
		,	m_completion_token{ std::move(completion_token) }
		,	m_reply_to{ reply_to }
	{}

	resolve_request_t(
		resolve_req_id_t req_id,
		std::string name,
		ip_version_t ip_version,
		forward::completion_token_shptr_t completion_token,
		so_5::mbox_t reply_to )
		:	m_req_id{ req_id }
		,	m_name{ std::move(name) }
		,	m_ip_version{ std::move(ip_version) }
		,	m_completion_token{ std::move(completion_token) }
		,	m_reply_to{ reply_to }
	{}

	resolve_request_t() = default;
};

//
// resolve_reply_t
//
/*!
 * @brief Сообщение с результатом  имени.
 */
struct resolve_reply_t final : public so_5::message_t
{
	using completion_token_t = forward::completion_token_shptr_t;
	using resolve_result_t = forward::resolve_result_t;

	//!Идентификатор исходного запроса.
	resolve_req_id_t m_req_id;

	//! Токен для завершения обработки запроса.
	/*!
	 * @note
	 * Может быть нулевым указателем.
	 */
	forward::completion_token_shptr_t m_completion_token;

	//! Результат разрешения доменного имени.
	forward::resolve_result_t m_result;

	resolve_reply_t(
		resolve_req_id_t req_id,
		forward::completion_token_shptr_t completion_token,
		forward::resolve_result_t result )
		:	m_req_id{ req_id }
		,	m_completion_token{ std::move(completion_token) }
		,	m_result{ std::move(result) }
	{}
};

//
// introduce_dns_resolver
//
/*!
 * @brief Функция для создания и запуска агента dns_resolver в
 * указанном SObjectizer Environment с привязкой к указанному диспетчеру.
 *
 * Возвращается ID новой кооперации с агентом dns_resolver и mbox,
 * через который можно общаться с агентом dns_resolver.
 */
[[nodiscard]]
std::tuple< so_5::coop_handle_t, so_5::mbox_t >
introduce_dns_resolver(
	//! SObjectizer Environment, в котором нужно работать.
	so_5::environment_t & env,
	//! Родительская кооперация.
	so_5::coop_handle_t parent_coop,
	//! Диспетчер, к которому должен быть привязан новый агент.
	so_5::disp_binder_shptr_t disp_binder,
	//! Контекст всего arataga.
	application_context_t app_ctx,
	//! Индивидуальные параметры для нового агента.
	params_t params );

} /* namespace arataga::resolver */

