/*!
 * @file
 * @brief Публичная часть интерфейса агента authentificator.
 */

#pragma once

#include <arataga/application_context.hpp>

#include <arataga/user_list_auth_data.hpp>

#include <arataga/utils/acl_req_id.hpp>
#include <arataga/utils/overloaded.hpp>

#include <cstdint>
#include <optional>
#include <variant>

namespace arataga::authentificator
{

// Необходимые типы данных.

//! Идентификатор запроса на аутентификацию.
using auth_req_id_t = ::arataga::utils::acl_req_id_t;

//! Тип IP-адреса для ACL и клиентов.
/*!
 * В настоящий момент поддерживаются только IPv4 адреса.
 */
using ipv4_address_t = ::arataga::user_list_auth::ipv4_address_t;

//! Тип для номера IP-порта.
using ip_port_t = ::arataga::user_list_auth::ip_port_t;

//! Тип для идентификатора пользователя.
using user_id_t = ::arataga::user_list_auth::user_id_t;

//! Тип для хранения лимита для одного домена.
using one_domain_limit_t = ::arataga::user_list_auth::site_limits_data_t::one_limit_t;

//
// params_t
//
/*!
 * @brief Параметры, необходимые агенту для начала его работы.
 */
struct params_t
{
	//! Уникальное имя, которое должно использоваться этим агентом
	//! для логирования.
	std::string m_name;
};

//
// introduce_authentificator
//
/*!
 * @brief Функция для создания и запуска агента authentificator в
 * указанном SObjectizer Environment с привязкой к указанному диспетчеру.
 *
 * Возвращается ID новой кооперации с агентом authentificator и mbox,
 * через который можно общаться с агентом authentificator.
 */
[[nodiscard]]
std::tuple< so_5::coop_handle_t, so_5::mbox_t >
introduce_authentificator(
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

//
// failure_reason_t
//
//! Причина отказа в аутентификации/авторизации.
enum class failure_reason_t
{
	//! Пользователь не найден в списке разрешенных пользователей
	//! для указанного прокси-сервиса.
	unknown_user,

	//! Пользователь имеет право подключиться к прокси-сервису,
	//! но доступ к целевому хосту заблокирован.
	target_blocked,

	//! Истек тайм-аут проведения операции аутентификации.
	auth_operation_timedout,
};

//! Вспомогательная функция для получения строкового значения
//! соответствующего failure_reason.
[[nodiscard]]
std::string_view
to_string_view( failure_reason_t reason ) noexcept;

//
// failed_auth_t
//
//! Содержимое ответа для случая неудачной аутентификации.
struct failed_auth_t
{
	//! Причина отказа в аутентификации/авторизации.
	failure_reason_t m_reason;
};

//
// successful_auth_t
//
//! Содержимое ответа для случая успешной аутентификации.
struct successful_auth_t
{
	//! Идентификатор пользователя.
	user_id_t m_user_id;

	//! Индивидуальные лимиты для этого пользователя.
	bandlim_config_t m_user_bandlims;

	//! Индивидуальный лимит для целевого хоста для этого пользователя.
	std::optional< one_domain_limit_t > m_domain_limits;
};

//
// auth_result_t
//
//! Тип ответа на попытку аутентификации/авторизации.
using auth_result_t = std::variant< failed_auth_t, successful_auth_t >;

inline std::ostream &
operator<<( std::ostream & to, const auth_result_t & v )
{
	std::visit( ::arataga::utils::overloaded{
			[&to]( const failed_auth_t & info ) {
				to << "(failed: " << to_string_view(info.m_reason) << ')';
			},
			[&to]( const successful_auth_t & info ) {
				to << "(successful: user_id=" << info.m_user_id << ", ("
						<< info.m_user_bandlims << ")";
				if( info.m_domain_limits )
				{
					to << ", (" << info.m_domain_limits->m_domain << ": "
						<< info.m_domain_limits->m_bandlims << ")";
				}
				to << ")";
			}
		},
		v );
		
	return to;
}

//
// completion_token_t
//
/*!
 * @brief Интерфейс объекта, который передается в запросе на
 * аутентификацию и который должен вернуться в ответе на запрос.
 *
 * Предполагается, что объект, реализующий данный интерфейс,
 * будет упрощать обработку ответов в каких-то случаях.
 */
class completion_token_t
{
public:
	virtual ~completion_token_t();

	virtual void
	complete( const auth_result_t & result ) = 0;
};

//
// completion_token_shptr_t
//
//! Тип умного указателья для completion_token.
using completion_token_shptr_t = std::shared_ptr< completion_token_t >;

//
// auth_request_t
//
/*!
 * @brief Запрос на аутентификацию клиента.
 */
struct auth_request_t final : public so_5::message_t
{
	//! Идентификатор запроса на аутентификацию.
	auth_req_id_t m_req_id;
	//! Обратный адрес, на который нужно отослать ответ.
	so_5::mbox_t m_reply_to;

	//! Токен для завершения обработки запроса.
	/*!
	 * @note
	 * Может быть нулевым указателем.
	 */
	completion_token_shptr_t m_completion_token;

	//! IP адрес ACL, на который подключился клиент.
	ipv4_address_t m_proxy_in_addr;
	//! Порт ACL, на который подключился клиент.
	ip_port_t m_proxy_port;

	//! IP адрес клиента.
	ipv4_address_t m_user_ip;

	//! Имя пользователя.
	std::optional< std::string > m_username;
	//! Пароль пользователя.
	std::optional< std::string > m_password;

	//! Куда пользователь хочет подключиться.
	/*!
	 * Это доменное имя целевого хоста.
	 */
	std::string m_target_host;
	//! Порт на целевом хосте, куда хочет подключиться пользователь.
	ip_port_t m_target_port;
};

//
// auth_reply_t
//
/*!
 * @brief Ответное сообщение с результатом аутентификации.
 */
struct auth_reply_t final : public so_5::message_t
{
	//! Идентификатор исходного запроса.
	auth_req_id_t m_req_id;

	//! Токен для завершения обработки запроса.
	/*!
	 * @note
	 * Может быть нулевым указателем.
	 */
	completion_token_shptr_t m_completion_token;

	//! Результат аутентификации.
	auth_result_t m_result;

	auth_reply_t(
		auth_req_id_t req_id,
		completion_token_shptr_t completion_token,
		auth_result_t result )
		:	m_req_id{ req_id }
		,	m_completion_token{ std::move(completion_token) }
		,	m_result{ std::move(result) }
	{}
};

} /* namespace arataga::authentificator */

