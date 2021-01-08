/*!
 * @file
 * @brief Описания нотификаций, которые может рассылать агент config_processor.
 */

#pragma once

#include <arataga/config.hpp>

#include <so_5/all.hpp>

namespace arataga::config_processor
{

//
// started_t
//
/*!
 * @brief Уведомление о том, что config_processor успешно стартовал.
 */
struct started_t final : public so_5::signal_t {};

//
// updated_dns_params_t
//
/*!
 * @brief Сообщение с обновлением конфигурации для DNS-resolver-а.
 */
struct updated_dns_params_t final : public so_5::message_t
{
	std::chrono::milliseconds m_cache_cleanup_period;

	updated_dns_params_t(
		std::chrono::milliseconds cache_cleanup_period )
		:	m_cache_cleanup_period{ cache_cleanup_period }
	{}
};

//
// updated_common_acl_params_t
//
/*!
 * @brief Сообщение с новыми значениями общих параметров для всех ACL.
 */
struct updated_common_acl_params_t final : public so_5::message_t
{
	//! Обновленные параметры.
	const common_acl_params_t m_params;

	updated_common_acl_params_t(
		const common_acl_params_t & params )
		:	m_params{ params }
	{}
};

//
// updated_auth_params_t
//
/*!
 * @brief Сообщение об изменении параметров аутентификации клиентов.
 */
struct updated_auth_params_t final : public so_5::message_t
{
	/*!
	 * @brief Заблокированные для клиента TCP-порты.
	 */
	denied_ports_config_t m_denied_ports;

	/*!
	 * @brief Величина тайм-аута перед отдачей результата
	 * неудачной аутентификации клиента.
	 */
	std::chrono::milliseconds m_failed_auth_reply_timeout;

	updated_auth_params_t(
		denied_ports_config_t denied_ports,
		std::chrono::milliseconds failed_auth_reply_timeout )
		:	m_denied_ports{ std::move(denied_ports) }
		,	m_failed_auth_reply_timeout{ failed_auth_reply_timeout }
	{}
};

} /* namespace arataga::config_processor */

