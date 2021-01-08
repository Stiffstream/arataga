/*!
 * @file
 * @brief Описание агента authentificator.
 */

#pragma once

#include <arataga/authentificator/pub.hpp>

#include <arataga/user_list_processor/notifications.hpp>
#include <arataga/config_processor/notifications.hpp>

namespace arataga::authentificator
{

//
// a_authentificator_t
//
/*!
 * @brief Агент, который обрабатывает аутентификацию и авторизацию
 * клиентов.
 *
 * @attention
 * Подписка на сообщения об обновлении конфигурации выполняется не
 * в so_define_agent(), а в so_evt_start(). Сделано это потому, что
 * если подписываться на retained-msg-mbox в so_define_agent(),
 * то агенту сразу будет отсылаться сообщение из retained-msg, а поскольку
 * регистрация кооперации с агентом еще не закончилась и агент не
 * привязан к очереди сообщений, то сообщение будет выброшено и к
 * агенту не попадет. Тогда как в so_evt_start() этой проблемы нет,
 * т.к. агент уже связан со своей очередью сообщений.
 */
class a_authentificator_t final : public so_5::agent_t
{
public:
	//! Основной конструктор.
	a_authentificator_t(
		context_t ctx,
		application_context_t app_ctx,
		params_t params );

	void
	so_define_agent() override;

	void
	so_evt_start() override;

private:
	//! Контекст всего arataga.
	const application_context_t m_app_ctx;

	//! Индивидуальные параметры этого агента.
	const params_t m_params;

	//! Локальная статистика этого агента.
	::arataga::stats::auth::auth_stats_t m_auth_stats;
	::arataga::stats::auth::auto_reg_t m_auth_stats_reg;

	//! Своя локальная копия списка пользователей.
	/*!
	 * Своя копия делается для простоты реализации самой первой
	 * версии arataga.
	 */
	::arataga::user_list_auth::auth_data_t m_auth_data;

	//! Своя локальная копия списка заблокированных TCP-портов.
	denied_ports_config_t m_denied_ports;

	//! Величина тайм-аута перед отдачей результата неудачной
	//! аутентификации.
	std::chrono::milliseconds m_failed_auth_reply_timeout{ 750 };

	//! Реакция на обновление списка пользователей.
	void
	on_updated_user_list(
		mhood_t< ::arataga::user_list_processor::updated_user_list_t > cmd );

	//! Реакция на обновление списка параметров аутентификации.
	void
	on_updated_auth_params(
		mhood_t< ::arataga::config_processor::updated_auth_params_t > cmd );

	//! Реакция на запрос аутентифицировать/авторизовать клиента.
	void
	on_auth_request(
		mhood_t< auth_request_t > cmd );

	//! Выполнение аутентификации клиента по его IP-адресу.
	void
	do_auth_by_ip(
		const auth_request_t & req );

	//! Выполнение аутентификации клиента по login/password.
	void
	do_auth_by_login_password(
		const auth_request_t & req );

	//! Завершить неудачную попытку аутентификации клиента.
	void
	complete_failed_auth(
		const auth_request_t & req,
		failure_reason_t reason );

	//! Завершить успешную попытку аутентификации/авторизации клиента.
	void
	complete_successful_auth(
		const auth_request_t & req,
		const ::arataga::user_list_auth::user_data_t & user_data );

	//! Попробовать провести авторизацию клиента, которому
	//! разрешено подключится к прокси-сервису.
	/*!
	 * Возвращает пустое значение, если клиент успешно авторизован.
	 */
	[[nodiscard]]
	std::optional< failure_reason_t >
	try_authorize_user(
		const auth_request_t & req );

	//! Попробовать найти лимит для домена, к которому пользователь
	//! собирается обращаться.
	[[nodiscard]]
	std::optional< one_domain_limit_t >
	try_detect_domain_limits(
		const ::arataga::user_list_auth::user_data_t & user_data,
		const std::string & target_host ) const;
};

} /* namespace arataga::authentificator */

