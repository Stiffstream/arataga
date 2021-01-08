/*!
 * @file
 * @brief Публичная часть интерфейса агента acl_handler.
 */

#pragma once

#include <arataga/application_context.hpp>

#include <arataga/config.hpp>

#include <asio/io_context.hpp>

namespace arataga::acl_handler
{

//
// params_t
//
/*!
 * @brief Параметры, необходимые агенту для начала его работы.
 */
struct params_t
{
	//! Asio-шный контекст, на котором предстоит работать этому агенту.
	asio::io_context & m_io_ctx;

	//! Конфигурация ACL для этого агента.
	acl_config_t m_acl_config;

	//! Почтовый ящик агента dns_resolver.
	so_5::mbox_t m_dns_mbox;

	//! Почтовый ящик агента authentificator.
	so_5::mbox_t m_auth_mbox;

	//! Уникальное имя, которое должно использоваться этим агентом
	//! для логирования.
	std::string m_name;

	//! Общие для всех ACL параметры.
	common_acl_params_t m_common_acl_params;
};

//
// shutdown_t
//
/*!
 * @brief Специальный сигнал, который указывает, что acl_handler
 * должен завершить свою работу.
 *
 * Получив этот сигнал acl_handler должен закрыть свою точку входа,
 * а затем должен инициировать дерегистрацию своей кооперации.
 */
struct shutdown_t final : public so_5::signal_t {};

//
// introduce_acl_handler
//
/*!
 * @brief Функция для создания и запуска агента acl_handler в
 * указанном SObjectizer Environment с привязкой к указанному диспетчеру.
 *
 * Возвращается mbox, через который можно общаться с агентом acl_handler.
 */
[[nodiscard]]
so_5::mbox_t
introduce_acl_handler(
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

} /* namespace arataga::acl_handler */

