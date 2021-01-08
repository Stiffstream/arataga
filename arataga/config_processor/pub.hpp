/*!
 * @file
 * @brief Публичная часть интерфейса агента config_processor.
 */

#pragma once

#include <arataga/application_context.hpp>

#include <arataga/admin_http_entry/pub.hpp>

#include <filesystem>

namespace arataga::config_processor
{

//
// params_t
//
/*!
 * @brief Параметры, необходимые агенту для начала его работы.
 */
struct params_t
{
	//! Путь, в котором нужно искать и сохранять локальные копии конфига.
	std::filesystem::path m_local_config_path;

	//! mbox, на который нужно отправить подтверждение об успешном старте.
	so_5::mbox_t m_startup_notify_mbox;

	//! Количество io_threads, которые необходимо создавать.
	std::optional< std::size_t > m_io_threads_count;
};

//
// new_config_t
//
/*!
 * @brief Сообщение о получении нового конфига.
 */
struct new_config_t final : public so_5::message_t
{
	//! Объект, через который нужно будет сформировать
	//! ответ на попытку обновить конфиг.
	::arataga::admin_http_entry::replier_shptr_t m_replier;

	//! Содержимое нового конфига.
	const std::string_view m_content;

	new_config_t(
		::arataga::admin_http_entry::replier_shptr_t replier,
		std::string_view content )
		:	m_replier{ std::move(replier) }
		,	m_content{ std::move(content) }
	{}
};

//
// get_acl_list_t
//
/*!
 * @brief Сообщение о необходимости предоставить информацию
 * о запущенных ACL.
 */
struct get_acl_list_t final : public so_5::message_t
{
	//! Объект, через который нужно будет сформировать ответ.
	::arataga::admin_http_entry::replier_shptr_t m_replier;

	get_acl_list_t(
		::arataga::admin_http_entry::replier_shptr_t replier )
		:	m_replier{ std::move(replier) }
	{}
};

//
// debug_auth
//
/*!
 * @brief Сообщение о необходимости провести тестовую аутентификацию.
 */
struct debug_auth_t final : public so_5::message_t
{
	//! Объект, через который нужно будет сформировать ответ.
	::arataga::admin_http_entry::replier_shptr_t m_replier;

	//! Параметры аутентификации.
	::arataga::admin_http_entry::debug_requests::authentificate_t m_request;

	debug_auth_t(
		::arataga::admin_http_entry::replier_shptr_t replier,
		::arataga::admin_http_entry::debug_requests::authentificate_t
				request )
		:	m_replier{ std::move(replier) }
		,	m_request{ std::move(request) }
	{}
};

//
// debug_dns_resolve_t
//
/*!
 * @brief Сообщение о необходимости провести тестовое разрешение доменного имени.
 */
struct debug_dns_resolve_t final : public so_5::message_t
{
	//! Объект, через который нужно будет сформировать ответ.
	::arataga::admin_http_entry::replier_shptr_t m_replier;

	//! Параметры разрешения доменного имени.
	::arataga::admin_http_entry::debug_requests::dns_resolve_t m_request;

	debug_dns_resolve_t(
		::arataga::admin_http_entry::replier_shptr_t replier,
		::arataga::admin_http_entry::debug_requests::dns_resolve_t
				request )
		:	m_replier{ std::move(replier) }
		,	m_request{ std::move(request) }
	{}
};

//
// introduce_config_processor
//
/*!
 * @brief Функция для создания и запуска агента config_processor в
 * указанном SObjectizer Environment.
 */
void
introduce_config_processor(
	//! SObjectizer Environment, в котором нужно работать.
	so_5::environment_t & env,
	//! Диспетчер, к которому должен быть привязан новый агент.
	so_5::disp_binder_shptr_t disp_binder,
	//! Контекст всего arataga.
	application_context_t app_ctx,
	//! Индивидуальные параметры для нового агента.
	params_t params );

} /* namespace arataga::config_processor */

