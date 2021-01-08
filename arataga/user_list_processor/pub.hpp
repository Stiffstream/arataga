/*!
 * @file
 * @brief Публичная часть интерфейса агента user_list_processor.
 */

#pragma once

#include <arataga/application_context.hpp>

#include <arataga/admin_http_entry/pub.hpp>

#include <filesystem>

namespace arataga::user_list_processor
{

//
// params_t
//
/*!
 * @brief Параметры, необходимые агенту для начала его работы.
 */
struct params_t
{
	//! Путь, в котором нужно искать и сохранять локальные копии user-list-а.
	std::filesystem::path m_local_config_path;

	//! mbox, на который нужно отправить подтверждение об успешном старте.
	so_5::mbox_t m_startup_notify_mbox;
};

//
// new_user_list_t
//
/*!
 * @brief Сообщение о получении нового списка пользователей.
 */
struct new_user_list_t final : public so_5::message_t
{
	//! Объект, через который нужно будет сформировать
	//! ответ на попытку обновить список пользователей.
	::arataga::admin_http_entry::replier_shptr_t m_replier;

	//! Содержимое нового списка пользователей.
	const std::string_view m_content;

	new_user_list_t(
		::arataga::admin_http_entry::replier_shptr_t replier,
		std::string_view content )
		:	m_replier{ std::move(replier) }
		,	m_content{ std::move(content) }
	{}
};

//
// introduce_user_list_processor
//
/*!
 * @brief Функция для создания и запуска агента user_list_processor в
 * указанном SObjectizer Environment.
 */
void
introduce_user_list_processor(
	//! SObjectizer Environment, в котором нужно работать.
	so_5::environment_t & env,
	//! Диспетчер, к которому должен быть привязан новый агент.
	so_5::disp_binder_shptr_t disp_binder,
	//! Контекст всего arataga.
	application_context_t app_ctx,
	//! Индивидуальные параметры для нового агента.
	params_t params );

} /* namespace arataga::user_list_processor */

