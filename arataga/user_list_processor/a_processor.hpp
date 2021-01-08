/*!
 * @file
 * @brief Агент для обработки списка пользователей.
 */

#pragma once

#include <arataga/user_list_processor/pub.hpp>

#include <arataga/config.hpp>
#include <arataga/user_list_auth_data.hpp>

namespace arataga::user_list_processor
{

//
// a_processor_t
//
/*!
 * @brief Агент для работы со списком пользователей.
 */
class a_processor_t : public so_5::agent_t
{
public:
	//! Основной конструктор.
	a_processor_t(
		//! SOEnv и параметры для агента.
		context_t ctx,
		//! Контекст всего arataga.
		application_context_t app_ctx,
		//! Индивидуальные параметры для этого агента.
		params_t params );

	void
	so_define_agent() override;

	void
	so_evt_start() override;

private:
	//! Контекст всего arataga.
	const application_context_t m_app_ctx;

	//! Индивидуальные параметры для агента.
	const params_t m_params;

	//! Имя файла с локальной копией списка пользователей.
	const std::filesystem::path m_local_user_list_file_name;

	//! Реакция на получение нового списка пользователей от HTTP-входа.
	void
	on_new_user_list(
		mhood_t< new_user_list_t > cmd );

	//! Попытка загрузить список из локального файла при старте агента.
	void
	try_load_local_user_list_first_time();

	//! Попытка обработать новый список пользователей, полученный
	//! из административного HTTP-входа.
	void
	try_handle_new_user_list_from_post_request(
		std::string_view content );

	//! Пытается загрузить содержимое локального файла.
	/*!
	 * Обрабатывает исключения, которые при этом возникают.
	 *
	 * Если при загрузке возникла ошибка, то возвращается пустой optional.
	 */
	std::optional< ::arataga::user_list_auth::auth_data_t >
	try_load_local_user_list_content();

	//! Отсылка обновленного списка пользователей.
	/*!
	 * Этот метод помечен как noexcept потому, что он перехватывает
	 * все исключения, логирует их и аварийно завершает работу приложения,
	 * поскольку если обновленный список пользователей отослать не
	 * удалось, то продолжать работу нет смысла. И не важно, что это
	 * за ошибка. Что-то явно идет не так.
	 */
	void
	distribute_updated_user_list(
		::arataga::user_list_auth::auth_data_t auth_data ) noexcept;

	//! Сохранение нового списка пользователей в локальный файл.
	/*!
	 * @note
	 * Возникшие при выполнении этой операции исключения логируются,
	 * но не выпускаются наружу.
	 */
	void
	store_new_user_list_to_file(
		std::string_view content );
};

} /* namespace arataga::user_list_processor */

