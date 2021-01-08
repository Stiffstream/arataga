/*!
 * @file
 * @brief Публичная часть интерфейса агента startup_manager.
 */

#pragma once

#include <arataga/application_context.hpp>

#include <so_5/all.hpp>

#include <asio/ip/address.hpp>

#include <filesystem>

namespace arataga::startup_manager
{

//
// params_t
//
/*!
 * @brief Конфигурационные параметры для агента startup_manager.
 */
struct params_t
{
	//! Путь, в котором нужно искать и сохранять локальные копии конфига.
	std::filesystem::path m_local_config_path;

	//! Максимальное время ожидания старта одного агента.
	/*!
	 * Если агент за это время стартовать не успел, то работа
	 * всего приложения будет аварийно прервана.
	 */
	std::chrono::seconds m_max_stage_startup_time;

	//! Количество IO-threads, которые должны быть созданы.
	std::optional< std::size_t > m_io_threads_count;

	//! IP-адрес для административного HTTP-входа.
	asio::ip::address m_admin_http_ip;
	//! TCP-порт для административного HTTP-входа.
	std::uint16_t m_admin_http_port;
	//! Значение токена, которое должно присутствовать во входящих запросах.
	std::string m_admin_http_token;
};

//
// introduce_startup_manager
//
/*!
 * @brief Функция для создания и запуска агента startup_manager в
 * указанном SObjectizer Environment.
 */
void
introduce_startup_manager(
	so_5::environment_t & env,
	params_t params );

} /* namespace arataga::startup_manager */


