/*!
 * @file
 * @brief Описание контекста, в котором будут работать сущности arataga.
 */

#pragma once

#include <so_5/all.hpp>

#include <arataga/stats/auth/pub.hpp>
#include <arataga/stats/connections/pub.hpp>
#include <arataga/stats/dns/pub.hpp>

namespace arataga
{

//
// application_context_t
//
/*!
 * @brief Структура, которая содержит информацию, необходимую для
 * взаимодействия сущностей внутри arataga.
 */
struct application_context_t
{
	//! mbox для взаимодействия с config_processor-ом.
	so_5::mbox_t m_config_processor_mbox;

	//! mbox для взаимодействия с user_list_processor-ом.
	so_5::mbox_t m_user_list_processor_mbox;
	
	//! mbox для распространения информации об обновлениях конфигурации.
	so_5::mbox_t m_config_updates_mbox;

	//! mbox для сбора статистики.
	so_5::mbox_t m_stats_collector_mbox;

	//! mbox для глобальных сообщений от таймера.
	so_5::mbox_t m_global_timer_mbox;

	//! Хранилище статистики по ACL.
	std::shared_ptr<
			stats::connections::acl_stats_reference_manager_t > m_acl_stats_manager;

	//! Хранилище статистики по аутентификациям.
	std::shared_ptr<
			stats::auth::auth_stats_reference_manager_t > m_auth_stats_manager;

	//! Хранилище статистики по DNS.
	std::shared_ptr<
			stats::dns::dns_stats_reference_manager_t > m_dns_stats_manager;
};

} /* namespace arataga */

