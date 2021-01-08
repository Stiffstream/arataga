/*!
 * @file
 * @brief Описания нотификаций, которые может рассылать агент
 * user_list_processor.
 */

#pragma once

#include <arataga/config.hpp>

#include <arataga/user_list_auth_data.hpp>

#include <so_5/all.hpp>

namespace arataga::user_list_processor
{

//
// started_t
//
/*!
 * @brief Уведомление о том, что user_list_processor успешно стартовал.
 */
struct started_t final : public so_5::signal_t {};

//
// updated_user_list_t
//
/*!
 * @brief Сообщение о получении нового содержимого списка пользователей.
 *
 * @note
 * Для упрощения реализации первой версии список пользователей в этом
 * сообщении передается по значению.
 */
struct updated_user_list_t final : public so_5::message_t
{
	//! Содержимое списка пользователей.
	::arataga::user_list_auth::auth_data_t m_auth_data;

	updated_user_list_t(
		::arataga::user_list_auth::auth_data_t auth_data )
		:	m_auth_data{ std::move(auth_data) }
	{}
};

} /* namespace arataga::user_list_processor */

