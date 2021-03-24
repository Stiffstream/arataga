/*!
 * @file
 * @brief Notifications sent by user_list_processor-agent.
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
 * @brief Notification about successful start of user_list_processor-agent.
 */
struct started_t final : public so_5::signal_t {};

//
// updated_user_list_t
//
/*!
 * @brief Notification about accepted new user-list.
 *
 * @note
 * For simplicity new user-list is sent by a value.
 */
struct updated_user_list_t final : public so_5::message_t
{
	//! New user-list.
	::arataga::user_list_auth::auth_data_t m_auth_data;

	updated_user_list_t(
		::arataga::user_list_auth::auth_data_t auth_data )
		:	m_auth_data{ std::move(auth_data) }
	{}
};

} /* namespace arataga::user_list_processor */

