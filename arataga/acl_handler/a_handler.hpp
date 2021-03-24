/*!
 * @file
 * @brief Agent acl_handler.
 */

#pragma once

#include <arataga/acl_handler/pub.hpp>

#include <arataga/acl_handler/connection_handler_ifaces.hpp>

#include <arataga/acl_handler/bandlim_manager.hpp>

#include <arataga/stats/connections/pub.hpp>

#include <arataga/config_processor/notifications.hpp>

#include <arataga/dns_resolver/pub.hpp>

#include <arataga/authentificator/pub.hpp>

#include <arataga/one_second_timer.hpp>

#include <asio/ip/tcp.hpp>

namespace arataga::acl_handler
{

//
// actual_config_t
//
/*!
 * @brief Actual implementation of config interface.
 */
class actual_config_t final : public config_t
{
	const acl_config_t & m_acl_config;
	const common_acl_params_t & m_common_acl_params;

public:
	actual_config_t(
		const acl_config_t & acl_config,
		const common_acl_params_t & common_acl_params );

	[[nodiscard]]
	acl_protocol_t
	acl_protocol() const noexcept override;

	[[nodiscard]]
	const asio::ip::address &
	out_addr() const noexcept override;

	[[nodiscard]]
	std::size_t
	io_chunk_size() const noexcept override;

	[[nodiscard]]
	std::size_t
	io_chunk_count() const noexcept override;

	[[nodiscard]]
	std::chrono::milliseconds
	protocol_detection_timeout() const noexcept override;

	[[nodiscard]]
	std::chrono::milliseconds
	socks_handshake_phase_timeout() const noexcept override;

	[[nodiscard]]
	std::chrono::milliseconds
	dns_resolving_timeout() const noexcept override;

	[[nodiscard]]
	std::chrono::milliseconds
	authentification_timeout() const noexcept override;

	[[nodiscard]]
	std::chrono::milliseconds
	connect_target_timeout() const noexcept override;

	[[nodiscard]]
	std::chrono::milliseconds
	socks_bind_timeout() const noexcept override;

	[[nodiscard]]
	std::chrono::milliseconds
	idle_connection_timeout() const noexcept override;

	[[nodiscard]]
	std::chrono::milliseconds
	http_headers_complete_timeout() const noexcept override;

	[[nodiscard]]
	std::chrono::milliseconds
	http_negative_response_timeout() const noexcept override;

	[[nodiscard]]
	const http_message_value_limits_t &
	http_message_limits() const noexcept override;
};

//
// authentificated_user_info_t
//
//! Info about successfully authentificated client.
struct authentificated_user_info_t
{
	//! The number of current connection from this user.
	std::size_t m_connection_count{};

	//! Limits for this user.
	bandlim_manager_t m_bandlims;
};

//
// authentificated_user_map_t
//
//! Map of successfully authentificated users.
using authentificated_user_map_t = std::map<
		::arataga::user_list_auth::user_id_t,
		authentificated_user_info_t
	>;

//
// a_handler_t
//
/*!
 * @brief An agent that serves ACL.
 *
 * Some notices about replace_connection_handler() and remove_connection():
 *
 * A replacement of connection-handler is performed
 * inside replace_connection_handler() that is called by
 * the current connection-handler synchronously. There can be a case
 * when replace_connection_handler() calls on_start() for a new
 * connection-handler that new connection-handler can make another
 * nested call to replace_connection_handler() (to set another
 * connection-handler) or to remove_connection() (to destroy the
 * connection if it can be served).
 *
 * Additional care should also be taken during the call to on_timer()
 * for connection-handlers, because a backward call to remove_connection()
 * can be made from inside on_timer. In that case a_handler should delete
 * a object for that on_timer() isn't completed yet.
 */
class a_handler_t final
	:	public so_5::agent_t
	,	public handler_context_t
{
public:
	//! Initializing constructor.
	a_handler_t(
		context_t ctx,
		application_context_t app_ctx,
		params_t params );
	~a_handler_t() override;

	void
	so_define_agent() override;

	void
	so_evt_start() override;

	void
	so_evt_finish() override;

	void
	replace_connection_handler(
		delete_protector_t,
		connection_id_t id,
		connection_handler_shptr_t handler ) override;

	void
	remove_connection_handler(
		delete_protector_t,
		connection_id_t id,
		remove_reason_t reason ) noexcept override;

	void
	log_message_for_connection(
		connection_id_t id,
		::arataga::logging::processed_log_level_t level,
		std::string_view message ) override;

	[[nodiscard]]
	const config_t &
	config() const noexcept override;

	void
	async_resolve_hostname(
		connection_id_t connection_id,
		const std::string & hostname,
		dns_resolving::hostname_result_handler_t result_handler ) override;

	void
	async_authentificate(
		connection_id_t connection_id,
		authentification::request_params_t request,
		authentification::result_handler_t result_handler ) override;

	void
	stats_inc_connection_count(
		connection_type_t connection_type ) override;

private:
	//! Signal for next attempt to make an entry point.
	struct try_create_entry_point_t final : public so_5::signal_t {};

	//! Signal for next call to async_accept.
	struct accept_next_t final : public so_5::signal_t {};

	//! Notification about the completion of the current call to accept.
	struct current_accept_completed_t final : public so_5::signal_t {};

	//! Signal to return to accepting new connections.
	struct enable_accepting_connections_t final : public so_5::signal_t {};

	//! The description for a single connection from a user.
	/*!
	 * It could be possible to store just connection_handler_shptr_t
	 * inside connection_map_t. But the presence of connection_info_t
	 * allow us:
	 *
	 * - to call connection_handler_t::release() when connection
	 *   info has to be deleted regardless of the reason of the
	 *   deletion;
	 * - to extend the info in the future if it'll be necessary.
	 */
	class connection_info_t
	{
		//! The current handler for that connection.
		connection_handler_shptr_t m_handler;

		// Copy is disabled for that type.
		connection_info_t( const connection_info_t & ) = delete;
		connection_info_t &
		operator=( const connection_info_t & ) = delete;

		// Safe call of handler's release for the case when
		// the handler is not needed anymore.
		static void
		release_handler( const connection_handler_shptr_t & handler_ptr )
		{
			if( handler_ptr )
				handler_ptr->release();
		}

	public:
		// There are only move construtor/operator.
		connection_info_t( connection_info_t && ) = default;
		connection_info_t &
		operator=( connection_info_t && ) = default;

		connection_info_t(
			connection_handler_shptr_t handler )
			:	m_handler{ std::move(handler) }
		{}

		~connection_info_t()
		{
			// The call to release() should be done to complete all
			// active IO-operations.
			release_handler( m_handler );
		}

		[[nodiscard]]
		const connection_handler_shptr_t &
		handler() const noexcept
		{
			return m_handler;
		}

		// Replacement of the old handler to a new one.
		// The release() method is automatically called for the old handler.
		// The old handler is returned.
		connection_handler_shptr_t
		replace( connection_handler_shptr_t new_handler )
		{
			using std::swap;
			swap( m_handler, new_handler );

			release_handler( new_handler );

			return new_handler;
		}
	};

	//! Type of connections map.
	using connection_map_t = std::map<
			handler_context_t::connection_id_t,
			connection_info_t >;

	//! The top-level state for the agent.
	/*!
	 * Events that have to be handled regardless of the current state
	 * are subscribed for this top-level state.
	 */
	state_t st_basic{ this, "basic" };

	//! The state in that entry point isn't created yet.
	state_t st_entry_not_created{
		initial_substate_of{ st_basic }, "entry_not_created" };

	//! The state in that entry point is already created and the agent
	//! can accept new connections.
	state_t st_entry_created{
		substate_of{ st_basic }, "entry_created" };

	//! The state in that entry point actively accepts new connections.
	state_t st_accepting{
		initial_substate_of{ st_entry_created }, "accepting" };

	//! The state in that entry point is already created but the agent
	//! can't accept new connections because there are too many
	//! accepted connections.
	state_t st_too_many_connections{
		substate_of{ st_entry_created }, "too_many_connections" };

	//! The state in that the agent waits the completion of its work.
	state_t st_shutting_down{ this, "shutting_down" };

	//! The context of the whole application.
	const application_context_t m_app_ctx;

	//! Initial parameters for the agent.
	const params_t m_params;

	//! Individual stats for this ACL.
	::arataga::stats::connections::acl_stats_t m_acl_stats;
	::arataga::stats::connections::auto_reg_t m_acl_stats_reg;

	//! The current values of common ACL params.
	common_acl_params_t m_current_common_acl_params;

	//! Configuration object for connection-handlers.
	actual_config_t m_connection_handlers_config;

	//! The server socket for accepting new connections.
	asio::ip::tcp::acceptor m_acceptor;

	//! ID counter for new connections.
	handler_context_t::connection_id_t m_connection_id_counter{};

	//! The map of current connections.
	connection_map_t m_connections;

	//! The map of successfully authentificated users.
	authentificated_user_map_t m_authentificated_users;

	void
	on_shutdown( mhood_t< shutdown_t > );

	void
	on_try_create_entry_point( mhood_t< try_create_entry_point_t > );

	void
	on_enter_st_entry_created() noexcept;

	void
	on_one_second_timer( mhood_t< one_second_timer_t > );

	void
	on_enter_st_accepting() noexcept;

	void
	on_accept_next_when_accepting( mhood_t< accept_next_t > );

	void
	on_accept_completion_when_accepting(
		mhood_t< current_accept_completed_t > );

	void
	on_dns_result(
		mhood_t< ::arataga::dns_resolver::resolve_reply_t > cmd );

	void
	on_auth_result(
		mhood_t< ::arataga::authentificator::auth_reply_t > cmd );

	void
	on_updated_config(
		mhood_t< ::arataga::config_processor::updated_common_acl_params_t > cmd );

	//! Get access to the description of a connection by ID.
	/*!
	 * This description should exists. Otherwise an exception will be thrown.
	 */
	[[nodiscard]]
	connection_info_t &
	connection_info_that_must_be_present(
		connection_id_t id );

	//! Try to find the description of a connection by ID.
	/*!
	 * The description can be non-existent. The nullptr is returned
	 * in that case.
	 */
	[[nodiscard]]
	connection_info_t *
	try_find_connection_info(
		connection_id_t id );

	//! Acception of a new connection.
	void
	accept_new_connection(
		asio::ip::tcp::socket connection ) noexcept;

	//! Update the info about default limits.
	/*!
	 * This method is called when the config is changed.
	 */
	void
	update_default_bandlims_on_confg_change() noexcept;

	//! Recalculation of traffic quotes.
	/*!
	 * This method is called at the beginning of a new turn.
	 */
	void
	update_traffic_limit_quotes_on_new_turn();

	//! Handling of successful authentification.
	/*!
	 * The info about this client should go into m_authentificated_users.
	 *
	 * An instance of traffic_limiter for a new connection from this client
	 * is returned.
	 */
	traffic_limiter_unique_ptr_t
	user_authentificated(
		const ::arataga::authentificator::successful_auth_t & info );

	//! Helper method for make an ID.
	/*!
	 * This ID will simplify the searching connection-related info
	 * in log files.
	 */
	::arataga::utils::acl_req_id_t
	make_long_id( connection_id_t id ) const noexcept;

	//! Attempt to go into accepting state if it is possible.
	void
	try_switch_to_accepting_if_necessary_and_possible();

	//! Update the stats for removed connection-handlers.
	void
	update_remove_handle_stats( remove_reason_t reason ) noexcept;
};

} /* namespace arataga::acl_handler */

