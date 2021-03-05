/*!
 * @file
 * @brief Agent for handling arataga's configuration.
 */

#pragma once

#include <arataga/config_processor/pub.hpp>
#include <arataga/authentificator/pub.hpp>
#include <arataga/dns_resolver/pub.hpp>

#include <arataga/config.hpp>

#include <so_5_extra/disp/asio_one_thread/pub.hpp>

namespace arataga::config_processor
{

//
// a_processor_t
//
/*!
 * @brief Agent for handling arataga's configuration.
 */
class a_processor_t : public so_5::agent_t
{
public:
	//! Initializing constructor.
	a_processor_t(
		//! SOEnv and SObjectizer-related parameters for the agent.
		context_t ctx,
		//! The whole app's context.
		application_context_t app_ctx,
		//! Initial parameters for the agent.
		params_t params );

	void
	so_define_agent() override;

	void
	so_evt_start() override;

	// NOTE: this struct is defined in the public part of the class
	// to have a possibility to work with it outside the class.

	//! The description for one running ACL.
	struct running_acl_info_t
	{
		//! Config for that ACL.
		acl_config_t m_config;

		//! Index of IO-thread on that the ACL works.
		std::size_t m_io_thread_index;

		//! ACL's mbox.
		so_5::mbox_t m_mbox;

		running_acl_info_t(
			acl_config_t config,
			std::size_t io_thread_index,
			so_5::mbox_t mbox )
			:	m_config{ std::move(config) }
			,	m_io_thread_index{ io_thread_index }
			,	m_mbox{ std::move(mbox) }
		{}
	};

private:
	//! The description of a IO-thread for serving ACLs.
	struct io_thread_info_t
	{
		//! The dispatcher for acl_handler agents.
		so_5::extra::disp::asio_one_thread::dispatcher_handle_t m_disp;

		//! Coop with authentificator-agent for that IO-thread.
		so_5::coop_handle_t m_auth_coop;
		//! mbox of authentificator-agent for that IO-thread.
		so_5::mbox_t m_auth_mbox;

		//! Coop with dns_resolver-agent for that IO-thread.
		so_5::coop_handle_t m_dns_coop;
		//! mbox of dns_resolver-agent for that IO-thread.
		so_5::mbox_t m_dns_mbox;

		//! How many ACLs work on that IO-thread.
		std::size_t m_running_acl_count{ 0u };
	};

	//! Type of container for descriptions of IO-threads.
	using io_thread_container_t = std::vector< io_thread_info_t >;

	//! Type of container for info about running ACLs.
	using running_acl_container_t = std::vector< running_acl_info_t >;

	//! The context of the whole app.
	const application_context_t m_app_ctx;

	//! Initial parameters for the agent.
	const params_t m_params;

	//! Name of the file with local copy of the config.
	const std::filesystem::path m_local_config_file_name;

	//! The parser for the configuration.
	config_parser_t m_parser;

	//! IO-threads for serving ACLs.
	/*!
	 * This container is initially empty. It will be filled up on the
	 * first successful config update.
	 */
	io_thread_container_t m_io_threads;

	//! Info about running ACLs.
	/*!
	 * @attention
	 * The content is sorted by (port, in_addr).
	 */
	running_acl_container_t m_running_acls;

	//! Counter of configuration updates.
	/*!
	 * It's incremented on every successful config update.
	 *
	 * It's used for making names of children agents.
	 */
	std::uint_fast64_t m_config_update_counter{ 0u };

	//! Handler for a new config.
	void
	on_new_config(
		mhood_t< new_config_t > cmd );

	//! Handler for requesting the list of running ACLs.
	void
	on_get_acl_list(
		mhood_t< get_acl_list_t > cmd );

	//! Handler for test authentification.
	void
	on_debug_auth(
		mhood_t< debug_auth_t > cmd );

	//! Handler for a reply for test authentification.
	void
	on_auth_reply(
		mhood_t< ::arataga::authentificator::auth_reply_t > cmd );

	//! Handler for test domain name resolution.
	void
	on_debug_dns_resolve(
		mhood_t< debug_dns_resolve_t > cmd );

	//! Handler for a reply for test domain name resolution.
	void
	on_resolve_reply(
		mhood_t< ::arataga::dns_resolver::resolve_reply_t > cmd );

	void
	try_load_local_config_first_time();

	//! An attempt to process new config from HTTP-entry.
	/*!
	 * Throws an exception in the case of error.
	 */
	void
	try_handle_new_config_from_post_request(
		std::string_view content );

	//! An attempt to process new config that successfully parsed.
	/*!
	 * This method should be called after successful reading from a file
	 * or after receiving the content from HTTP-entry.
	 */
	void
	try_handle_just_parsed_config(
		config_t config );

	/*!
	 * @attention
	 * It's expected that ACL list in @a config is sorted by (port, in_addr)
	 * and there is no duplicates.
	 *
	 * @note
	 * This method doesn't throw exceptions. If there is an exception
	 * inside it that exception is caught and logged. Then the work of
	 * the whole application will be aborted.
	 */
	void
	accept_new_config( config_t config ) noexcept;

	void
	send_updated_config_messages(
		const config_t & config );

	/*!
	 * @attention
	 * It's expected that ACL list in @a config is sorted by (port, in_addr)
	 * and there is no duplicates.
	 */
	void
	handle_upcoming_acl_list(
		const config_t & config );

	void
	create_dispatchers_if_necessary(
		const config_t & config );

	/*!
	 * @attention
	 * It's expected that ACL list in @a config is sorted by (port, in_addr)
	 * and there is no duplicates.
	 */
	void
	stop_and_remove_outdated_acls(
		const config_t & config );

	/*!
	 * @attention
	 * It's expected that ACL list in @a config is sorted by (port, in_addr)
	 * and there is no duplicates.
	 *
	 * At the end m_running_acls will be sorted by (port, in_addr).
	 */
	void
	launch_new_acls(
		const config_t & config );

	[[nodiscard]]
	std::size_t
	index_of_io_thread_with_lowest_acl_count() const noexcept;

	//! Store the new config into a local file.
	/*!
	 * @note
	 * Exceptions are caught and logged, then suppressed.
	 */
	void
	store_new_config_to_file(
		std::string_view content );

	//! Initiation of test authentification.
	void
	initiate_debug_auth_processing(
		::arataga::admin_http_entry::replier_shptr_t replier,
		::arataga::admin_http_entry::debug_requests::authentificate_t request );

	//! Initiation of test domain name resolution.
	void
	initiate_debug_dns_resolve_processing(
		::arataga::admin_http_entry::replier_shptr_t replier,
		::arataga::admin_http_entry::debug_requests::dns_resolve_t request );
};

} /* namespace arataga::config_processor */

