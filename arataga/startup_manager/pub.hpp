/*!
 * @file
 * @brief The public interface of startup_manager-agent.
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
 * @brief Initial parameters for startup_manager-agent.
 */
struct params_t
{
	//! Path for local copy of the config.
	std::filesystem::path m_local_config_path;

	//! Max waiting time for startup of one agent.
	/*!
	 * If an agent doesn't start within that time then the
	 * whole application will be terminated.
	 */
	std::chrono::seconds m_max_stage_startup_time;

	//! Number of IO-threads to be created.
	/*!
	 * If this value is empty then the number of IO-thread
	 * will be detected automatically.
	 */
	std::optional< std::size_t > m_io_threads_count;

	//! IP-address of admin HTTP-entry.
	asio::ip::address m_admin_http_ip;
	//! TCP-port of admin HTTP-entry.
	std::uint16_t m_admin_http_port;
	//! Value of special admin-token to be present in incoming POST requests.
	std::string m_admin_http_token;
};

//
// introduce_startup_manager
//
/*!
 * @brief A factory for creation and launching a new startup_manager-agent.
 */
void
introduce_startup_manager(
	so_5::environment_t & env,
	params_t params );

} /* namespace arataga::startup_manager */

