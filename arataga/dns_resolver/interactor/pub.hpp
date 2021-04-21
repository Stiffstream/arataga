/*!
 * @file
 * @brief Public interface of nameserver_interactor agent.
 * @since v.0.4.0
 */

#pragma once

#include <arataga/application_context.hpp>
#include <arataga/ip_version.hpp>

#include <asio/ip/address.hpp>
#include <asio/io_context.hpp>

#include <so_5/all.hpp>

#include <functional>
#include <variant>
#include <vector>

namespace arataga::dns_resolver::interactor
{

//
// successful_lookup_t
//
//! Description of successful DNS-lookup result.
struct successful_lookup_t
{
	using address_container_t = std::vector< asio::ip::address >;

	//! The result of domain name resolution.
	address_container_t m_addresses;
};

//
// failed_lookup_t
//
//! Description of failed DNS-lookup result.
struct failed_lookup_t
{
	std::string m_description;
};

//
// lookup_result_t
//
//! Type for result of DNS-lookup operation.
using lookup_result_t = std::variant< successful_lookup_t, failed_lookup_t >;

//
// result_processor_t
//
//! Type of processor of a DNS-lookup result.
using result_processor_t = std::function< void(lookup_result_t) >;

//
// lookup_request_t
//
//! Message with DNS-lookup request.
struct lookup_request_t final : public so_5::message_t
{
	//FIXME: it should have type domain_name_t. std::string is used
	// just for quick prototyping.
	//! Name to be resolved.
	std::string m_domain_name;

	//! Version of desired IP address (IPv4 or IPv6).
	ip_version_t m_ip_version;

	//! Mbox for the result.
	so_5::mbox_t m_reply_to;

	//! Handler of the lookup result.
	result_processor_t m_result_processor;

	lookup_request_t(
		std::string domain_name,
		ip_version_t ip_version,
		so_5::mbox_t reply_to,
		result_processor_t result_processor )
		:	m_domain_name{ std::move(domain_name) }
		,	m_ip_version{ ip_version }
		,	m_reply_to{ std::move(reply_to) }
		,	m_result_processor{ std::move(result_processor) }
	{}
};

//
// lookup_response_t
//
//! Message with the result of DNS-lookup.
struct lookup_response_t final : public so_5::message_t
{
	//! The result.
	lookup_result_t m_result;

	//! Handler for the result.
	/*!
	 * This value is copied from the source lookup_request_t message.
	 */
	result_processor_t m_result_processor;

	lookup_response_t(
		lookup_result_t result,
		result_processor_t result_processor )
		:	m_result{ std::move(result) }
		,	m_result_processor{ std::move(result_processor) }
	{}
};

//
// params_t
//
/*!
 * @brief Initial parameters for nameserver_interactor-agent.
 */
struct params_t
{
	//! Asio's io_context to be used by nameserver_interactor.
	/*!
	 * @note
	 * This reference is expected to be valid for the whole lifetime
	 * of nameserver_interactor-agent.
	 */
	asio::io_context & m_io_ctx;

	//! Unique name of that agent.
	/*!
	 * Intended to be used for logging.
	 */
	std::string m_name;
};

//
// add_interactor_to_coop
//
[[nodiscard]]
so_5::mbox_t
add_interactor_to_coop(
	//! Coop to that a new agent should be added.
	so_5::coop_t & coop,
	//! The context of the whole application.
	application_context_t app_ctx,
	//! Parameters for a new interactor agent.
	params_t params );

} /* namespace arataga::dns_resolver::interactor */

