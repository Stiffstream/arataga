/*!
 * @file
 * @brief Helper function for searching an address of appropriate type
 * in a list of addresses.
 */

#pragma once

#include <arataga/dns_resolver/pub.hpp>
#include <arataga/exception.hpp>

namespace arataga::dns_resolver
{

/*!
 * @brief Search an IP-address of appropriate version in a list of addresses.
 *
 * @note
 * Return the first IP-address with the appropriate version.
 *
 * @note
 * If IPv6 address is required and not found then the first IPv4 address
 * will be converted into IPv6 address.
 *
 * @return asio::ip::address The resulting address with required version.
 * @return std::nullopt If there is no appropriate address and no
 * possibility to make a conversion between IPv4 and IPv6 versions.
 */
template <typename List, typename Extractor>
std::optional<asio::ip::address>
resolve_address_from_list(
	//! List of addresses to search within.
	const List & list,
	//! The required IP version.
	ip_version_t ip_version,
	//! Functor (lambda-function) for extraction an IP address from a list item.
	Extractor && address_extractor )
{
	for( const auto & element: list )
	{
		const auto & address = address_extractor(element);
		if( address.is_v4() && ip_version == ip_version_t::ip_v4 )
		{
			return address;
		}

		if( address.is_v6() && ip_version == ip_version_t::ip_v6 )
		{
			return address;
		}
	}
	/*
		If we are here then there is no an address with required version.
		Let's try to convert the first IPv4 address.
	*/
	if( ip_version == ip_version_t::ip_v6 )
	{
		return asio::ip::make_address_v6(
			asio::ip::v4_mapped,
			address_extractor( *(list.begin()) ).to_v4() );
	}
	else
	{
		// Assume that there is no way to convert IPv6 to IPv4.
		// Because of that return nullopt.
		return std::nullopt;
	}
}

/*!
 * @brief Get the resolution result for the specified IP version.
 */
template <typename List, typename Extractor>
forward::resolve_result_t
get_resolve_result(
	//! List of addresses to search within.
	const List & list,
	//! The required IP version.
	ip_version_t ip_version,
	//! Functor (lambda-function) for extraction an IP address from a list item.
	Extractor && address_extractor )
{
	forward::resolve_result_t result;

	auto address = resolve_address_from_list(
		list,
		std::move(ip_version),
		std::move(address_extractor) );

	if(address)
		result = forward::successful_resolve_t
			{
				*address
			};
	else
		result = forward::failed_resolve_t
			{
				"address with required IP version was not found"
			};

	return result;
}

} /* namespace arataga::dns_resolver */

