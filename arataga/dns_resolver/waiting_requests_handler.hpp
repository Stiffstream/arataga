/*!
 * @file
 * @brief Helper class for holding info about actual DNS lookups.
 */

#pragma once

#include <arataga/dns_resolver/pub.hpp>

#include <list>

namespace arataga::dns_resolver
{

/*!
 * @brief Class for holding a list of active DNS lookups.
 *
 * This class is necessary to avoid new lookup if there are some active
 * lookup with the same parameters. So this class is used to deal with
 * duplicates of ResolveRequest.
 *
 * @tparam Key Type of the key for items in the dictionary.
 * @tparam ResolveRequest Type of resolution request.
 * @tparam ResolveResponse Type of resolution response.
 */
template <
	typename Key,
	typename ResolveRequest,
	typename ResolveResponse >
class waiting_requests_handler_t
{
	using completion_token_t =
		typename ResolveResponse::completion_token_t;

	using resolve_result_t =
		typename ResolveResponse::resolve_result_t;

	//! Info about a request.
	struct resolve_request_info_t
	{
		//! Request ID.
		resolve_req_id_t m_req_id;

		//! Required IP-version.
		ip_version_t m_ip_version;

		//! Completion token for the request.
		/*!
		* @note
		* Could be nullptr.
		*/
		completion_token_t m_completion_token;

		//! mbox for the reply.
		so_5::mbox_t m_reply_to;
	};

public:

	/*!
	 * @brief Add a request to wait list.
	 *
	 * @param key Key for the result.
	 * @param req The request to be added.
	 *
	 * @return true If the actual resolution attempt should be performed.
	 * @return false If there already is active request with the same params.
	 */
	[[nodiscard]]
	bool
	add_request( const Key & key, const ResolveRequest & req )
	{
		bool need_resolve = false;

		auto find = m_waiting_requests.find( key );

		if( find == m_waiting_requests.end() )
		{
			resolve_requests_info_list_t requests = {
				resolve_request_info_t {
					req.m_req_id,
					req.m_ip_version,
					req.m_completion_token,
					req.m_reply_to
				}
			};

			m_waiting_requests.emplace(
				key,
				std::move(requests) );

			need_resolve = true;
		}
		else
		{
			find->second.push_back(
				resolve_request_info_t {
					req.m_req_id,
					req.m_ip_version,
					req.m_completion_token,
					req.m_reply_to } );

			need_resolve = false;
		}

		return need_resolve;
	}

	/*!
	 * @brief Handle the result for all requests with the same params.
	 *
	 * All requests receive the same result.
	 *
	 * @param key Key for the request.
	 * @param result The result for resolution attempt.
	 * @param logger Logging function for logging the result.
	 */
	template<typename LoggerFunc>
	void
	handle_waiting_requests(
		const Key & key,
		const resolve_result_t & result,
		LoggerFunc && logger )
	{
		auto find = m_waiting_requests.find( key );

		if( find != m_waiting_requests.end() )
		{
			auto requests = std::move( find->second );
			m_waiting_requests.erase( find );

			for( const auto & req_info : requests )
			{
				//FIXME: what to do if this send throws?
				so_5::send< ResolveResponse >(
					req_info.m_reply_to,
					req_info.m_req_id,
					req_info.m_completion_token,
					result );

				logger( std::move(req_info.m_req_id), result );
			}
		}
	}

	/*!
	 * @brief Handle the result for all requests with the same params.
	 *
	 * All requests receive the same result.
	 *
	 * @param key Key for the request.
	 * @param result The result for resolution attempt.
	 * @param logger Logging function for logging the result.
	 * @param address_extractor Functor for extraction of an IP-address
	 * from the resolution result.
	 */
	template<typename List, typename LoggerFunc, typename Extractor>
	void
	handle_waiting_requests(
		const Key & key,
		const List & results,
		LoggerFunc && logger,
		Extractor && address_extractor )
	{
		auto find = m_waiting_requests.find( key );

		if( find != m_waiting_requests.end() )
		{
			auto requests = std::move( find->second );
			m_waiting_requests.erase( find );

			for( const auto & req_info : requests )
			{
				auto result = get_resolve_result(
					results, req_info.m_ip_version, address_extractor );

				//FIXME: what to do if this send throws?
				so_5::send< ResolveResponse >(
					req_info.m_reply_to,
					req_info.m_req_id,
					req_info.m_completion_token,
					result );

				logger(
					std::move(req_info.m_req_id),
					std::move(result) );
			}
		}
	}

private:
	//! Type of list of waiting requests with the same params.
	using resolve_requests_info_list_t =
		std::list< resolve_request_info_t >;

	/*!
	 * @brief A map of waiting requests.
	 */
	std::map< Key, resolve_requests_info_list_t > m_waiting_requests;
};

} /* namespace arataga::dns_resolver */

