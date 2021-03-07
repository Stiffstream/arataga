/*!
 * @file
 * @brief Stuff for collecting connections-related stats.
 */

#pragma once

#include <atomic>
#include <cstdint>
#include <memory>

namespace arataga::stats::connections
{

//
// acl_stats_t
//
//! Stats for a single ACL.
struct acl_stats_t
{
	//! Total number of connections.
	std::atomic< std::uint64_t > m_total_connections{};
	//! Number of connections by HTTP protocol.
	std::atomic< std::uint64_t > m_http_connections{};
	//! Number of connections by SOCKS5 protocol.
	std::atomic< std::uint64_t > m_socks5_connections{};

	/*!
	 * @name Counters for various reasons of connection_handlers deletion.
	 * @{
	 */
	std::atomic< std::uint64_t > m_remove_reason_normal_completion{};
	std::atomic< std::uint64_t > m_remove_reason_io_error{};
	std::atomic< std::uint64_t > m_remove_reason_current_operation_timed_out{};
	std::atomic< std::uint64_t > m_remove_reason_unsupported_protocol{};
	std::atomic< std::uint64_t > m_remove_reason_protocol_error{};
	std::atomic< std::uint64_t > m_remove_reason_unexpected_error{};
	std::atomic< std::uint64_t > m_remove_reason_no_activity_for_too_long{};
	std::atomic< std::uint64_t > m_remove_reason_current_operation_canceled{};
	std::atomic< std::uint64_t > m_remove_reason_unhandled_exception{};
	std::atomic< std::uint64_t > m_remove_reason_ip_version_mismatch{};
	std::atomic< std::uint64_t > m_remove_reason_access_denied{};
	std::atomic< std::uint64_t > m_remove_reason_unresolved_target{};
	std::atomic< std::uint64_t > m_remove_reason_target_end_broken{};
	std::atomic< std::uint64_t > m_remove_reason_user_end_broken{};
	std::atomic< std::uint64_t > m_remove_reason_early_http_response{};
	std::atomic< std::uint64_t > m_remove_reason_user_end_closed_by_client{};
	std::atomic< std::uint64_t > m_remove_reason_http_no_incoming_request{};
	/*!
	 * @}
	 */
};

//
// acl_stats_enumerator_t
//
class acl_stats_enumerator_t
{
public:
	enum class result_t
	{
		go_next,
		stop
	};

	static constexpr auto go_next = result_t::go_next;
	static constexpr auto stop = result_t::stop;

	acl_stats_enumerator_t();
	virtual ~acl_stats_enumerator_t();

	[[nodiscard]]
	virtual result_t
	on_next( const acl_stats_t & stats_object ) = 0;
};

namespace impl
{

//
// enumerator_from_lambda_t
//
template< typename Lambda >
class enumerator_from_lambda_t final : public acl_stats_enumerator_t
{
	Lambda m_lambda;

public:
	enumerator_from_lambda_t( Lambda lambda ) : m_lambda{ std::move(lambda) }
	{}

	[[nodiscard]]
	result_t
	on_next( const acl_stats_t & stats_object ) override
	{
		return m_lambda( stats_object );
	}
};

} /* namespace impl */

//
// lambda_as_enumerator
//
template< typename Lambda >
[[nodiscard]]
auto
lambda_as_enumerator( Lambda && lambda )
{
	using actual_lambda_type = std::decay_t<Lambda>;
	return impl::enumerator_from_lambda_t<actual_lambda_type>{
			std::forward<Lambda>(lambda)
		};
}

//
// acl_stats_reference_manager_t
//
/*!
 * @brief An interface of holder of references to acl_stats objects.
 *
 * An object of acl_stats is owned by ACL-agent. But a reference to that
 * object should be available to stats_collector. ACL-agent passes that
 * reference to acl_stats_reference_manager at the beginning, then removes that
 * references at the end.
 */
class acl_stats_reference_manager_t
{
public:
	acl_stats_reference_manager_t();
	virtual ~acl_stats_reference_manager_t();

	// Objects of that type can't be copied or moved.
	acl_stats_reference_manager_t(
		const acl_stats_reference_manager_t & ) = delete;
	acl_stats_reference_manager_t(
		acl_stats_reference_manager_t && ) = delete;

	//! Add a new acl_stats to the storage.
	virtual void
	add( acl_stats_t & stats_object ) = 0;

	//! Remove acl_stats from the storage.
	virtual void
	remove( acl_stats_t & stats_object ) noexcept = 0;

	//! Enumerate all objects from the storage.
	/*!
	 * For the safety purposes the storage will be blocked to the end
	 * of the enumeration. It means that add() and remove() will block
	 * the caller until enumerate() completes.
	 *
	 * It also means that calls to add()/remove() from inside enumerate()
	 * are prohibited.
	 */
	virtual void
	enumerate( acl_stats_enumerator_t & enumerator ) = 0;
};

//
// auto_reg_t
//
/*!
 * @brief Helper for adding/removing references to acl_stats
 * objects in RAII style.
 */
class auto_reg_t
{
	std::shared_ptr< acl_stats_reference_manager_t > m_manager;
	acl_stats_t & m_stats;

public:
	auto_reg_t(
		std::shared_ptr< acl_stats_reference_manager_t > manager,
		acl_stats_t & stats )
		:	m_manager{ std::move(manager) }
		,	m_stats{ stats }
	{
		m_manager->add( m_stats );
	}
	~auto_reg_t()
	{
		m_manager->remove( m_stats );
	}

	// Objects of that class can't be copied or moved.
	auto_reg_t( const auto_reg_t & ) = delete;
	auto_reg_t( auto_reg_t && ) = delete;
};

//
// make_std_acl_stats_reference_manager
//
[[nodiscard]]
std::shared_ptr< acl_stats_reference_manager_t >
make_std_acl_stats_reference_manager();

} /* namespace arataga::stats::connections */

