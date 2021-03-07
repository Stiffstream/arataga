/*!
 * @file
 * @brief Stuff for collecting DNS-related stats.
 */

#pragma once

#include <atomic>
#include <cstdint>
#include <memory>

namespace arataga::stats::dns
{

//
// dns_stats_t
//
//! Stats for a single dns_resolver-agent.
struct dns_stats_t
{
	//! Cache hits counter.
	std::atomic< std::uint64_t > m_dns_cache_hits{};
	//! Counter for successful lookups.
	std::atomic< std::uint64_t > m_dns_successful_lookups{};
	//! Counter for failed lookups.
	std::atomic< std::uint64_t > m_dns_failed_lookups{};
};

//
// dns_stats_enumerator_t
//
class dns_stats_enumerator_t
{
public:
	enum class result_t
	{
		go_next,
		stop
	};

	static constexpr auto go_next = result_t::go_next;
	static constexpr auto stop = result_t::stop;

	dns_stats_enumerator_t();
	virtual ~dns_stats_enumerator_t();

	[[nodiscard]]
	virtual result_t
	on_next( const dns_stats_t & stats_object ) = 0;
};

namespace impl
{

//
// enumerator_from_lambda_t
//
template< typename Lambda >
class enumerator_from_lambda_t final : public dns_stats_enumerator_t
{
	Lambda m_lambda;

public:
	enumerator_from_lambda_t( Lambda lambda ) : m_lambda{ std::move(lambda) }
	{}

	[[nodiscard]]
	result_t
	on_next( const dns_stats_t & stats_object ) override
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
// dns_stats_reference_manager_t
//
/*!
 * @brief An interface of holder of references to dns_stats objects.
 *
 * An object of auth_stats_t is owned by dns_resolver-agent.
 * But a reference to that object should be available to stats_collector.
 * Dns_resolver-agent passes that reference to
 * dns_stats_reference_manager at the beginning, then removes that
 * references at the end.
 */
class dns_stats_reference_manager_t
{
public:
	dns_stats_reference_manager_t();
	virtual ~dns_stats_reference_manager_t();

	// Objects of that type can't be moved or copied.
	dns_stats_reference_manager_t(
		const dns_stats_reference_manager_t & ) = delete;
	dns_stats_reference_manager_t(
		dns_stats_reference_manager_t && ) = delete;

	//! Add a new dns_stats to the storage.
	virtual void
	add( dns_stats_t & stats_object ) = 0;

	//! Remove dns_stats from the storage.
	virtual void
	remove( dns_stats_t & stats_object ) noexcept = 0;

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
	enumerate( dns_stats_enumerator_t & enumerator ) = 0;
};

//
// auto_reg_t
//
/*!
 * @brief Helper for adding/removing references to dns_stats
 * objects in RAII style.
 */
class auto_reg_t
{
	std::shared_ptr< dns_stats_reference_manager_t > m_manager;
	dns_stats_t & m_stats;

public:
	auto_reg_t(
		std::shared_ptr< dns_stats_reference_manager_t > manager,
		dns_stats_t & stats )
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
// make_std_dns_stats_reference_manager
//
[[nodiscard]]
std::shared_ptr< dns_stats_reference_manager_t >
make_std_dns_stats_reference_manager();

} /* namespace arataga::stats::auth */

