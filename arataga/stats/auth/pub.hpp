/*!
 * @file
 * @brief Stuff for collecting authentification-related stats.
 */

#pragma once

#include <atomic>
#include <cstdint>
#include <memory>

namespace arataga::stats::auth
{

//
// auth_stats_t
//
//! Stats for one authentificator-agent.
struct auth_stats_t
{
	//! Total count of auth operations.
	std::atomic< std::uint64_t > m_auth_total_count{};
	//! Total count of authentifications by IP-address.
	/*!
	 * Including successful and failed authentifications.
	 */
	std::atomic< std::uint64_t > m_auth_by_ip_count{};
	//! Count of failed authentifications by IP-address.
	std::atomic< std::uint64_t > m_failed_auth_by_ip_count{};
	//! Total count of authentifications by login/password.
	/*!
	 * Including successful and failed authentifications.
	 */
	std::atomic< std::uint64_t > m_auth_by_login_count{};
	//! Count of failed authentifications by login/password.
	std::atomic< std::uint64_t > m_failed_auth_by_login_count{};

	//! Count of failed authentifications because of denied port
	//! on the target host.
	std::atomic< std::uint64_t > m_failed_authorization_denied_port{};
};

//
// auth_stats_enumerator_t
//
class auth_stats_enumerator_t
{
public:
	enum class result_t
	{
		go_next,
		stop
	};

	static constexpr auto go_next = result_t::go_next;
	static constexpr auto stop = result_t::stop;

	auth_stats_enumerator_t();
	virtual ~auth_stats_enumerator_t();

	[[nodiscard]]
	virtual result_t
	on_next( const auth_stats_t & stats_object ) = 0;
};

namespace impl
{

//
// enumerator_from_lambda_t
//
template< typename Lambda >
class enumerator_from_lambda_t final : public auth_stats_enumerator_t
{
	Lambda m_lambda;

public:
	enumerator_from_lambda_t( Lambda lambda ) : m_lambda{ std::move(lambda) }
	{}

	[[nodiscard]]
	result_t
	on_next( const auth_stats_t & stats_object ) override
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
// auth_stats_reference_manager_t
//
/*!
 * @brief An interface of holder of references to auth_stats objects.
 *
 * An object of auth_stats_t is owned by authentificator-agent.
 * But a reference to that object should be available to stats_collector.
 * Authentificator-agent passes that reference to
 * auth_stats_reference_manager at the beginning, then removes that
 * references at the end.
 */
class auth_stats_reference_manager_t
{
public:
	auth_stats_reference_manager_t();
	virtual ~auth_stats_reference_manager_t();

	// Objects of that type can't be moved or copied.
	auth_stats_reference_manager_t(
		const auth_stats_reference_manager_t & ) = delete;
	auth_stats_reference_manager_t(
		auth_stats_reference_manager_t && ) = delete;

	//! Add a new auth_stats to the storage.
	virtual void
	add( auth_stats_t & stats_object ) = 0;

	//! Remove auth_stats from the storage.
	virtual void
	remove( auth_stats_t & stats_object ) noexcept = 0;

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
	enumerate( auth_stats_enumerator_t & enumerator ) = 0;
};

//
// auto_reg_t
//
/*!
 * @brief Helper for adding/removing references to auth_stats
 * objects in RAII style.
 */
class auto_reg_t
{
	std::shared_ptr< auth_stats_reference_manager_t > m_manager;
	auth_stats_t & m_stats;

public:
	auto_reg_t(
		std::shared_ptr< auth_stats_reference_manager_t > manager,
		auth_stats_t & stats )
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
// make_std_auth_stats_reference_manager
//
[[nodiscard]]
std::shared_ptr< auth_stats_reference_manager_t >
make_std_auth_stats_reference_manager();

} /* namespace arataga::stats::auth */

