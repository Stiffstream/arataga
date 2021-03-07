/*!
 * @file
 * @brief Stuff for collecting authentification-related stats.
 */

#include <arataga/stats/auth/pub.hpp>

#include <mutex>
#include <set>

namespace arataga::stats::auth
{

//
// auth_stats_enumerator_t
//
auth_stats_enumerator_t::auth_stats_enumerator_t()
{}

auth_stats_enumerator_t::~auth_stats_enumerator_t()
{}

//
// auth_stats_reference_manager_t
//
auth_stats_reference_manager_t::auth_stats_reference_manager_t()
{}

auth_stats_reference_manager_t::~auth_stats_reference_manager_t()
{}

namespace
{

//
// manager_t
//
class manager_t final : public auth_stats_reference_manager_t
{
	using set_t = std::set< auth_stats_t * >;

	std::mutex m_lock;

	set_t m_objects;

public:
	void
	add( auth_stats_t & stats_object ) override
	{
		std::lock_guard< std::mutex > lock{ m_lock };

		m_objects.insert( &stats_object );
	}

	void
	remove( auth_stats_t & stats_object ) noexcept override
	{
		std::lock_guard< std::mutex > lock{ m_lock };

		m_objects.erase( &stats_object );
	}

	void
	enumerate( auth_stats_enumerator_t & enumerator ) override
	{
		std::lock_guard< std::mutex > lock{ m_lock };

		for( auto * o : m_objects )
		{
			const auto r = enumerator.on_next( *o );
			switch( r )
			{
				case auth_stats_enumerator_t::go_next: /* Nothing to do. */
				break;

				case auth_stats_enumerator_t::stop: return;
			}
		}
	}
};

} /* namespace anonymous */

//
// make_std_auth_stats_reference_manager
//
[[nodiscard]]
std::shared_ptr< auth_stats_reference_manager_t >
make_std_auth_stats_reference_manager()
{
	return std::make_shared< manager_t >();
}

} /* namespace arataga::stats::auth */

