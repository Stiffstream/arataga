/*!
 * @file
 * @brief Средства для сбора статистики по подключениям.
 */

#include <arataga/stats/connections/pub.hpp>

#include <mutex>
#include <set>

namespace arataga::stats::connections
{

//
// acl_stats_enumerator_t
//
acl_stats_enumerator_t::acl_stats_enumerator_t()
{}

acl_stats_enumerator_t::~acl_stats_enumerator_t()
{}

//
// acl_stats_reference_manager_t
//
acl_stats_reference_manager_t::acl_stats_reference_manager_t()
{}

acl_stats_reference_manager_t::~acl_stats_reference_manager_t()
{}

namespace
{

//
// manager_t
//
class manager_t final : public acl_stats_reference_manager_t
{
	using set_t = std::set< acl_stats_t * >;

	std::mutex m_lock;

	set_t m_objects;

public:
	void
	add( acl_stats_t & stats_object ) override
	{
		std::lock_guard< std::mutex > lock{ m_lock };

		m_objects.insert( &stats_object );
	}

	void
	remove( acl_stats_t & stats_object ) noexcept override
	{
		std::lock_guard< std::mutex > lock{ m_lock };

		m_objects.erase( &stats_object );
	}

	void
	enumerate( acl_stats_enumerator_t & enumerator ) override
	{
		std::lock_guard< std::mutex > lock{ m_lock };

		for( auto * o : m_objects )
		{
			const auto r = enumerator.on_next( *o );
			switch( r )
			{
				case acl_stats_enumerator_t::go_next: /* Ничего не делаем. */
				break;

				case acl_stats_enumerator_t::stop: return;
			}
		}
	}
};

} /* namespace anonymous */

//
// make_std_acl_stats_reference_manager
//
[[nodiscard]]
std::shared_ptr< acl_stats_reference_manager_t >
make_std_acl_stats_reference_manager()
{
	return std::make_shared< manager_t >();
}

} /* namespace arataga::stats::connections */

