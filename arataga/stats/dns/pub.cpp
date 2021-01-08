/*!
 * @file
 * @brief Средства для сбора статистики по DNS.
 */

#include <arataga/stats/dns/pub.hpp>

#include <mutex>
#include <set>

namespace arataga::stats::dns
{

//
// dns_stats_enumerator_t
//
dns_stats_enumerator_t::dns_stats_enumerator_t()
{}

dns_stats_enumerator_t::~dns_stats_enumerator_t()
{}

//
// dns_stats_reference_manager_t
//
dns_stats_reference_manager_t::dns_stats_reference_manager_t()
{}

dns_stats_reference_manager_t::~dns_stats_reference_manager_t()
{}

namespace
{

//
// manager_t
//
class manager_t final : public dns_stats_reference_manager_t
{
	using set_t = std::set< dns_stats_t * >;

	std::mutex m_lock;

	set_t m_objects;

public:
	void
	add( dns_stats_t & stats_object ) override
	{
		std::lock_guard< std::mutex > lock{ m_lock };

		m_objects.insert( &stats_object );
	}

	void
	remove( dns_stats_t & stats_object ) noexcept override
	{
		std::lock_guard< std::mutex > lock{ m_lock };

		m_objects.erase( &stats_object );
	}

	void
	enumerate( dns_stats_enumerator_t & enumerator ) override
	{
		std::lock_guard< std::mutex > lock{ m_lock };

		for( auto * o : m_objects )
		{
			const auto r = enumerator.on_next( *o );
			switch( r )
			{
				case dns_stats_enumerator_t::go_next: /* Ничего не делаем. */
				break;

				case dns_stats_enumerator_t::stop: return;
			}
		}
	}
};

} /* namespace anonymous */

//
// make_std_dns_stats_reference_manager
//
[[nodiscard]]
std::shared_ptr< dns_stats_reference_manager_t >
make_std_dns_stats_reference_manager()
{
	return std::make_shared< manager_t >();
}

} /* namespace arataga::stats::dns */

