/*!
 * @file
 * @brief Bandwidth limit manager for a single user.
 */

#include <arataga/acl_handler/bandlim_manager.hpp>

#include <fmt/format.h>
#include <fmt/ostream.h>
#include <fmt/chrono.h>

namespace arataga::acl_handler
{

namespace
{

[[nodiscard]]
bandlim_config_t
make_personal_limits_with_respect_to_defaults(
	bandlim_config_t personal,
	bandlim_config_t defaults ) noexcept
{
	const auto selector = []( auto p, auto d ) {
		return bandlim_config_t::is_unlimited( p ) ? d : p;
	};

	return {
		selector(personal.m_in, defaults.m_in),
		selector(personal.m_out, defaults.m_out)
	};
}

[[nodiscard]]
bandlim_manager_t::channel_limits_data_t
make_new_channel_limits_data(
	sequence_number_t sequence_number,
	bandlim_config_t from ) noexcept
{
	bandlim_manager_t::channel_limits_data_t result;
	result.m_directive_values = from;

	result.m_user_end_traffic.m_sequence_number = sequence_number;
	result.m_user_end_traffic.m_quote = from.m_out;

	result.m_target_end_traffic.m_sequence_number = sequence_number;
	result.m_target_end_traffic.m_quote = from.m_in;

	return result;
}

} /* namespace anonymous */

bandlim_manager_t::bandlim_manager_t(
	bandlim_config_t personal_limits,
	bandlim_config_t default_limits )
	:	m_directive_personal_limits{ personal_limits }
	,	m_general_limits{ make_personal_limits_with_respect_to_defaults(
			personal_limits, default_limits )
		}
	,	m_sequence_number{}
	,	m_last_update_at{ std::chrono::steady_clock::now() }
{
	// Set a value from general_limits for all connections (those would appear
	// in the future).
	m_general_traffic = make_new_channel_limits_data(
			m_sequence_number,
			m_general_limits );
}

void
bandlim_manager_t::update_personal_limits(
	bandlim_config_t personal_limits,
	bandlim_config_t default_limits )
{
	m_directive_personal_limits = personal_limits;
	m_general_limits = make_personal_limits_with_respect_to_defaults(
			personal_limits, default_limits );

	// Values for general traffic should be changed too.
	m_general_traffic.m_directive_values = m_general_limits;

	// Do not change other counters. Keep that for the beginning
	// of the next turn.
}

void
bandlim_manager_t::update_default_limits(
	bandlim_config_t default_limits ) noexcept
{
	m_general_limits = make_personal_limits_with_respect_to_defaults(
			m_directive_personal_limits, default_limits );

	// Values for general traffic should be changed too.
	m_general_traffic.m_directive_values = m_general_limits;

	// Do not change other counters. Keep that for the beginning
	// of the next turn.
}

bandlim_manager_t::channel_limits_data_t &
bandlim_manager_t::general_traffic() noexcept
{
	return m_general_traffic;
}

const bandlim_manager_t::channel_limits_data_t &
bandlim_manager_t::general_traffic() const noexcept
{
	return m_general_traffic;
}

bandlim_manager_t::domain_traffic_map_t::iterator
bandlim_manager_t::make_domain_limits(
	domain_name_t domain,
	bandlim_config_t limits )
{
	auto it = m_domain_traffic.find( domain );
	if( it == m_domain_traffic.end() )
	{
		// Have to create a new item.
		// A new limit has to be prepared for it.
		it = m_domain_traffic.emplace(
				std::move(domain),
				domain_traffic_data_t{
						// Count the new connection right now.
						1u,
						make_new_channel_limits_data( m_sequence_number, limits )
				} ).first;
	}
	else
	{
		// Count the new connection for the existing item.
		it->second.m_connection_count += 1u;

		// Limits can have new values, we have take that into account.
		it->second.m_traffic.m_directive_values = limits;
	}

	return it;
}

void
bandlim_manager_t::connection_removed(
	domain_traffic_map_t::iterator it_domain_traffic ) noexcept
{
	auto & data = it_domain_traffic->second;
	data.m_connection_count -= 1u;

	if( !data.m_connection_count )
		m_domain_traffic.erase( it_domain_traffic );
}

void
bandlim_manager_t::update_traffic_counters_for_new_turn() noexcept
{
	using namespace std::chrono;

	// Timer could be not a very precise.
	// We have to take that inaccuracy into the account.
	const auto update_at = steady_clock::now();
	// We belive that difference betwen m_last_update_at and
	// update_at will always fit into double type.
	const auto diff_ms = static_cast<double>(
			duration_cast< milliseconds >( update_at - m_last_update_at ).count()
		);
	const auto multiplier = diff_ms / 1000.0;
	const auto quote_calculator = [multiplier]( auto nat_value ) {
			using result_t = decltype(nat_value);
			const auto r = static_cast<result_t>(
					static_cast<double>(nat_value) * multiplier + 0.5);
			return r;
		};
	m_last_update_at = update_at;

	// Helper function for doing the same actions on
	// channel_limits_data_t::m_user_end_traffic and
	// channel_limits_data_t::m_target_end_traffic.
	const auto dir_handler =
		[seq_num = m_sequence_number, quote_calculator](
			auto & item, auto member, auto new_quote )
		{
			auto & f = (item.*member);
			f.m_sequence_number = seq_num;

			const auto old_quote = quote_calculator( *(f.m_quote) );

			if( f.m_actual <= old_quote )
				f.m_actual = 0u;
			else
			{
				// If we sent more that allowed on the previous turn then
				// count that "surplus" on the current turn.
				// If the value of "surplus" is greater than the quote for
				// the current turn, then the current turn will be skipped.
				f.m_actual -= old_quote;
			}

			// Set a new quote because the config could have been changed.
			f.m_quote = quote_t{new_quote};
			f.m_reserved = 0u;
		};

	const auto processor =
		[dir_handler]( auto & traffic )
		{
			dir_handler(
					traffic,
					&channel_limits_data_t::m_user_end_traffic,
					traffic.m_directive_values.m_out );
			dir_handler(
					traffic,
					&channel_limits_data_t::m_target_end_traffic,
					traffic.m_directive_values.m_in );
		};

	// The turn number should increase.
	m_sequence_number.increment();

	// The general limit should be processed first.
	processor( m_general_traffic );
	// Then the domain limits can be processed.
	for( auto & [k, v] : m_domain_traffic )
		processor( v.m_traffic );
}

} /* namespace arataga::acl_handler */

