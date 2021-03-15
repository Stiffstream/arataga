/*!
 * @file
 * @brief Bandwidth limit manager for a single user.
 */

#pragma once

#include <arataga/acl_handler/sequence_number.hpp>

#include <arataga/user_list_auth_data.hpp>

#include <map>

namespace arataga::acl_handler
{

//! Alias for type representing a domain name.
using domain_name_t = ::arataga::user_list_auth::domain_name_t;

//
// bandlim_manager_t
//
/*!
 * @brief Bandwidth limit manager for a single user.
 */
class bandlim_manager_t
{
public:
	//
	// Public data type.
	//
	
	//! A special representation of a quote with automatic handling
	//! of `unlimited` value.
	class quote_t
	{
		static constexpr bandlim_config_t::value_t maximum =
				std::numeric_limits< bandlim_config_t::value_t >::max();

		bandlim_config_t::value_t m_raw_value{ maximum };

	public:
		quote_t() = default;
		quote_t( bandlim_config_t::value_t limit ) noexcept
			:	m_raw_value{
					bandlim_config_t::is_unlimited(limit) ? maximum : limit
				}
		{}

		[[nodiscard]]
		auto
		get() const noexcept { return m_raw_value; }

		[[nodiscard]]
		auto
		operator*() const noexcept { return get(); }

		friend std::ostream &
		operator<<( std::ostream & to, const quote_t v )
		{
			if( v.m_raw_value == quote_t::maximum )
				to << "unlimited";
			else
				to << v.m_raw_value;
			return to;
		}
	};

	//! Info about traffic in one direction.
	struct direction_traffic_info_t
	{
		//! The quote for the current turn.
		quote_t m_quote{};
		//! How much bandwidth are reserved on the current turn.
		bandlim_config_t::value_t m_reserved{};
		//! How much bandwidth are consumed on the current turn.
		bandlim_config_t::value_t m_actual{};

		//! The number of the turn for that this information is actual.
		sequence_number_t m_sequence_number{};
	};

	//! Info about limits for one connection.
	struct channel_limits_data_t
	{
		//! Source values from the config.
		bandlim_config_t m_directive_values;

		// The current values.
		direction_traffic_info_t m_user_end_traffic;
		direction_traffic_info_t m_target_end_traffic;
	};

	//! Info about traffic for one specific domain.
	struct domain_traffic_data_t
	{
		//! How many connections are established to that domain.
		std::size_t m_connection_count;

		//! Info about traffic for that domain.
		channel_limits_data_t m_traffic;
	};

	//! Type of dictionary for domains and their bandwidths.
	using domain_traffic_map_t =
			std::map< domain_name_t, domain_traffic_data_t >;

private:
	//
	// Own data for bandwidth limits manager.
	//

	//! The value of the personal limit for the user.
	/*!
	 * This value has to be stored separately for the case when
	 * `default_limits` in the config has been changed.
	 */
	bandlim_config_t m_directive_personal_limits;

	//! The general limit for the user calculated by using
	//! the personal user limit and `default_limits` from the config.
	bandlim_config_t m_general_limits;

	//! Traffic counter for all user's connections.
	channel_limits_data_t m_general_traffic;

	//! Traffic counters for particular domains.
	domain_traffic_map_t m_domain_traffic;

	//! Counter for number of turns.
	sequence_number_t m_sequence_number;

	//! The timepoint of the last recalculation of limits.
	std::chrono::steady_clock::time_point m_last_update_at;

public:
	bandlim_manager_t(
		bandlim_config_t personal_limits,
		bandlim_config_t default_limits );

	// Called every time of successful authentification of the user.
	void
	update_personal_limits(
		bandlim_config_t personal_limits,
		bandlim_config_t default_limits );

	// Called every time of a change of arataga's config.
	void
	update_default_limits(
		bandlim_config_t default_limits ) noexcept;

	[[nodiscard]]
	channel_limits_data_t &
	general_traffic() noexcept;

	[[nodiscard]]
	const channel_limits_data_t &
	general_traffic() const noexcept;

	// Create a new limit for a particular domain.
	//
	// The number of connections for the new limit is set to 1.
	// If there is already such limit then the number of connections
	// is increased by 1.
	[[nodiscard]]
	domain_traffic_map_t::iterator
	make_domain_limits(
		domain_name_t domain,
		bandlim_config_t limits );

	void
	connection_removed(
		domain_traffic_map_t::iterator it_domain_traffic ) noexcept;

	void
	update_traffic_counters_for_new_turn() noexcept;
};

} /* namespace arataga::acl_handler */

