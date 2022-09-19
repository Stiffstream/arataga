/*!
 * @file
 * @brief Description of data in a user-list.
 */

#pragma once

#include <arataga/bandlim_config.hpp>

#include <asio/ip/address_v4.hpp>

#include <cstdint>
#include <filesystem>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <tuple>
#include <vector>

namespace arataga::user_list_auth {

//
// ipv4_address_t
//
//! Type of IPv4 address that will be used in user_list_auth_data.
using ipv4_address_t = asio::ip::address_v4;

//
// ip_port_t
//
using ip_port_t = std::uint16_t;

//
// user_id_t
//
//! Type of user ID.
using user_id_t = std::uint_least32_t;

//
// auth_by_ip_key_t
//
/*!
 * @brief Parameters for authentification by IP-address.
 */
struct auth_by_ip_key_t {
	//! Proxy ID-address.
	/*!
	 * It's in_addr for ACL.
	 */
	ipv4_address_t m_proxy_in_addr;
	//! Proxy TCP-port.
	ip_port_t m_proxy_port;
	//! User IP-address.
	ipv4_address_t m_user_ip;
};

namespace details
{

[[nodiscard]]
inline auto
tie( const auth_by_ip_key_t & v ) noexcept
{
	return std::tie(v.m_proxy_in_addr, v.m_proxy_port, v.m_user_ip);
}

} /* namespace details */

[[nodiscard]]
inline bool
operator<(
	const auth_by_ip_key_t & a,
	const auth_by_ip_key_t & b) noexcept
{
	return details::tie(a) < details::tie(b);
}

[[nodiscard]]
inline bool
operator==(
	const auth_by_ip_key_t & a,
	const auth_by_ip_key_t & b) noexcept
{
	return details::tie(a) == details::tie(b);
}

//
// auth_by_login_key_t
//
/*!
 * @brief Parameters for authentification by login/password.
 */
struct auth_by_login_key_t
{
	//! Proxy IP-address.
	/*!
	 * It's in_addr for ACL.
	 */
	ipv4_address_t m_proxy_in_addr;
	//! Proxy TCP-port.
	ip_port_t m_proxy_port;
	//! User's login.
	std::string m_username;
	//! User's password.
	std::string m_password;
};

namespace details
{

[[nodiscard]]
inline auto
tie(const auth_by_login_key_t & v) noexcept
{
	return std::tie(
			v.m_proxy_in_addr,
			v.m_proxy_port,
			v.m_username,
			v.m_password);
}

} /* namespace details */

[[nodiscard]]
inline bool
operator<(
	const auth_by_login_key_t & a,
	const auth_by_login_key_t & b) noexcept
{
	return details::tie(a) < details::tie(b);
}

[[nodiscard]]
inline bool
operator==(
	const auth_by_login_key_t & a,
	const auth_by_login_key_t & b) noexcept
{
	return details::tie(a) == details::tie(b);
}

//
// user_data_t
//
/*!
 * @brief Additional data for a user.
 */
struct user_data_t
{
	//! Main band-limits for a user.
	bandlim_config_t m_bandlims;

	//! ID of additional band-limits for a user.
	std::uint32_t m_site_limits_id;

	//! User's ID.
	user_id_t m_user_id;
};

[[nodiscard]]
inline bool
operator==(
	const user_data_t & a,
	const user_data_t & b) noexcept
{
	const auto t = [](const user_data_t & v) {
		return std::tie(
				v.m_bandlims.m_in, v.m_bandlims.m_out,
				v.m_site_limits_id, v.m_user_id);
	};
	return t(a) == t(b);
}

//
// site_limits_key_t
//
/*!
 * @brief Type of the key in a dictionary of personal limits.
 */
struct site_limits_key_t
{
	std::uint32_t m_site_limits_id;
};

[[nodiscard]]
inline bool
operator<(
	const site_limits_key_t & a,
	const site_limits_key_t & b) noexcept
{
	return a.m_site_limits_id < b.m_site_limits_id;
}

[[nodiscard]]
inline bool
operator==(
	const site_limits_key_t & a,
	const site_limits_key_t & b) noexcept
{
	return a.m_site_limits_id == b.m_site_limits_id;
}

//
// domain_name_t
//
/*!
 * @brief Special representation of domain name.
 *
 * Name is stored in lower case.
 * All leading '.' are removed.
 */
class domain_name_t
{
	std::string m_value;

public:
	domain_name_t();

	domain_name_t( std::string value );

	[[nodiscard]]
	const std::string &
	value() const noexcept;
};

[[nodiscard]]
inline domain_name_t
operator "" _dn( const char * arg )
{
	return { std::string(arg) };
}

[[nodiscard]]
inline domain_name_t
operator "" _dn( const char * arg, std::size_t size )
{
	return { std::string{ arg, size } };
}

[[nodiscard]]
bool
operator==(const domain_name_t & a, const domain_name_t & b) noexcept;

[[nodiscard]]
bool
operator<(const domain_name_t & a, const domain_name_t & b) noexcept;

std::ostream &
operator<<(std::ostream & to, const domain_name_t & name);

//
// is_subdomain_of
//
/*!
 * @brief A helper function that allows to detect is one domain
 * is a subdomain of another domain.
 *
 * @return true if @a full_name is a subdomain of @a domain_name.
 */
[[nodiscard]]
bool
is_subdomain_of(
	const domain_name_t & full_name,
	const domain_name_t & domain_name) noexcept;

//
// site_limits_data_t
//
/*!
 * @brief Description of one personal limit.
 *
 * One personal limit can contain a list of domain with
 * individual limits for each of them.
 */
struct site_limits_data_t
{
	//! Description of a limit for one domain.
	struct one_limit_t
	{
		//! Domain name.
		domain_name_t m_domain;
		//! The limit for the domain.
		bandlim_config_t m_bandlims;

		[[nodiscard]]
		bool
		operator==(const one_limit_t & o) const noexcept
		{
			const auto t = [](const one_limit_t & v) {
				return std::tie(v.m_domain, v.m_bandlims.m_in, v.m_bandlims.m_out);
			};
			return t(*this) == t(o);
		}
	};

	//! Type of container for holding domains' limits.
	using limits_container_t = std::vector<one_limit_t>;

	//! List of domains with individual limits.
	limits_container_t m_limits;

	//! Find the limit for a particular domain.
	/*!
	 * Returns an empty `optional` if there is no limit for the domain. 
	 *
	 * If there are several domain for those @a host is a subdomain,
	 * then a domain with longest name is selected. For example,
	 * if m_limits contains "v2.api.vk.com", "api.vk.com" and
	 * "vk.com", and @a host contains "v1.api.vk.com" then
	 * the limit for "api.vk.com" will be selected.
	 */
	[[nodiscard]]
	std::optional< one_limit_t >
	try_find_limits_for( domain_name_t host ) const;
};

[[nodiscard]]
inline bool
operator==(
	const site_limits_data_t & a,
	const site_limits_data_t & b) noexcept
{
	return a.m_limits == b.m_limits;
}

//
// auth_data_t
//
/*!
 * @brief Type of storage for authentification info.
 */
struct auth_data_t
{
	//! Type of a dictionary for authentification by IP.
	using by_ip_map_t =
			std::map<auth_by_ip_key_t, user_data_t>;

	//! Type of a dictionary for authentification by login/password.
	using by_login_map_t =
			std::map<auth_by_login_key_t, user_data_t>;

	//! Type of a dictionary for personal limits.
	using site_limits_map_t =
			std::map<site_limits_key_t, site_limits_data_t>;

	//! Info for authentification by IP.
	by_ip_map_t m_by_ip;

	//! Info for authentification by login/password.
	by_login_map_t m_by_login;

	//! The dictionary of personal limits.
	site_limits_map_t m_site_limits;
};

//
// parse_auth_data
//
/*!
 * @brief Parsing of already loaded content of user-list file.
 *
 * @throw std::runtime_error In the case of parsing error.
 */
[[nodiscard]]
auth_data_t
parse_auth_data(
	std::string_view user_list_content );

//
// load_auth_data
//
/*!
 * @brief Load and parse content of user-list file.
 *
 * @throw std::runtime_error In the case of loading/parsing errors.
 */
[[nodiscard]]
auth_data_t
load_auth_data(
	const std::filesystem::path & file_name);

} /* namespace arataga::user_list_auth */

