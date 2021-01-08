/*!
 * @file
 * @brief Описание данных, которые содержатся в user-list.
 */

#pragma once

#include <arataga/bandlim_config.hpp>

#include <asio/ip/address_v4.hpp>

#include <cstdint>
#include <filesystem>
#include <map>
#include <string>
#include <string_view>
#include <tuple>
#include <vector>

namespace arataga::user_list_auth {

//
// ipv4_address_t
//
//! Тип IPv4 адреса, который будет использоваться в user_list_auth_data.
using ipv4_address_t = asio::ip::address_v4;

//
// ip_port_t
//
using ip_port_t = std::uint16_t;

//
// user_id_t
//
//! Тип идентификатора для пользователя.
using user_id_t = std::uint_least32_t;

//
// auth_by_ip_key_t
//
/*!
 * @brief Параметры аутентификации пользователя по IP-адресу.
 */
struct auth_by_ip_key_t {
	//! IP-адрес прокси.
	/*!
	 * Это in_addr для ACL.
	 */
	ipv4_address_t m_proxy_in_addr;
	//! TCP-порт прокси.
	ip_port_t m_proxy_port;
	//! IP-адрес пользователя.
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
 * @brief Параметры аутентификации пользователя по login/password.
 */
struct auth_by_login_key_t
{
	//! IP-адрес прокси.
	/*!
	 * Это in_addr для ACL.
	 */
	ipv4_address_t m_proxy_in_addr;
	//! TCP-порт прокси.
	ip_port_t m_proxy_port;
	//! login пользователя.
	std::string m_username;
	//! Пароль пользователя.
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
 * @brief Дополнительные данные для клиента.
 */
struct user_data_t
{
	//! Ограничения на пропускную способность для клиента.
	bandlim_config_t m_bandlims;

	//! Идентификатор дополнительных лимитов для пользователя.
	std::uint32_t m_site_limits_id;

	//! Идентификатор пользователя.
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
 * @brief Тип ключа в словаре индивидуальных лимитов.
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
 * @brief Специальное представление доменного имени.
 *
 * Имя преобразуется в нижний регистр.
 * Лидирующие '.' удаляются.
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
 * @brief Вспомогательная функция, которая позволяет определить
 * является ли один домен поддоменом другого домена.
 *
 * @return true если @a full_name является поддоменом @a domain_name.
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
 * @brief Описание одного персонального лимита.
 *
 * Один персональный лимит может содержать перечень доменов с
 * ограничениями пропускной способности по каждому из них.
 */
struct site_limits_data_t
{
	//! Описание лимита для одного домена.
	struct one_limit_t
	{
		//! Имя домена.
		domain_name_t m_domain;
		//! Лимит для домена.
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

	//! Тип контейнера для хранения индивидуальных лимитов по доменам.
	using limits_container_t = std::vector<one_limit_t>;

	//! Список доменов с их индивидуальными лимитами.
	limits_container_t m_limits;

	//! Найти огpаничение для конкретного домена.
	/*!
	 * Возвращается пустой optional, если для домена ограничение
	 * задано не было.
	 *
	 * Если в m_limits есть сразу несколько доменов, для которых
	 * @a host является поддоменом, то выбирается домен с наиболее
	 * длинным именем. Так, если в m_limits указаны "v2.api.vk.com",
	 * "api.vk.com" и "vk.com", а в @a host задан "v1.api.vk.com",
	 * то будет выбран лимит для "api.vk.com".
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
 * @brief Тип хранилища информации для аутентификации клиентов.
 */
struct auth_data_t
{
	//! Тип словаря для аутентификации клиента по IP.
	using by_ip_map_t =
			std::map<auth_by_ip_key_t, user_data_t>;

	//! Тип словаря для аутентификации клиента по паре login/password.
	using by_login_map_t =
			std::map<auth_by_login_key_t, user_data_t>;

	//! Тип словаря персональных лимитов.
	using site_limits_map_t =
			std::map<site_limits_key_t, site_limits_data_t>;

	//! Информация для аутентификации клиентов по IP.
	by_ip_map_t m_by_ip;

	//! Информация для аутентификации клиентов по паре login/password.
	by_login_map_t m_by_login;

	//! Словарь персональных лимитов.
	site_limits_map_t m_site_limits;
};

//
// parse_auth_data
//
/*!
 * @brief Разбор загруженного в память содержимого списка пользователей.
 *
 * @throw std::runtime_error При возникновении ошибок парсинга.
 */
[[nodiscard]]
auth_data_t
parse_auth_data(
	std::string_view user_list_content );

//
// load_auth_data
//
/*!
 * @brief Загрузка информации об аутентификации из указанного файла.
 *
 * @throw std::runtime_error При возникновении ошибок загрузки.
 */
[[nodiscard]]
auth_data_t
load_auth_data(
	const std::filesystem::path & file_name);

} /* namespace arataga::user_list_auth */

