#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN 
#include <doctest/doctest.h>

#include <arataga/user_list_auth_data.hpp>

[[nodiscard]]
auto
ip_from_int( asio::ip::address_v4::uint_type uint_v )
{
	return asio::ip::address_v4{ uint_v };
}

TEST_CASE("is_subdomain_of") {
	using namespace arataga::user_list_auth;

	REQUIRE( is_subdomain_of(
			domain_name_t{ "api.vk.com" }, domain_name_t{ "vk.com" } ) );
	REQUIRE( is_subdomain_of(
			domain_name_t{ "v2.api.vk.com" }, domain_name_t{ "vk.com" } ) );
	REQUIRE( is_subdomain_of(
			domain_name_t{ "v2.api.vk.com" }, domain_name_t{ "api.vk.com" } ) );
	REQUIRE( is_subdomain_of(
			domain_name_t{ "v2.api.vk.com" }, domain_name_t{ ".api.vk.com" } ) );
	REQUIRE( !is_subdomain_of(
			domain_name_t{ "v2.api.vk.com" }, domain_name_t{ "2.api.vk.com" } ) );
	REQUIRE( is_subdomain_of(
			domain_name_t{ ".vk.com" }, domain_name_t{ "vk.com" } ) );
	REQUIRE( !is_subdomain_of(
			domain_name_t{ "vvk.com" }, domain_name_t{ "vk.com" } ) );
	REQUIRE( !is_subdomain_of(
			domain_name_t{ "k.com" }, domain_name_t{ "vk.com" } ) );
}

TEST_CASE("try_find_limits_for") {
	using namespace arataga::user_list_auth;
	using arataga::bandlim_config_t;

	site_limits_data_t data{ site_limits_data_t::limits_container_t{ 
		{ "vk.com"_dn, bandlim_config_t{ 1024u, 1024u } },
		{ "facebook.com"_dn, bandlim_config_t{ 1024u, 1024u } },
		{ "v2.api.vk.com"_dn, bandlim_config_t{ 2024u, 2024u } },
		{ "api.vk.com"_dn, bandlim_config_t{ 3024u, 3024u } },
		{ "avito.ru"_dn, bandlim_config_t{ 1024u, 1024u } },
		{ "avito.st"_dn, bandlim_config_t{ 1024u, 1024u } },
		{ "css.static.vk.com"_dn, bandlim_config_t{ 4024u, 4024u } },
		{ "tv.mail.ru"_dn, bandlim_config_t{ 1024u, 1024u } },
		{ "static.vk.com"_dn, bandlim_config_t{ 5024u, 5024u } },
		{ "mp4.tv.mail.ru"_dn, bandlim_config_t{ 6024u, 6024u } }
	} };

	{
		const auto r = data.try_find_limits_for( "vk.com"_dn );
		REQUIRE( r );
	}

	{
		const auto r = data.try_find_limits_for( "k.com"_dn );
		REQUIRE( !r );
	}

	{
		const auto r = data.try_find_limits_for( "content.vk.com"_dn );
		REQUIRE( r );
		REQUIRE( "vk.com"_dn == r->m_domain );
	}

	{
		const auto r = data.try_find_limits_for( "v1.api.vk.com"_dn );
		REQUIRE( r );
		REQUIRE( "api.vk.com"_dn == r->m_domain );
	}

	{
		const auto r = data.try_find_limits_for( "check.v2.api.vk.com"_dn );
		REQUIRE( r );
		REQUIRE( "v2.api.vk.com"_dn == r->m_domain );
	}

	{
		const auto r = data.try_find_limits_for( "www.facebook.com"_dn );
		REQUIRE( r );
		REQUIRE( "facebook.com"_dn == r->m_domain );
	}

	{
		const auto r = data.try_find_limits_for( "css.static.vk.com"_dn );
		REQUIRE( r );
		REQUIRE( "css.static.vk.com"_dn == r->m_domain );
	}

	{
		const auto r = data.try_find_limits_for( "img.static.vk.com"_dn );
		REQUIRE( r );
		REQUIRE( "static.vk.com"_dn == r->m_domain );
	}

	{
		const auto r = data.try_find_limits_for( "images.mail.ru"_dn );
		REQUIRE( !r );
	}

	{
		const auto r = data.try_find_limits_for( "vp8.tv.mail.ru"_dn );
		REQUIRE( r );
		REQUIRE( "tv.mail.ru"_dn == r->m_domain );
	}
}

TEST_CASE("no config file") {
	using namespace arataga::user_list_auth;

	auth_data_t cnt;
	REQUIRE_THROWS_AS(
			cnt = load_auth_data(
				"tests/local_user_list_data/cfgs/no-such-config"),
			const std::exception &);
}

TEST_CASE("empty config file") {
	using namespace arataga::user_list_auth;

	auth_data_t cnt;
	REQUIRE_NOTHROW(
			cnt = load_auth_data(
				"tests/local_user_list_data/cfgs/empty-config"));

	REQUIRE(cnt.m_by_ip.empty());
	REQUIRE(cnt.m_by_login.empty());
	REQUIRE(cnt.m_site_limits.empty());
}

TEST_CASE("normal-config-1") {
	using namespace arataga::user_list_auth;
	using arataga::bandlim_config_t;

	auth_data_t cnt;
	REQUIRE_NOTHROW(
			cnt = load_auth_data(
				"tests/local_user_list_data/cfgs/normal-config-1"));

	{
		auth_data_t::by_ip_map_t expected{
				{
					{ip_from_int(760812377u), 3002u, ip_from_int(908385451u)},
					{0u, 0u, 8u, 91442u}
				},
				{
					{ip_from_int(760812377u), 3003u, ip_from_int(908385451u)},
					{0u, 0u, 8u, 91442u}
				},
				{
					{ip_from_int(760812377u), 3004u, ip_from_int(1604889428u)},
					{0u, 0u, 8u, 90989u}
				},
				{
					{ip_from_int(760812377u), 3005u, ip_from_int(1604889428u)},
					{0u, 0u, 8u, 90989u}
				}
		};

		REQUIRE(cnt.m_by_ip == expected);
	}

	{
		auth_data_t::by_login_map_t expected{
				{
					{ip_from_int(760812377u), 3002u, "xXXXXX", "jGGGGGGGGG"},
					{0u, 0u, 8u, 58508u}
				},
				{
					{ip_from_int(760812377u), 3003u, "xXXXXX", "jGGGGGGGGG"},
					{0u, 0u, 8u, 58508u}
				},
				{
					{ip_from_int(760812377u), 3002u, "xAAAAA", "yUQQQQQQQQ"},
					{0u, 0u, 8u, 91442u}
				},
				{
					{ip_from_int(760812377u), 3003u, "xAAAAA", "yUQQQQQQQQ"},
					{0u, 0u, 8u, 91442u}
				},
		};

		REQUIRE(cnt.m_by_login == expected);
	}

	{
		auth_data_t::site_limits_map_t expected{
			{
				{3u},
				site_limits_data_t{
					site_limits_data_t::limits_container_t{
						{domain_name_t{"facebook.com"}, bandlim_config_t{5u*1024u, 5000u}},
						{domain_name_t{"yandex.ru"}, bandlim_config_t{5000u, 5000u}},
						{domain_name_t{"yandex6.net"}, bandlim_config_t{5000u, 5000u}},
						{domain_name_t{"mail.ru"}, bandlim_config_t{70000u, 70000u}},
					}
				}
			},
			{
				{6u},
				site_limits_data_t{
					site_limits_data_t::limits_container_t{
						{domain_name_t{"facebook.com"}, bandlim_config_t{5242880u, 5242880u}},
						{domain_name_t{"fbcdn.net"}, bandlim_config_t{5242880u, 5242880u}},
						{domain_name_t{"avito.ru"}, bandlim_config_t{5242880u, 5242880u}},
						{domain_name_t{"avito.st"}, bandlim_config_t{5242880u, 5242880u}},
						{domain_name_t{"vk.com"}, bandlim_config_t{5242880u, 5242880u}},
						{domain_name_t{"userapi.com"}, bandlim_config_t{5242880u, 5242880u}},
						{domain_name_t{"instagram.com"}, bandlim_config_t{5242880u, 5242880u}}
					}
				}
			},
			{
				{7u},
				site_limits_data_t{
					site_limits_data_t::limits_container_t{
						{domain_name_t{"facebook.com"}, bandlim_config_t{3145728u, 3145728u}},
						{domain_name_t{"fbcdn.net"}, bandlim_config_t{3145728u, 3145728u}},
						{domain_name_t{"avito.st"}, bandlim_config_t{3145728u, 3145728u}},
						{domain_name_t{"avito.ru"}, bandlim_config_t{3145728u, 3145728u}},
						{domain_name_t{"vk.com"}, bandlim_config_t{3145728u, 3145728u}},
						{domain_name_t{"userapi.com"}, bandlim_config_t{3145728u, 3145728u}},
						{domain_name_t{"instagram.com"}, bandlim_config_t{3145728u, 3145728u}}
					}
				}
			},
			{
				{8u},
				site_limits_data_t{
					site_limits_data_t::limits_container_t{
						{domain_name_t{"facebook.com"}, bandlim_config_t{524288u, 524288u}},
						{domain_name_t{"fbcdn.net"}, bandlim_config_t{5242880u, 524288u}},
						{domain_name_t{"avito.ru"}, bandlim_config_t{5242880u, 5242880u}},
						{domain_name_t{"avito.st"}, bandlim_config_t{5242880u, 5242880u}},
						{domain_name_t{"vk.com"}, bandlim_config_t{5242880u, 5242880u}},
						{domain_name_t{"userapi.com"}, bandlim_config_t{5242880u, 5242880u}},
						{domain_name_t{"instagram.com"}, bandlim_config_t{524288u, 524288u}}
					}
				}
			}
		};
		REQUIRE(expected == cnt.m_site_limits);
	}
}

