#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN 
#include <doctest/doctest.h>

#include <arataga/config.hpp>

using namespace std::string_view_literals;
using namespace std::chrono_literals;

TEST_CASE("minimalistic config") {
	using namespace arataga;

	config_parser_t parser;

	{
		const auto what = 
R"(
# This is a comment
				
	# This is an another comment

log_level debug
nserver 1.1.1.1
				)"sv;

		config_t cfg;
		REQUIRE_NOTHROW( cfg = parser.parse( what ) );

		REQUIRE( spdlog::level::debug == cfg.m_log_level );
		REQUIRE( 100u == cfg.m_common_acl_params.m_maxconn );
		REQUIRE( 8u*1024u == cfg.m_common_acl_params.m_io_chunk_size );
		REQUIRE( 4u == cfg.m_common_acl_params.m_io_chunk_count );

		REQUIRE( bandlim_config_t::is_unlimited(
				cfg.m_common_acl_params.m_client_bandlim.m_in ) );
		REQUIRE( bandlim_config_t::is_unlimited(
				cfg.m_common_acl_params.m_client_bandlim.m_out ) );

		REQUIRE( 30s == cfg.m_dns_cache_cleanup_period );

		REQUIRE( cfg.m_denied_ports.m_cases.empty() );

		REQUIRE( 750ms == cfg.m_common_acl_params.m_failed_auth_reply_timeout );

		REQUIRE( 8u*1024u == cfg.m_common_acl_params.m_http_message_limits
				.m_max_request_target_length );
		REQUIRE( 2u*1024u == cfg.m_common_acl_params.m_http_message_limits
				.m_max_field_name_length );
		REQUIRE( 10u*1024u == cfg.m_common_acl_params.m_http_message_limits
				.m_max_field_value_length );
		REQUIRE( 80u*1024u == cfg.m_common_acl_params.m_http_message_limits
				.m_max_total_headers_size );
		REQUIRE( 1u*1024u == cfg.m_common_acl_params.m_http_message_limits
				.m_max_status_line_length );

		REQUIRE( cfg.m_acls.empty() );
	}
}

TEST_CASE("nserver") {
	using namespace arataga;

	config_parser_t parser;

	{
		const auto what = 
R"(
nserver 1.1.1.1
)"sv;

		config_t cfg;
		REQUIRE_NOTHROW( cfg = parser.parse( what ) );

		REQUIRE( cfg.m_nameserver_ips ==
			config_t::nameserver_ip_container_t{
				asio::ip::make_address("1.1.1.1")
			} );
	}

	{
		const auto what = 
R"(
nserver 1.1.1.1, 1.0.0.1, 8.8.8.8
)"sv;

		config_t cfg;
		REQUIRE_NOTHROW( cfg = parser.parse( what ) );

		REQUIRE( cfg.m_nameserver_ips ==
			config_t::nameserver_ip_container_t{
				asio::ip::make_address("1.1.1.1")
				, asio::ip::make_address("1.0.0.1")
				, asio::ip::make_address("8.8.8.8")
			} );
	}

	{
		const auto what = 
R"(
nserver 1.1.1.1, 1.0.0.1, 8.8.8.8
nserver 8.8.4.4
nserver 9.9.9.9, 
nserver 149.112.112.112
)"sv;

		config_t cfg;
		REQUIRE_NOTHROW( cfg = parser.parse( what ) );

		REQUIRE( cfg.m_nameserver_ips ==
			config_t::nameserver_ip_container_t{
				asio::ip::make_address("1.1.1.1")
				, asio::ip::make_address("1.0.0.1")
				, asio::ip::make_address("8.8.8.8")
				, asio::ip::make_address("8.8.4.4")
				, asio::ip::make_address("9.9.9.9")
				, asio::ip::make_address("149.112.112.112")
			} );
	}
}

TEST_CASE("log_levels") {
	using namespace arataga;

	config_parser_t parser;

	{
		const auto what = 
R"(
log_level debug
nserver 1.1.1.1
)"sv;

		config_t cfg;
		REQUIRE_NOTHROW( cfg = parser.parse( what ) );

		REQUIRE( spdlog::level::debug == cfg.m_log_level );
	}

	{
		const auto what = 
R"(
log_level off
nserver 1.1.1.1
)"sv;

		config_t cfg;
		REQUIRE_NOTHROW( cfg = parser.parse( what ) );

		REQUIRE( spdlog::level::off == cfg.m_log_level );
	}

	{
		const auto what = 
R"(
log_level 
nserver 1.1.1.1
)"sv;

		config_t cfg;
		REQUIRE_THROWS_AS(
				cfg = parser.parse( what ),
				arataga::config_parser_t::parser_exception_t );
	}

	{
		const auto what = 
R"(
log_level 123
nserver 1.1.1.1
)"sv;

		config_t cfg;
		REQUIRE_THROWS_AS(
				cfg = parser.parse( what ),
				arataga::config_parser_t::parser_exception_t );
	}
}

TEST_CASE("dns_cache_cleanup_period") {
	using namespace arataga;

	config_parser_t parser;

	{
		const auto what = 
R"(
dns_cache_cleanup_period 3
nserver 1.1.1.1
)"sv;

		config_t cfg;
		REQUIRE_NOTHROW( cfg = parser.parse( what ) );

		REQUIRE( 3s == cfg.m_dns_cache_cleanup_period );
	}

	{
		const auto what = 
R"(
dns_cache_cleanup_period 5s
nserver 1.1.1.1
)"sv;

		config_t cfg;
		REQUIRE_NOTHROW( cfg = parser.parse( what ) );

		REQUIRE( 5s == cfg.m_dns_cache_cleanup_period );
	}

	{
		const auto what = 
R"(
dns_cache_cleanup_period 250ms
nserver 1.1.1.1
)"sv;

		config_t cfg;
		REQUIRE_NOTHROW( cfg = parser.parse( what ) );

		REQUIRE( 250ms == cfg.m_dns_cache_cleanup_period );
	}

	{
		const auto what = 
R"(
dns_cache_cleanup_period 0
nserver 1.1.1.1
)"sv;

		config_t cfg;
		REQUIRE_THROWS_AS(
				cfg = parser.parse( what ),
				arataga::config_parser_t::parser_exception_t );
	}

	{
		const auto what = 
R"(
dns_cache_cleanup_period 2min
nserver 1.1.1.1
)"sv;

		config_t cfg;
		REQUIRE_NOTHROW( cfg = parser.parse( what ) );

		REQUIRE( 2min == cfg.m_dns_cache_cleanup_period );
	}
}

TEST_CASE("acl.max.conn") {
	using namespace arataga;

	config_parser_t parser;

	{
		const auto what = 
R"(
acl.max.conn 256
nserver 1.1.1.1
)"sv;

		config_t cfg;
		REQUIRE_NOTHROW( cfg = parser.parse( what ) );

		REQUIRE( 256u == cfg.m_common_acl_params.m_maxconn );
	}

	{
		const auto what = 
R"(
acl.max.conn off
nserver 1.1.1.1
)"sv;

		config_t cfg;
		REQUIRE_THROWS_AS(
				cfg = parser.parse( what ),
				arataga::config_parser_t::parser_exception_t );
	}

	{
		const auto what = 
R"(
acl.max.conn 0
nserver 1.1.1.1
)"sv;

		config_t cfg;
		REQUIRE_THROWS_AS(
				cfg = parser.parse( what ),
				arataga::config_parser_t::parser_exception_t );
	}

	{
		const auto what = 
R"(
acl.max.conn -120
nserver 1.1.1.1
)"sv;

		config_t cfg;
		REQUIRE_THROWS_AS(
				cfg = parser.parse( what ),
				arataga::config_parser_t::parser_exception_t );
	}
}

TEST_CASE("io_chunk_size") {
	using namespace arataga;

	config_parser_t parser;

	{
		const auto what = 
R"(
acl.io.chunk_size 128
nserver 1.1.1.1
)"sv;

		config_t cfg;
		REQUIRE_NOTHROW( cfg = parser.parse( what ) );

		REQUIRE( 128 == cfg.m_common_acl_params.m_io_chunk_size );
	}

	{
		const auto what = 
R"(
acl.io.chunk_size 256b
nserver 1.1.1.1
)"sv;

		config_t cfg;
		REQUIRE_NOTHROW( cfg = parser.parse( what ) );

		REQUIRE( 256 == cfg.m_common_acl_params.m_io_chunk_size );
	}

	{
		const auto what = 
R"(
acl.io.chunk_size 2kib
nserver 1.1.1.1
)"sv;

		config_t cfg;
		REQUIRE_NOTHROW( cfg = parser.parse( what ) );

		REQUIRE( 2u*1024u == cfg.m_common_acl_params.m_io_chunk_size );
	}

	{
		const auto what = 
R"(
acl.io.chunk_size 5mib
nserver 1.1.1.1
)"sv;

		config_t cfg;
		REQUIRE_NOTHROW( cfg = parser.parse( what ) );

		REQUIRE( 5ul*1024ul*1024ul == cfg.m_common_acl_params.m_io_chunk_size );
	}

	{
		const auto what = 
R"(
acl.io.chunk_size off
nserver 1.1.1.1
)"sv;

		config_t cfg;
		REQUIRE_THROWS_AS(
				cfg = parser.parse( what ),
				arataga::config_parser_t::parser_exception_t );
	}

	{
		const auto what = 
R"(
acl.io.chunk_size 0
nserver 1.1.1.1
)"sv;

		config_t cfg;
		REQUIRE_THROWS_AS(
				cfg = parser.parse( what ),
				arataga::config_parser_t::parser_exception_t );
	}

	{
		const auto what = 
R"(
acl.io.chunk_size -120
nserver 1.1.1.1
)"sv;

		config_t cfg;
		REQUIRE_THROWS_AS(
				cfg = parser.parse( what ),
				arataga::config_parser_t::parser_exception_t );
	}
}

TEST_CASE("io_chunk_count") {
	using namespace arataga;

	config_parser_t parser;

	{
		const auto what = 
R"(
acl.io.chunk_count 128
nserver 1.1.1.1
)"sv;

		config_t cfg;
		REQUIRE_NOTHROW( cfg = parser.parse( what ) );

		REQUIRE( 128u == cfg.m_common_acl_params.m_io_chunk_count );
	}

	{
		const auto what = 
R"(
acl.io.chunk_count off
nserver 1.1.1.1
)"sv;

		config_t cfg;
		REQUIRE_THROWS_AS(
				cfg = parser.parse( what ),
				arataga::config_parser_t::parser_exception_t );
	}

	{
		const auto what = 
R"(
acl.io.chunk_count 0
nserver 1.1.1.1
)"sv;

		config_t cfg;
		REQUIRE_THROWS_AS(
				cfg = parser.parse( what ),
				arataga::config_parser_t::parser_exception_t );
	}

	{
		const auto what = 
R"(
acl.io.chunk_count -120
nserver 1.1.1.1
)"sv;

		config_t cfg;
		REQUIRE_THROWS_AS(
				cfg = parser.parse( what ),
				arataga::config_parser_t::parser_exception_t );
	}
}

TEST_CASE("failed_auth_reply_timeout") {
	using namespace arataga;

	config_parser_t parser;

	{
		const auto what = 
R"(
timeout.failed_auth_reply 3
nserver 1.1.1.1
)"sv;

		config_t cfg;
		REQUIRE_NOTHROW( cfg = parser.parse( what ) );

		REQUIRE( 3s == cfg.m_common_acl_params.m_failed_auth_reply_timeout );
	}

	{
		const auto what = 
R"(
timeout.failed_auth_reply 5s
nserver 1.1.1.1
)"sv;

		config_t cfg;
		REQUIRE_NOTHROW( cfg = parser.parse( what ) );

		REQUIRE( 5s == cfg.m_common_acl_params.m_failed_auth_reply_timeout );
	}

	{
		const auto what = 
R"(
timeout.failed_auth_reply 250ms
nserver 1.1.1.1
)"sv;

		config_t cfg;
		REQUIRE_NOTHROW( cfg = parser.parse( what ) );

		REQUIRE( 250ms == cfg.m_common_acl_params.m_failed_auth_reply_timeout );
	}

	{
		const auto what = 
R"(
timeout.failed_auth_reply 0
nserver 1.1.1.1
)"sv;

		config_t cfg;
		REQUIRE_NOTHROW( cfg = parser.parse( what ) );

		REQUIRE( 0ms == cfg.m_common_acl_params.m_failed_auth_reply_timeout );
	}

	{
		const auto what = 
R"(
timeout.failed_auth_reply 0ms
nserver 1.1.1.1
)"sv;

		config_t cfg;
		REQUIRE_NOTHROW( cfg = parser.parse( what ) );

		REQUIRE( 0ms == cfg.m_common_acl_params.m_failed_auth_reply_timeout );
	}

	{
		const auto what = 
R"(
timeout.socks.bind 2min
nserver 1.1.1.1
)"sv;

		config_t cfg;
		REQUIRE_NOTHROW( cfg = parser.parse( what ) );

		REQUIRE( 2min == cfg.m_common_acl_params.m_socks_bind_timeout );
	}
}

TEST_CASE("main timeouts") {
	using namespace arataga;

	config_parser_t parser;

	{
		const auto what = 
R"(
timeout.failed_auth_reply 3
timeout.protocol_detection 1200ms
timeout.socks.handshake 2s
timeout.dns_resolving 1500ms
timeout.authentification 750ms
timeout.connect_target 3s
timeout.idle_connection 10min
timeout.http.headers_complete 1min
timeout.http.negative_response 650ms

nserver 1.1.1.1
)"sv;

		config_t cfg;
		REQUIRE_NOTHROW( cfg = parser.parse( what ) );

		REQUIRE( 3s == cfg.m_common_acl_params.m_failed_auth_reply_timeout );
		REQUIRE( 1'200ms == cfg.m_common_acl_params.m_protocol_detection_timeout );
		REQUIRE( 2s == cfg.m_common_acl_params.m_socks_handshake_phase_timeout );
		REQUIRE( 1'500ms == cfg.m_common_acl_params.m_dns_resolving_timeout );
		REQUIRE( 750ms == cfg.m_common_acl_params.m_authentification_timeout );
		REQUIRE( 3s == cfg.m_common_acl_params.m_connect_target_timeout );
		REQUIRE( 10min == cfg.m_common_acl_params.m_idle_connection_timeout );
		REQUIRE( 1min == cfg.m_common_acl_params.m_http_headers_complete_timeout );
		REQUIRE( 650ms == cfg.m_common_acl_params.m_http_negative_response_timeout );
	}
}

TEST_CASE("bandlim") {
	using namespace arataga;

	config_parser_t parser;

	{
		const auto what = 
R"(
bandlim.in 10240
nserver 1.1.1.1
)"sv;

		config_t cfg;
		REQUIRE_NOTHROW( cfg = parser.parse( what ) );

		REQUIRE( 10240u == cfg.m_common_acl_params.m_client_bandlim.m_in );
		REQUIRE( bandlim_config_t::is_unlimited(
				cfg.m_common_acl_params.m_client_bandlim.m_out ) );
	}

	{
		const auto what = 
R"(
bandlim.in 10KiB
nserver 1.1.1.1
)"sv;

		config_t cfg;
		REQUIRE_NOTHROW( cfg = parser.parse( what ) );

		REQUIRE( 10240u == cfg.m_common_acl_params.m_client_bandlim.m_in );
		REQUIRE( bandlim_config_t::is_unlimited(
				cfg.m_common_acl_params.m_client_bandlim.m_out ) );
	}

	{
		const auto what = 
R"(
bandlim.in 1MiB
nserver 1.1.1.1
)"sv;

		config_t cfg;
		REQUIRE_NOTHROW( cfg = parser.parse( what ) );

		REQUIRE( 1024u*1024u == cfg.m_common_acl_params.m_client_bandlim.m_in );
		REQUIRE( bandlim_config_t::is_unlimited(
				cfg.m_common_acl_params.m_client_bandlim.m_out ) );
	}

	{
		const auto what = 
R"(
bandlim.out 10240
nserver 1.1.1.1
)"sv;

		config_t cfg;
		REQUIRE_NOTHROW( cfg = parser.parse( what ) );

		REQUIRE( 10240u == cfg.m_common_acl_params.m_client_bandlim.m_out );
		REQUIRE( bandlim_config_t::is_unlimited(
				cfg.m_common_acl_params.m_client_bandlim.m_in ) );
	}

	{
		const auto what = 
R"(
bandlim.in 0
bandlim.out 0
nserver 1.1.1.1
)"sv;

		config_t cfg;
		REQUIRE_NOTHROW( cfg = parser.parse( what ) );

		REQUIRE( bandlim_config_t::is_unlimited(
				cfg.m_common_acl_params.m_client_bandlim.m_in ) );
		REQUIRE( bandlim_config_t::is_unlimited(
				cfg.m_common_acl_params.m_client_bandlim.m_out ) );
	}

	{
		const auto what = 
R"(
bandlim.in 10240
bandlim.out 81920
nserver 1.1.1.1
)"sv;

		config_t cfg;
		REQUIRE_NOTHROW( cfg = parser.parse( what ) );

		REQUIRE( 10240u == cfg.m_common_acl_params.m_client_bandlim.m_in );
		REQUIRE( 81920u == cfg.m_common_acl_params.m_client_bandlim.m_out );
	}

	{
		const auto what = 
R"(
bandlim.in 80kbps
bandlim.out 160kbps
nserver 1.1.1.1
)"sv;

		config_t cfg;
		REQUIRE_NOTHROW( cfg = parser.parse( what ) );

		REQUIRE( 10000u == cfg.m_common_acl_params.m_client_bandlim.m_in );
		REQUIRE( 20000u == cfg.m_common_acl_params.m_client_bandlim.m_out );
	}

	{
		const auto what = 
R"(
bandlim.in 80KiBps
bandlim.out 160KiBps
nserver 1.1.1.1
)"sv;

		config_t cfg;
		REQUIRE_NOTHROW( cfg = parser.parse( what ) );

		REQUIRE( 10240u == cfg.m_common_acl_params.m_client_bandlim.m_in );
		REQUIRE( 20480u == cfg.m_common_acl_params.m_client_bandlim.m_out );
	}

	{
		const auto what = 
R"(
bandlim.in non-digit
nserver 1.1.1.1
)"sv;

		config_t cfg;
		REQUIRE_THROWS_AS(
				cfg = parser.parse( what ),
				arataga::config_parser_t::parser_exception_t );
	}

	{
		const auto what = 
R"(
bandlim.out -120
nserver 1.1.1.1
)"sv;

		config_t cfg;
		REQUIRE_THROWS_AS(
				cfg = parser.parse( what ),
				arataga::config_parser_t::parser_exception_t );
	}
}

TEST_CASE("denied_ports") {
	using namespace arataga;

	config_parser_t parser;

	using dp = denied_ports_config_t;

	{
		const auto what = 
R"(
denied_ports 25
nserver 1.1.1.1
)"sv;

		config_t cfg;
		REQUIRE_NOTHROW( cfg = parser.parse( what ) );

		dp::case_container_t expected{
			{ dp::single_port_case_t{ 25u } }
		};

		REQUIRE( expected == cfg.m_denied_ports.m_cases );
		REQUIRE( cfg.m_denied_ports.is_denied( 25u ) );
		REQUIRE( !cfg.m_denied_ports.is_denied( 26u ) );
	}

	{
		const auto what = 
R"(
denied_ports 25-100
nserver 1.1.1.1
)"sv;

		config_t cfg;
		REQUIRE_NOTHROW( cfg = parser.parse( what ) );

		dp::case_container_t expected{
			{ dp::ports_range_case_t{ 25u, 100u } }
		};

		REQUIRE( expected == cfg.m_denied_ports.m_cases );
		REQUIRE( cfg.m_denied_ports.is_denied( 25u ) );
		REQUIRE( cfg.m_denied_ports.is_denied( 26u ) );
		REQUIRE( cfg.m_denied_ports.is_denied( 99u ) );
		REQUIRE( cfg.m_denied_ports.is_denied( 100u ) );
		REQUIRE( !cfg.m_denied_ports.is_denied( 24u ) );
		REQUIRE( !cfg.m_denied_ports.is_denied( 101u ) );
	}

	{
		const auto what = 
R"(
denied_ports 25-100, 443 ,  500 -604   ,700,800-  950
nserver 1.1.1.1
)"sv;

		config_t cfg;
		REQUIRE_NOTHROW( cfg = parser.parse( what ) );

		dp::case_container_t expected{
			{ dp::ports_range_case_t{ 25u, 100u } },
			{ dp::single_port_case_t{ 443u } },
			{ dp::ports_range_case_t{ 500u, 604u } },
			{ dp::single_port_case_t{ 700u } },
			{ dp::ports_range_case_t{ 800u, 950 } },
		};

		REQUIRE( expected == cfg.m_denied_ports.m_cases );
		REQUIRE( cfg.m_denied_ports.is_denied( 25u ) );
		REQUIRE( cfg.m_denied_ports.is_denied( 100u ) );
		REQUIRE( !cfg.m_denied_ports.is_denied( 24u ) );
		REQUIRE( !cfg.m_denied_ports.is_denied( 101u ) );
		REQUIRE( !cfg.m_denied_ports.is_denied( 442u ) );
		REQUIRE( cfg.m_denied_ports.is_denied( 443u ) );
		REQUIRE( !cfg.m_denied_ports.is_denied( 444u ) );
		REQUIRE( !cfg.m_denied_ports.is_denied( 499u ) );
		REQUIRE( cfg.m_denied_ports.is_denied( 500u ) );
		REQUIRE( cfg.m_denied_ports.is_denied( 604u ) );
		REQUIRE( !cfg.m_denied_ports.is_denied( 605u ) );
		REQUIRE( !cfg.m_denied_ports.is_denied( 699u ) );
		REQUIRE( cfg.m_denied_ports.is_denied( 700u ) );
		REQUIRE( !cfg.m_denied_ports.is_denied( 701u ) );
		REQUIRE( !cfg.m_denied_ports.is_denied( 799u ) );
		REQUIRE( cfg.m_denied_ports.is_denied( 800u ) );
		REQUIRE( cfg.m_denied_ports.is_denied( 950u ) );
		REQUIRE( !cfg.m_denied_ports.is_denied( 951u ) );
	}

	{
		const auto what = 
R"(
denied_ports 256-100
nserver 1.1.1.1
)"sv;

		config_t cfg;
		REQUIRE_THROWS_AS(
				cfg = parser.parse( what ),
				arataga::config_parser_t::parser_exception_t );
	}

	{
		const auto what = 
R"(
denied_ports 256-
nserver 1.1.1.1
)"sv;

		config_t cfg;
		REQUIRE_THROWS_AS(
				cfg = parser.parse( what ),
				arataga::config_parser_t::parser_exception_t );
	}


	{
		const auto what = 
R"(
denied_ports 256-257,
nserver 1.1.1.1
)"sv;

		config_t cfg;
		REQUIRE_NOTHROW( cfg = parser.parse( what ) );

		dp::case_container_t expected{
			{ dp::ports_range_case_t{ 256u, 257u } }
		};

		REQUIRE( expected == cfg.m_denied_ports.m_cases );
	}
}

TEST_CASE("acls") {
	using namespace arataga;

	config_parser_t parser;

	{
		const auto what = 
R"(
acl auto, port=3000, in_ip=127.0.0.1, out_ip=192.168.100.1
nserver 1.1.1.1
)"sv;

		config_t cfg;
		REQUIRE_NOTHROW( cfg = parser.parse( what ) );

		config_t::acl_container_t expected{
			acl_config_t{ acl_protocol_t::autodetect,
					3000u,
					asio::ip::make_address_v4( "127.0.0.1" ),
					asio::ip::make_address( "192.168.100.1" )
			}
		};

		REQUIRE( expected == cfg.m_acls );
	}

	{
		const auto what = 
R"(
acl auto,  port=3000, in_ip=127.0.0.1, out_ip=192.168.100.1
acl socks, port=3002, in_ip=127.0.0.1, out_ip=192.168.100.2
acl http,  port=3003, in_ip=127.0.0.1, out_ip=192.168.100.3
acl http,  port=3004, in_ip=127.0.0.1, out_ip=2a0a:5686:0001:1b1f:0695:e6ff:fed4:2a8b
acl http,  port=3005, in_ip=127.0.0.1, out_ip=2a0a:5686::0b46:0e80:63ff:fe7a:966d
nserver 1.1.1.1
)"sv;

		config_t cfg;
		REQUIRE_NOTHROW( cfg = parser.parse( what ) );

		config_t::acl_container_t expected{
			acl_config_t{ acl_protocol_t::autodetect,
					3000u,
					asio::ip::make_address_v4( "127.0.0.1" ),
					asio::ip::make_address( "192.168.100.1" )
			},
			acl_config_t{ acl_protocol_t::socks,
					3002u,
					asio::ip::make_address_v4( "127.0.0.1" ),
					asio::ip::make_address( "192.168.100.2" )
			},
			acl_config_t{ acl_protocol_t::http,
					3003u,
					asio::ip::make_address_v4( "127.0.0.1" ),
					asio::ip::make_address( "192.168.100.3" )
			},
			acl_config_t{ acl_protocol_t::http,
					3004u,
					asio::ip::make_address_v4( "127.0.0.1" ),
					asio::ip::make_address( "2a0a:5686:0001:1b1f:0695:e6ff:fed4:2a8b" )
			},
			acl_config_t{ acl_protocol_t::http,
					3005u,
					asio::ip::make_address_v4( "127.0.0.1" ),
					asio::ip::make_address( "2a0a:5686::0b46:0e80:63ff:fe7a:966d" )
			}
		};

		REQUIRE( expected == cfg.m_acls );
	}

	{
		const auto what = 
R"(
acl auto,  port=3000, in_ip=127.0.0.1, out_ip=192.168.100.1 ,
acl socks, port=3002, in_ip=127.0.0.1, out_ip=192.168.100.2,
acl http,  port=3003, in_ip=127.0.0.1, out_ip=192.168.100.3     ,
nserver 1.1.1.1
)"sv;

		config_t cfg;
		REQUIRE_NOTHROW( cfg = parser.parse( what ) );

		config_t::acl_container_t expected{
			acl_config_t{ acl_protocol_t::autodetect,
					3000u,
					asio::ip::make_address_v4( "127.0.0.1" ),
					asio::ip::make_address( "192.168.100.1" )
			},
			acl_config_t{ acl_protocol_t::socks,
					3002u,
					asio::ip::make_address_v4( "127.0.0.1" ),
					asio::ip::make_address( "192.168.100.2" )
			},
			acl_config_t{ acl_protocol_t::http,
					3003u,
					asio::ip::make_address_v4( "127.0.0.1" ),
					asio::ip::make_address( "192.168.100.3" )
			}
		};

		REQUIRE( expected == cfg.m_acls );
	}

	{
		const auto what = 
R"(
acl auto,  in_ip=127.0.0.1, port=3000, out_ip=192.168.100.1
acl socks, out_ip=192.168.100.2, in_ip=127.0.0.1, port=3002
acl http,  port=3003, in_ip=127.0.0.1, out_ip=192.168.100.3
nserver 1.1.1.1
)"sv;

		config_t cfg;
		REQUIRE_NOTHROW( cfg = parser.parse( what ) );

		config_t::acl_container_t expected{
			acl_config_t{ acl_protocol_t::autodetect,
					3000u,
					asio::ip::make_address_v4( "127.0.0.1" ),
					asio::ip::make_address( "192.168.100.1" )
			},
			acl_config_t{ acl_protocol_t::socks,
					3002u,
					asio::ip::make_address_v4( "127.0.0.1" ),
					asio::ip::make_address( "192.168.100.2" )
			},
			acl_config_t{ acl_protocol_t::http,
					3003u,
					asio::ip::make_address_v4( "127.0.0.1" ),
					asio::ip::make_address( "192.168.100.3" )
			}
		};

		REQUIRE( expected == cfg.m_acls );
	}

	{
		const auto what = 
R"(
acl auto,  in_ip = 127.0.0.1 , port= 3000  ,out_ip  =192.168.100.1
acl socks  , out_ip=192.168.100.2    , in_ip   =   127.0.0.1, port=  3002
acl http   ,port=3003,in_ip=127.0.0.1,out_ip=192.168.100.3
nserver 1.1.1.1
)"sv;

		config_t cfg;
		REQUIRE_NOTHROW( cfg = parser.parse( what ) );

		config_t::acl_container_t expected{
			acl_config_t{ acl_protocol_t::autodetect,
					3000u,
					asio::ip::make_address_v4( "127.0.0.1" ),
					asio::ip::make_address( "192.168.100.1" )
			},
			acl_config_t{ acl_protocol_t::socks,
					3002u,
					asio::ip::make_address_v4( "127.0.0.1" ),
					asio::ip::make_address( "192.168.100.2" )
			},
			acl_config_t{ acl_protocol_t::http,
					3003u,
					asio::ip::make_address_v4( "127.0.0.1" ),
					asio::ip::make_address( "192.168.100.3" )
			}
		};

		REQUIRE( expected == cfg.m_acls );
	}

	{
		const auto what = 
R"(
acl auto, in_ip=127.0.0.1, out_ip=192.168.100.1
nserver 1.1.1.1
)"sv;

		config_t cfg;
		REQUIRE_THROWS_AS(
				cfg = parser.parse( what ),
				arataga::config_parser_t::parser_exception_t );
	}

	{
		const auto what = 
R"(
acl auto, port=3000, out_ip=192.168.100.1
nserver 1.1.1.1
)"sv;

		config_t cfg;
		REQUIRE_THROWS_AS(
				cfg = parser.parse( what ),
				arataga::config_parser_t::parser_exception_t );
	}

	{
		const auto what = 
R"(
acl auto, port=3000, in_ip=192.168.100.1
nserver 1.1.1.1
)"sv;

		config_t cfg;
		REQUIRE_THROWS_AS(
				cfg = parser.parse( what ),
				arataga::config_parser_t::parser_exception_t );
	}

	{
		const auto what = 
R"(
acl auto, port=-20, in_ip=192.168.100.1, out_ip=192.168.1.100
nserver 1.1.1.1
)"sv;

		config_t cfg;
		REQUIRE_THROWS_AS(
				cfg = parser.parse( what ),
				arataga::config_parser_t::parser_exception_t );
	}

	{
		const auto what = 
R"(
acl auto, port=200, in_ip=123444.2938383.33939, out_ip=192.168.1.100
nserver 1.1.1.1
)"sv;

		config_t cfg;
		REQUIRE_THROWS_AS(
				cfg = parser.parse( what ),
				arataga::config_parser_t::parser_exception_t );
	}

	{
		const auto what = 
R"(
acl auto, port=200, in_ip=192.168.1.100, out_ip=123444.2938383.33939
nserver 1.1.1.1
)"sv;

		config_t cfg;
		REQUIRE_THROWS_AS(
				cfg = parser.parse( what ),
				arataga::config_parser_t::parser_exception_t );
	}
}

TEST_CASE("http.limits") {
	using namespace arataga;

	config_parser_t parser;

	{
		const auto what = 
R"(
http.limits.request_target 2500
http.limits.field_name 1kib
http.limits.field_value 20kib
http.limits.total_headers_size 1mib
http.limits.status_line 512b
nserver 1.1.1.1
)"sv;

		config_t cfg;
		REQUIRE_NOTHROW( cfg = parser.parse( what ) );

		REQUIRE( 2500u == cfg.m_common_acl_params.m_http_message_limits
				.m_max_request_target_length );
		REQUIRE( 1u*1024u == cfg.m_common_acl_params.m_http_message_limits
				.m_max_field_name_length );
		REQUIRE( 20u*1024u == cfg.m_common_acl_params.m_http_message_limits
				.m_max_field_value_length );
		REQUIRE( 1024u*1024u == cfg.m_common_acl_params.m_http_message_limits
				.m_max_total_headers_size );
		REQUIRE( 512u == cfg.m_common_acl_params.m_http_message_limits
				.m_max_status_line_length );
	}

	{
		const auto what = 
R"(
http.limits.request_target off
nserver 1.1.1.1
)"sv;

		config_t cfg;
		REQUIRE_THROWS_AS(
				cfg = parser.parse( what ),
				arataga::config_parser_t::parser_exception_t );
	}

	{
		const auto what = 
R"(
http.limits.request_target 0
nserver 1.1.1.1
)"sv;

		config_t cfg;
		REQUIRE_THROWS_AS(
				cfg = parser.parse( what ),
				arataga::config_parser_t::parser_exception_t );
	}

	{
		const auto what = 
R"(
http.limits.request_target -120
nserver 1.1.1.1
)"sv;

		config_t cfg;
		REQUIRE_THROWS_AS(
				cfg = parser.parse( what ),
				arataga::config_parser_t::parser_exception_t );
	}
}

