/*!
 * @file
 * @brief Description of data in a user-list.
 */

#include <arataga/user_list_auth_data.hpp>

#include <arataga/utils/ensure_successful_syscall.hpp>
#include <arataga/utils/line_reader.hpp>
#include <arataga/utils/load_file_into_memory.hpp>
#include <arataga/utils/overloaded.hpp>
#include <arataga/utils/ip_address_parsers.hpp>
#include <arataga/utils/transfer_speed_parser.hpp>

#include <restinio/helpers/http_field_parsers/basics.hpp>

#include <fmt/format.h>
#include <fmt/ostream.h>

#include <algorithm>
#include <cctype>
#include <variant>

namespace arataga::user_list_auth {

//
// domain_name_t
//
domain_name_t::domain_name_t()
{}

domain_name_t::domain_name_t( std::string value )
	: m_value{ std::move(value) }
{
	// Name should be converted into the lower case.
	std::transform(
			m_value.begin(), m_value.end(),
			m_value.begin(),
			[](unsigned char ch) { return std::tolower(ch); });

	// If there are leading '.' they should be removed.
	if( const auto pos = m_value.find_first_not_of('.');
			std::string::npos != pos )
	{
		m_value = m_value.substr(pos);
	}
}

const std::string &
domain_name_t::value() const noexcept { return m_value; }

bool
operator==(const domain_name_t & a, const domain_name_t & b) noexcept
{
	return a.value() == b.value();
}

bool
operator<(const domain_name_t & a, const domain_name_t & b) noexcept
{
	return a.value() < b.value();
}

std::ostream &
operator<<(std::ostream & to, const domain_name_t & name)
{
	return (to << "[" << name.value() << "]");
}

//
// is_subdomain_of
//
[[nodiscard]]
bool
is_subdomain_of(
	const domain_name_t & full_name,
	const domain_name_t & domain_name) noexcept
{
	const auto & fn = full_name.value();
	const auto & d = domain_name.value();

	if( fn.size() == d.size() )
		return fn == d;
	else if( fn.size() > d.size() )
	{
		const auto pos = fn.size() - d.size() - 1u;
		return '.' == fn[pos] &&
				std::equal(fn.begin() + pos + 1u, fn.end(), d.begin());
	}
	else
		return false;
}

//
// site_limits_data_t
//
std::optional< site_limits_data_t::one_limit_t >
site_limits_data_t::try_find_limits_for( domain_name_t host ) const
{
	std::optional< one_limit_t > result;

	// Because limit's list is not a big one and that list isn't ordered
	// a simple sequential search is used.
	const one_limit_t * last_found{ nullptr };
	for( const auto & l : m_limits )
	{
		if( is_subdomain_of( host, l.m_domain ) )
		{
			// Find a limit. Is it the best one?
			if( !last_found )
			{
				// There is no other limits yet so this is the best one.
				last_found = &l;
			}
			else
			{
				// The current limit will be better if it is for a subdomain
				// for the previous case.
				// For example if the previous case "vk.com" and the current
				// is "api.vk.com" then the current case is better than
				// the previous.
				if( is_subdomain_of( l.m_domain, last_found->m_domain ) )
					last_found = &l;
			}
		}
	}

	if( last_found )
		result = *last_found;

	return result;
}

namespace
{

//
// is_nonspace_char_predicate_t
//
/*!
 * @brief A predicate for easy_parser that detects non-space symbols.
 */
struct is_nonspace_char_predicate_t
{
	[[nodiscard]]
	bool
	operator()( char ch ) const noexcept
	{
		return !restinio::easy_parser::impl::is_space(ch);
	}
};

//
// nonspace_char_p
//
/*!
 * @brief A producer for easy_parser that extracts non-space symbols.
 */
[[nodiscard]]
inline auto
nonspace_char_p() noexcept
{
	return restinio::easy_parser::impl::symbol_producer_template_t<
			is_nonspace_char_predicate_t >{};
}

//
// nonspace_char_seq_p
//
/*!
 * @brief A producer for easy_parser that extracts sequences of non-space
 * symbols.
 *
 * That producer makes instances of std::string.
 */
[[nodiscard]]
inline auto
nonspace_char_seq_p() noexcept
{
	using namespace restinio::easy_parser;

	return produce< std::string >(
			repeat( 1, N, nonspace_char_p() >> to_container() )
		);
}

// Helper function for expressing a sequences of spaces.
[[nodiscard]]
auto
mandatory_space()
{
	using namespace restinio::http_field_parsers;

	return repeat( 1u, N, space() );
}

//
// bandlim_p
//
/*!
 * @brief A producer for bandlim_config values.
 */
[[nodiscard]]
auto
bandlim_p()
{
	using namespace restinio::http_field_parsers;

	return produce< bandlim_config_t >(
			arataga::utils::parsers::transfer_speed_p()
					>> &bandlim_config_t::m_in,
			mandatory_space(),
			arataga::utils::parsers::transfer_speed_p()
					>> &bandlim_config_t::m_out
		);
}

//
// ipv4_address_p
//
/*!
 * @brief A producer for IPv4 addresses.
 *
 * An IPv4 address can be expressed either as a single integer value or
 * as traditional four groups of digits separated by '.'.
 */
[[nodiscard]]
inline auto
ipv4_address_p()
{
	using namespace restinio::http_field_parsers;

	const auto ip_as_integer_p = produce< ipv4_address_t >(
			non_negative_decimal_number_p< ipv4_address_t::uint_type >()
					>> convert( []( auto uint_v ) {
							return ipv4_address_t{ uint_v };
						} )
					>> as_result()
		);

	return produce< ipv4_address_t >(
			alternatives(
					arataga::utils::parsers::ipv4_address_p() >> as_result(),
					ip_as_integer_p >> as_result()
			)
		);
}

//
// ip_port_p
//
/*!
 * @brief A producer for IP-port value.
 */
[[nodiscard]]
auto
ip_port_p()
{
	using namespace restinio::http_field_parsers;

	return non_negative_decimal_number_p< ip_port_t >();
}

//
// user_data_p
//
/*!
 * @brief A producer for user_data value.
 */
[[nodiscard]]
auto
user_data_p()
{
	using namespace restinio::http_field_parsers;

	return produce< user_data_t >(
			bandlim_p() >> &user_data_t::m_bandlims,
			mandatory_space(),
			non_negative_decimal_number_p< std::uint32_t >()
					>> &user_data_t::m_site_limits_id,
			mandatory_space(),
			non_negative_decimal_number_p< user_id_t >()
					>> &user_data_t::m_user_id
		);
}

//
// auth_by_ip_p
//
/*!
 * @brief A producer for auth_by_ip_key_t value.
 */
[[nodiscard]]
auto
auth_by_ip_p()
{
	using namespace restinio::http_field_parsers;

	return produce< auth_by_ip_key_t >(
			ipv4_address_p() >> &auth_by_ip_key_t::m_proxy_in_addr,
			mandatory_space(),
			ip_port_p() >> &auth_by_ip_key_t::m_proxy_port,
			mandatory_space(),
			ipv4_address_p() >> &auth_by_ip_key_t::m_user_ip
		);
}

//
// auth_by_login_p
//
/*!
 * @brief A producer for auth_by_login_key_t value.
 */
[[nodiscard]]
auto
auth_by_login_p()
{
	using namespace restinio::http_field_parsers;

	return produce< auth_by_login_key_t >(
			ipv4_address_p() >> &auth_by_login_key_t::m_proxy_in_addr,
			mandatory_space(),
			ip_port_p() >> &auth_by_login_key_t::m_proxy_port,
			mandatory_space(),
			nonspace_char_seq_p() >> &auth_by_login_key_t::m_username,
			mandatory_space(),
			nonspace_char_seq_p() >> &auth_by_login_key_t::m_password
		);
}

//
// site_limits_key_p
//
/*!
 * @brief A producer for site_limits_key_t value.
 */
[[nodiscard]]
auto
site_limits_key_p()
{
	using namespace restinio::http_field_parsers;

	return produce< site_limits_key_t >(
			non_negative_decimal_number_p< std::uint32_t >()
					>> &site_limits_key_t::m_site_limits_id
		);
}

//
// one_site_limit_p
//
/*!
 * @brief A producer for site_limits_data_t::one_limit_t value.
 */
[[nodiscard]]
auto
one_site_limit_p()
{
	using namespace restinio::http_field_parsers;

	auto string_to_domain_name = []( std::string from ) -> domain_name_t {
		return { std::move(from) };
	};

	return produce< site_limits_data_t::one_limit_t >(
			nonspace_char_seq_p()
					>> convert( string_to_domain_name )
					>> &site_limits_data_t::one_limit_t::m_domain,
			mandatory_space(),
			bandlim_p() >> &site_limits_data_t::one_limit_t::m_bandlims
		);
}

//
// site_limits_data_p
//
/*!
 * @brief A producer for site_limits_data_t value.
 */
[[nodiscard]]
auto
site_limits_data_p()
{
	using namespace restinio::http_field_parsers;

	return produce< site_limits_data_t >(
			produce< site_limits_data_t::limits_container_t >(
				repeat( 0u, N,
					one_site_limit_p() >> to_container(),
					ows()
				)
			) >> &site_limits_data_t::m_limits
		);
}

//
// by_ip_data_t
//
/*
 * A value that has to be produced as the result of the parsing of the rule:
 *
 * auth_by_ip_key = user_data
 *
 */
struct by_ip_data_t
{
	auth_by_ip_key_t m_key;
	user_data_t m_data;

	[[nodiscard]]
	static auto
	make_producer()
	{
		using namespace restinio::http_field_parsers;

		return produce< by_ip_data_t >(
				auth_by_ip_p() >> &by_ip_data_t::m_key,
				ows(),
				symbol( '=' ),
				ows(),
				user_data_p() >> &by_ip_data_t::m_data );
	}
};

//
// by_login_data_t
//
/*
 * A value that has to be produced as the result of the parsing of the rule:
 *
 * auth_by_login = user_data
 *
 */
struct by_login_data_t
{
	auth_by_login_key_t m_key;
	user_data_t m_data;

	[[nodiscard]]
	static auto
	make_producer()
	{
		using namespace restinio::http_field_parsers;

		return produce< by_login_data_t >(
				auth_by_login_p() >> &by_login_data_t::m_key,
				ows(),
				symbol( '=' ),
				ows(),
				user_data_p() >> &by_login_data_t::m_data );
	}
};

//
// limits_data_t
//
/*
 * A value that has to be produced as the result of the parsing of the rule:
 *
 * site_limits_id = site_limits_data
 *
 */
struct limits_data_t
{
	site_limits_key_t m_key;
	site_limits_data_t m_data;

	[[nodiscard]]
	static auto
	make_producer()
	{
		using namespace restinio::http_field_parsers;

		return produce< limits_data_t >(
				site_limits_key_p() >> &limits_data_t::m_key,
				ows(),
				symbol( '=' ),
				ows(),
				site_limits_data_p() >> &limits_data_t::m_data );
	}
};

//
// line_content_t
//
/*
 * A type for holding the result of parsing a single line of user-list file.
 */
using line_content_t = std::variant<
	by_ip_data_t,
	by_login_data_t,
	limits_data_t >;

//
// make_line_parser
//
/*!
 * @brief Makes a producer for line_content_t values.
 */
[[nodiscard]]
auto
make_line_parser()
{
	using namespace restinio::http_field_parsers;

	return produce< line_content_t >(
		alternatives(
			by_ip_data_t::make_producer() >> as_result(),
			by_login_data_t::make_producer() >> as_result(),
			limits_data_t::make_producer() >> as_result()
		)
	);
}

template< typename Line_Parser >
void
analyze_line_read(
	std::string_view line,
	unsigned long line_number,
	Line_Parser & parser,
	auth_data_t & result)
{
	using namespace restinio::http_field_parsers;

	auto parse_result = try_parse( line, parser );
	if( !parse_result )
	{
		throw std::runtime_error{
				fmt::format( "unable to parse line #{}: {}",
						line_number,
						make_error_description( parse_result.error(), line ) )
			};
	}

	std::visit(
		::arataga::utils::overloaded{
			[&result]( by_ip_data_t & v ) {
				result.m_by_ip.emplace(
						std::move(v.m_key), std::move(v.m_data) );
			},
			[&result]( by_login_data_t & v ) {
				result.m_by_login.emplace(
						std::move(v.m_key), std::move(v.m_data) );
			},
			[&result]( limits_data_t & v ) {
				result.m_site_limits.emplace(
						std::move(v.m_key), std::move(v.m_data) );
			}
		},
		*parse_result );
}

} /* namespace anonymous */

//
// parse_auth_data
//
[[nodiscard]]
auth_data_t
parse_auth_data(
	std::string_view user_list_content )
{
	auth_data_t result;

	// A parser for lines from user-list file.
	auto parser = make_line_parser();

	::arataga::utils::line_reader_t content_reader{ user_list_content };

	content_reader.for_each_line( [&result, &parser]( const auto & line ) {
			analyze_line_read( line.content(), line.number(), parser, result );
		} );

	return result;
}

//
// load_auth_data
//
auth_data_t
load_auth_data(
	const std::filesystem::path & file_name)
{
	auth_data_t result;

	// Load the file. There will be a exception in the case of errors.
	const auto buffer = ::arataga::utils::load_file_into_memory( file_name );

	// Parse the loaded content.
	result = parse_auth_data(
			std::string_view{ buffer.data(), buffer.size() } );

	return result;
}

} /* namespace arataga::user_list_auth */

