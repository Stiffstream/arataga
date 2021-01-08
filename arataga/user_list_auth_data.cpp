/*!
 * @file
 * @brief Описание данных, которые содержатся в user-list.
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
	// Имя должно быть преобразовано в нижний регистр.
	std::transform(
			m_value.begin(), m_value.end(),
			m_value.begin(),
			[](unsigned char ch) { return std::tolower(ch); });

	// Если в имени есть лидирующие '.', то они должны быть изъяты.
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

	// Поскольку на практике список лимитов не очень длинный,
	// а данные поднимаются из list-файла в неотсортированном виде,
	// то используем простой последовательный перебор.
	const one_limit_t * last_found{ nullptr };
	for( const auto & l : m_limits )
	{
		if( is_subdomain_of( host, l.m_domain ) )
		{
			// Нашли ограничение. Но самое ли оно лучшее?
			if( !last_found )
			{
				// Других вариантов нет, так что лучшее пока.
				last_found = &l;
			}
			else
			{
				// Наш вариант будет лучше, если он является поддоменом
				// для ранее найденого варианта.
				// Т.е. если сперва нашли "vk.com", а текущий вариант
				// "api.vk.com", то тогда новый вариант лучше старого.
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
 * @brief Предикат для easy_parser-а, который распознает непробельные
 * символы.
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
 * @brief Продюсер для easy_parser-а, который извлекает непробельные
 * символы.
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
 * @brief Продюсер для easy_parser-а, который извлекает последовательность
 * непробельных символов.
 *
 * Этот продюсер производит экземпляр std::string.
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

// Вспомогательная функция для выражения последовательности из
// одного или более пробелов.
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
 * @brief Продюсер для значения bandlim_config.
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
 * @brief Продюсер для значения IPv4 адреса.
 *
 * Значение IPv4 адреса может быть задано как в виде одного целого числа,
 * так и в традиционном виде (последовательность из четырех групп цифр,
 * разделенных точками).
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
 * @brief Продюсер для значения IP-порта.
 */
[[nodiscard]]
auto
ip_port_p()
{
	using namespace restinio::http_field_parsers;

	return non_negative_decimal_number_p< ip_port_t >();
}

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
 * Значение, которое должно быть получено в результате разбора правила:
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
 * Значение, которое должно быть получено в результате разбора правила:
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
 * Значение, которое должно быть получено в результате разбора правила:
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
 * Тип, который должен получиться в результате разбора одной строки
 * файла со списком пользователей.
 */
using line_content_t = std::variant<
	by_ip_data_t,
	by_login_data_t,
	limits_data_t >;

//
// make_line_parser
//
//! Создает продюсера, который извлекает из строки значение line_content.
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

	// Парсер для строк из списка пользователей.
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

	// Читаем файл. При возникновении ошибок будет исключение.
	const auto buffer = ::arataga::utils::load_file_into_memory( file_name );

	// Осталось разобрать то, что прочитали.
	result = parse_auth_data(
			std::string_view{ buffer.data(), buffer.size() } );

	return result;
}

} /* namespace arataga::user_list_auth */

