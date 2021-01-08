/*!
 * @file
 * @brief Повторно используемые средства для разбора значения максимальной
 * пропускной способности.
 */

#pragma once

#include <arataga/bandlim_config.hpp>

#include <restinio/helpers/http_field_parsers/basics.hpp>

namespace arataga::utils::parsers
{

//
// transfer_speed_p
//
/*!
 * @brief Продюсер для easy_parser-а, который извлекает значение
 * скорости передачи данных с возможными суффиксами (gibps, mibps,
 * kibps, bps, kbps, mbps, gbps, b, kib, mib, gib).
 *
 * Продюсер производит значение типа bandlim_config_t::value_t.
 */
[[nodiscard]]
inline auto
transfer_speed_p()
{
	using value_t = bandlim_config_t::value_t;

	struct scale_t
	{
		value_t m_multiplier{ 1u };
		std::uint8_t m_divider{ 1u }; 
	};

	struct tmp_value_t
	{
		value_t m_count{ 0u };
		scale_t m_scale{};
	};

	using namespace restinio::http_field_parsers;

	return produce< value_t >(
			produce< tmp_value_t >(
				non_negative_decimal_number_p< value_t >()
						>> &tmp_value_t::m_count,
				maybe(
					produce< scale_t >(
						alternatives(
							expected_caseless_token_p( "GiBps" )
									>> just_result( scale_t{ 1024ul * 1024ul * 1024ul, 8u } ),
							expected_caseless_token_p( "MiBps" )
									>> just_result( scale_t{ 1024ul * 1024ul, 8u } ),
							expected_caseless_token_p( "KiBps" )
									>> just_result( scale_t{ 1024ul, 8u } ),
							expected_caseless_token_p( "gbps" )
									>> just_result( scale_t{ 1000ul * 1000ul * 1000ul, 8u } ),
							expected_caseless_token_p( "mbps" )
									>> just_result( scale_t{ 1000ul * 1000ul, 8u } ),
							expected_caseless_token_p( "kbps" )
									>> just_result( scale_t{ 1000ul, 8u } ),
							expected_caseless_token_p( "bps" )
									>> just_result( scale_t{ 1ul, 8u } ),
							expected_caseless_token_p( "GiB" )
									>> just_result( scale_t{ 1024ul * 1024ul * 1024ul, 1u } ),
							expected_caseless_token_p( "MiB" )
									>> just_result( scale_t{ 1024ul * 1024ul, 1u } ),
							expected_caseless_token_p( "KiB" )
									>> just_result( scale_t{ 1024ul, 1u } ),
							expected_caseless_token_p( "b" )
									>> just_result( scale_t{ 1ul, 1u } )
						)
					) >> &tmp_value_t::m_scale
				)
			)
			>> convert( []( const auto tmp ) {
					return (tmp.m_count * tmp.m_scale.m_multiplier) /
							tmp.m_scale.m_divider;
				} )
			>> as_result()
		);
}

} /* namespace arataga::utils::parsers */

