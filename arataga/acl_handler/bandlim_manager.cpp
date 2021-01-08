/*!
 * @file
 * @brief Менеджер лимитов по подключениям одного пользователя.
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
	// На текущий такт для всех подключений (которые еще только должны
	// появится) выставим значение из general_limits.
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

	// Должны так же поменять значения для общего счетчика трафика.
	m_general_traffic.m_directive_values = m_general_limits;

	// Изменения в текущие счетчики сейчас не вносим. Оставляем это
	// до наступления следующего такта.
}

void
bandlim_manager_t::update_default_limits(
	bandlim_config_t default_limits ) noexcept
{
	m_general_limits = make_personal_limits_with_respect_to_defaults(
			m_directive_personal_limits, default_limits );

	// Должны так же поменять значения для общего счетчика трафика.
	m_general_traffic.m_directive_values = m_general_limits;

	// Изменения в текущие счетчики сейчас не вносим. Оставляем это
	// до наступления следующего такта.
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
		// Нужно создавать новый элемент. Для которого нужно подготовить
		// новый лимит.
		it = m_domain_traffic.emplace(
				std::move(domain),
				domain_traffic_data_t{
						// Сразу же учитываем новое подключение.
						1u,
						make_new_channel_limits_data( m_sequence_number, limits )
				} ).first;
	}
	else
	{
		// Нужно учесть добавление нового подключения.
		it->second.m_connection_count += 1u;

		// Нужно учесть так же и то, что limits могут содержать
		// новые значения.
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

	// Т.к. таймерное сообщение может приходить нерегулярно,
	// то нам нужно учитывать эту нерегулярность и пересчитывать
	// квоты с учетом возможных подвижек туда-сюда.
	const auto update_at = steady_clock::now();
	// Есть большая вероятность того, что разница между m_last_update_at
	// и update_at всегда будет помещаться в double.
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

	// Вспомогательная функция для выполнения однотипных действий
	// над channel_limits_data_t::m_user_end_traffic и
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
				// Если на предыдущем такте отослали больше, чем было
				// разрешено, то в этом такте учитываем "излишек".
				// Если "излишек" превысит quote, то значит текущий такт
				// будет пропущен.
				f.m_actual -= old_quote;
			}

			// Т.к. на предыдущем такте конфигурация могла изменится, то
			// выставляем новую квоту.
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

	// Номер такта должен изменится.
	m_sequence_number.increment();

	// Сперва обрабатываем общий лимит на все подключения.
	processor( m_general_traffic );
	// А затем уже проходимся по всем доменам.
	for( auto & [k, v] : m_domain_traffic )
		processor( v.m_traffic );
}

} /* namespace arataga::acl_handler */

