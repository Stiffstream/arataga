/*!
 * @file
 * @brief Менеджер лимитов по подключениям одного пользователя.
 */

#pragma once

#include <arataga/acl_handler/sequence_number.hpp>

#include <arataga/user_list_auth_data.hpp>

#include <map>

namespace arataga::acl_handler
{

//! Псевдоним для типа, являющегося именем домена.
using domain_name_t = ::arataga::user_list_auth::domain_name_t;

//
// bandlim_manager_t
//
/*!
 * @brief Менеджер лимитов для подключений одного клиента.
 */
class bandlim_manager_t
{
public:
	//
	// Публично доступные типы данных.
	//
	
	//! Специальное представление квоты, которое автоматически
	//! обрабатывает значение unlimited.
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

	//! Информация о трафике по одному направлению.
	struct direction_traffic_info_t
	{
		//! Квота на текущий такт.
		quote_t m_quote{};
		//! Зарезервированное пространство на текущем такте.
		bandlim_config_t::value_t m_reserved{};
		//! Фактическая величина трафика на текущем такте.
		bandlim_config_t::value_t m_actual{};

		//! Номер такта, к которому относится информация.
		sequence_number_t m_sequence_number{};
	};

	//! Информация по лимитам на одном подключении.
	struct channel_limits_data_t
	{
		//! Исходные значения, которые заданы в конфигурации.
		bandlim_config_t m_directive_values;

		// Показатели по расходу трафика на текущем такте.
		direction_traffic_info_t m_user_end_traffic;
		direction_traffic_info_t m_target_end_traffic;
	};

	//! Информация по трафику на конкретный домен.
	struct domain_traffic_data_t
	{
		//! Сколько подключений сейчас работают с этим доменом.
		std::size_t m_connection_count;

		//! Информация по трафику на этот домен.
		channel_limits_data_t m_traffic;
	};

	//! Тип словаря для лимитов по доменам.
	using domain_traffic_map_t =
			std::map< domain_name_t, domain_traffic_data_t >;

private:
	//
	// Собственные данные менеджера лимитов.
	//

	//! Значение персонального лимита для этого пользователя.
	//! Это значение нужно сохранять на случай, если в конфигурации
	//! изменились default_limits.
	bandlim_config_t m_directive_personal_limits;

	//! Это значение общего лимита для клиента, которое вычислено
	//! на основании персонального лимита и default_limits из конфигурации.
	bandlim_config_t m_general_limits;

	//! Счетчик трафика по всем подключениям клиента.
	channel_limits_data_t m_general_traffic;

	//! Счетчики трафика по отдельным доменам.
	domain_traffic_map_t m_domain_traffic;

	//! Счетчик номеров тактов.
	sequence_number_t m_sequence_number;

	//! Время последнего пересчета лимитов.
	std::chrono::steady_clock::time_point m_last_update_at;

public:
	bandlim_manager_t(
		bandlim_config_t personal_limits,
		bandlim_config_t default_limits );

	// Вызывается каждый раз, когда получаем положительный
	// ответ на аутентификацию этого клиента.
	void
	update_personal_limits(
		bandlim_config_t personal_limits,
		bandlim_config_t default_limits );

	// Вызывается каждый раз, когда меняется конфигурация arataga.
	void
	update_default_limits(
		bandlim_config_t default_limits ) noexcept;

	[[nodiscard]]
	channel_limits_data_t &
	general_traffic() noexcept;

	[[nodiscard]]
	const channel_limits_data_t &
	general_traffic() const noexcept;

	// Создать новый лимит для конкретного домена.
	//
	// Количество подключений для нового лимита устанавливается в 1.
	// Если такой лимит уже был, то счетчик подключений увеличивается на 1.
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

