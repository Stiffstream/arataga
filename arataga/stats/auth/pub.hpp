/*!
 * @file
 * @brief Средства для сбора статистики по аутентификациям.
 */

#pragma once

#include <atomic>
#include <cstdint>
#include <memory>

namespace arataga::stats::auth
{

//
// auth_stats_t
//
//! Статистика по одному агенту-authentificator-у.
struct auth_stats_t
{
	//! Общее количество операций аутентификации.
	std::atomic< std::uint64_t > m_auth_total_count{};
	//! Общее количество аутентификаций по IP.
	std::atomic< std::uint64_t > m_auth_by_ip_count{};
	//! Количество неудачных аутентификаций по IP.
	std::atomic< std::uint64_t > m_failed_auth_by_ip_count{};
	//! Общее количество аутентификаций по login/password.
	std::atomic< std::uint64_t > m_auth_by_login_count{};
	//! Количество неудачных аутентификаций по login/password.
	std::atomic< std::uint64_t > m_failed_auth_by_login_count{};

	//! Количество неудачных авторизаций из-за блокировки порта на
	//! целевом узле.
	std::atomic< std::uint64_t > m_failed_authorization_denied_port{};
};

//
// auth_stats_enumerator_t
//
class auth_stats_enumerator_t
{
public:
	enum class result_t
	{
		go_next,
		stop
	};

	static constexpr auto go_next = result_t::go_next;
	static constexpr auto stop = result_t::stop;

	auth_stats_enumerator_t();
	virtual ~auth_stats_enumerator_t();

	[[nodiscard]]
	virtual result_t
	on_next( const auth_stats_t & stats_object ) = 0;
};

namespace impl
{

//
// enumerator_from_lambda_t
//
template< typename Lambda >
class enumerator_from_lambda_t final : public auth_stats_enumerator_t
{
	Lambda m_lambda;

public:
	enumerator_from_lambda_t( Lambda lambda ) : m_lambda{ std::move(lambda) }
	{}

	[[nodiscard]]
	result_t
	on_next( const auth_stats_t & stats_object ) override
	{
		return m_lambda( stats_object );
	}
};

} /* namespace impl */

//
// lambda_as_enumerator
//
template< typename Lambda >
[[nodiscard]]
auto
lambda_as_enumerator( Lambda && lambda )
{
	using actual_lambda_type = std::decay_t<Lambda>;
	return impl::enumerator_from_lambda_t<actual_lambda_type>{
			std::forward<Lambda>(lambda)
		};
}

//
// auth_stats_reference_manager_t
//
/*!
 * @brief Интерфейс хранителя ссылок на объекты auth_stats_t.
 *
 * Объет auth_stats_t является собственностью агента authentificator.
 * Но ссылки на существующие auth_stats-объекты должны быть
 * доступны stats_collector-у. Для чего агент authentificator при начале
 * своей работы сохраняет ссылку на свой auth_stats-объект в
 * auth_stats_reference_manager. А перед уничтожением агент
 * authentificator уничтожает эту ссылку.
 */
class auth_stats_reference_manager_t
{
public:
	auth_stats_reference_manager_t();
	virtual ~auth_stats_reference_manager_t();

	// Объекты этого типа нельзя ни копировать, ни перемещать.
	auth_stats_reference_manager_t(
		const auth_stats_reference_manager_t & ) = delete;
	auth_stats_reference_manager_t(
		auth_stats_reference_manager_t && ) = delete;

	//! Добавить очередной auth_stats_t в хранилище.
	virtual void
	add( auth_stats_t & stats_object ) = 0;

	//! Изъять auth_stats_t из хранилища.
	virtual void
	remove( auth_stats_t & stats_object ) noexcept = 0;

	//! Пробежаться по всем элементам в хранилище.
	/*!
	 * Для обеспечения exception-safety хранилище будет заблокировано
	 * на время выполнения итерации. До тех пор пока enumerate не вернет
	 * управление вызовы add() и remove() будут блокировать вызывающую
	 * сторону. Поэтому делать вызовы add/remove внутри enumerate нельзя.
	 */
	virtual void
	enumerate( auth_stats_enumerator_t & enumerator ) = 0;
};

//
// auto_reg_t
//
/*!
 * @brief Вспомогательный класс для добавления и удаления ссылки
 * на auth_stats объект в auth_stats_reference_manager в стиле RAII.
 */
class auto_reg_t
{
	std::shared_ptr< auth_stats_reference_manager_t > m_manager;
	auth_stats_t & m_stats;

public:
	auto_reg_t(
		std::shared_ptr< auth_stats_reference_manager_t > manager,
		auth_stats_t & stats )
		:	m_manager{ std::move(manager) }
		,	m_stats{ stats }
	{
		m_manager->add( m_stats );
	}
	~auto_reg_t()
	{
		m_manager->remove( m_stats );
	}

	// Копирование и перемещение этих объектов запрещено.
	auto_reg_t( const auto_reg_t & ) = delete;
	auto_reg_t( auto_reg_t && ) = delete;
};

//
// make_std_auth_stats_reference_manager
//
[[nodiscard]]
std::shared_ptr< auth_stats_reference_manager_t >
make_std_auth_stats_reference_manager();

} /* namespace arataga::stats::auth */

