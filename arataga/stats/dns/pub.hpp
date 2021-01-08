/*!
 * @file
 * @brief Средства для сбора статистики по DNS.
 */

#pragma once

#include <atomic>
#include <cstdint>
#include <memory>

namespace arataga::stats::dns
{

//
// dns_stats_t
//
//! Статистика по одному агенту-dns_resolver-у.
struct dns_stats_t
{
	//! Количество попаданий в кэш.
	std::atomic< std::uint64_t > m_dns_cache_hits{};
	//! Количество успешных операций DNS lookup.
	std::atomic< std::uint64_t > m_dns_successful_lookups{};
	//! Количество неудачных операций DNS lookup.
	std::atomic< std::uint64_t > m_dns_failed_lookups{};
};

//
// dns_stats_enumerator_t
//
class dns_stats_enumerator_t
{
public:
	enum class result_t
	{
		go_next,
		stop
	};

	static constexpr auto go_next = result_t::go_next;
	static constexpr auto stop = result_t::stop;

	dns_stats_enumerator_t();
	virtual ~dns_stats_enumerator_t();

	[[nodiscard]]
	virtual result_t
	on_next( const dns_stats_t & stats_object ) = 0;
};

namespace impl
{

//
// enumerator_from_lambda_t
//
template< typename Lambda >
class enumerator_from_lambda_t final : public dns_stats_enumerator_t
{
	Lambda m_lambda;

public:
	enumerator_from_lambda_t( Lambda lambda ) : m_lambda{ std::move(lambda) }
	{}

	[[nodiscard]]
	result_t
	on_next( const dns_stats_t & stats_object ) override
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
// dns_stats_reference_manager_t
//
/*!
 * @brief Интерфейс хранителя ссылок на объекты dns_stats_t.
 *
 * Объет dns_stats_t является собственностью агента dns_resolver.
 * Но ссылки на существующие dns_stats-объекты должны быть
 * доступны stats_collector-у. Для чего агент dns_resolver при начале
 * своей работы сохраняет ссылку на свой dns_stats-объект в
 * dns_stats_reference_manager. А перед уничтожением агент
 * dns_resolver уничтожает эту ссылку.
 */
class dns_stats_reference_manager_t
{
public:
	dns_stats_reference_manager_t();
	virtual ~dns_stats_reference_manager_t();

	// Объекты этого типа нельзя ни копировать, ни перемещать.
	dns_stats_reference_manager_t(
		const dns_stats_reference_manager_t & ) = delete;
	dns_stats_reference_manager_t(
		dns_stats_reference_manager_t && ) = delete;

	//! Добавить очередной auth_stats_t в хранилище.
	virtual void
	add( dns_stats_t & stats_object ) = 0;

	//! Изъять auth_stats_t из хранилища.
	virtual void
	remove( dns_stats_t & stats_object ) noexcept = 0;

	//! Пробежаться по всем элементам в хранилище.
	/*!
	 * Для обеспечения exception-safety хранилище будет заблокировано
	 * на время выполнения итерации. До тех пор пока enumerate не вернет
	 * управление вызовы add() и remove() будут блокировать вызывающую
	 * сторону. Поэтому делать вызовы add/remove внутри enumerate нельзя.
	 */
	virtual void
	enumerate( dns_stats_enumerator_t & enumerator ) = 0;
};

//
// auto_reg_t
//
/*!
 * @brief Вспомогательный класс для добавления и удаления ссылки
 * на dns_stats объект в dns_stats_reference_manager в стиле RAII.
 */
class auto_reg_t
{
	std::shared_ptr< dns_stats_reference_manager_t > m_manager;
	dns_stats_t & m_stats;

public:
	auto_reg_t(
		std::shared_ptr< dns_stats_reference_manager_t > manager,
		dns_stats_t & stats )
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
// make_std_dns_stats_reference_manager
//
[[nodiscard]]
std::shared_ptr< dns_stats_reference_manager_t >
make_std_dns_stats_reference_manager();

} /* namespace arataga::stats::auth */

