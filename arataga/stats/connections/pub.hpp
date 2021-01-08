/*!
 * @file
 * @brief Средства для сбора статистики по подключениям.
 */

#pragma once

#include <atomic>
#include <cstdint>
#include <memory>

namespace arataga::stats::connections
{

//
// acl_stats_t
//
//! Статистика по одному ACL.
struct acl_stats_t
{
	//! Общее количество подключений.
	std::atomic< std::uint64_t > m_total_connections{};
	//! Количество подключений по протоколу HTTP.
	std::atomic< std::uint64_t > m_http_connections{};
	//! Количетсво подключений по протоколу SOCKS5.
	std::atomic< std::uint64_t > m_socks5_connections{};

	/*!
	 * @name Счетчики причин удаления connection-handler-ов.
	 * @{
	 */
	std::atomic< std::uint64_t > m_remove_reason_normal_completion{};
	std::atomic< std::uint64_t > m_remove_reason_io_error{};
	std::atomic< std::uint64_t > m_remove_reason_current_operation_timed_out{};
	std::atomic< std::uint64_t > m_remove_reason_unsupported_protocol{};
	std::atomic< std::uint64_t > m_remove_reason_protocol_error{};
	std::atomic< std::uint64_t > m_remove_reason_unexpected_error{};
	std::atomic< std::uint64_t > m_remove_reason_no_activity_for_too_long{};
	std::atomic< std::uint64_t > m_remove_reason_current_operation_canceled{};
	std::atomic< std::uint64_t > m_remove_reason_unhandled_exception{};
	std::atomic< std::uint64_t > m_remove_reason_ip_version_mismatch{};
	std::atomic< std::uint64_t > m_remove_reason_access_denied{};
	std::atomic< std::uint64_t > m_remove_reason_unresolved_target{};
	std::atomic< std::uint64_t > m_remove_reason_target_end_broken{};
	std::atomic< std::uint64_t > m_remove_reason_user_end_broken{};
	std::atomic< std::uint64_t > m_remove_reason_early_http_response{};
	std::atomic< std::uint64_t > m_remove_reason_user_end_closed_by_client{};
	std::atomic< std::uint64_t > m_remove_reason_http_no_incoming_request{};
	/*!
	 * @}
	 */
};

//
// acl_stats_enumerator_t
//
class acl_stats_enumerator_t
{
public:
	enum class result_t
	{
		go_next,
		stop
	};

	static constexpr auto go_next = result_t::go_next;
	static constexpr auto stop = result_t::stop;

	acl_stats_enumerator_t();
	virtual ~acl_stats_enumerator_t();

	[[nodiscard]]
	virtual result_t
	on_next( const acl_stats_t & stats_object ) = 0;
};

namespace impl
{

//
// enumerator_from_lambda_t
//
template< typename Lambda >
class enumerator_from_lambda_t final : public acl_stats_enumerator_t
{
	Lambda m_lambda;

public:
	enumerator_from_lambda_t( Lambda lambda ) : m_lambda{ std::move(lambda) }
	{}

	[[nodiscard]]
	result_t
	on_next( const acl_stats_t & stats_object ) override
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
// acl_stats_reference_manager_t
//
/*!
 * @brief Интерфейс хранителя ссылок на объекты acl_stats_t.
 *
 * Объет acl_stats_t является собственностью обработчика ACL.
 * Но ссылки на существующие acl_stats-объекты должны быть
 * доступны stats_collector-у. Для чего ACL-handler при начале
 * своей работы сохраняет ссылку на свой acl_stats-объект в
 * acl_stats_reference_manager. А перед уничтожением ACL-handler
 * уничтожает эту ссылку.
 */
class acl_stats_reference_manager_t
{
public:
	acl_stats_reference_manager_t();
	virtual ~acl_stats_reference_manager_t();

	// Объекты этого типа нельзя ни копировать, ни перемещать.
	acl_stats_reference_manager_t(
		const acl_stats_reference_manager_t & ) = delete;
	acl_stats_reference_manager_t(
		acl_stats_reference_manager_t && ) = delete;

	//! Добавить очередной acl_stats_t в хранилище.
	virtual void
	add( acl_stats_t & stats_object ) = 0;

	//! Изъять acl_stats_t из хранилища.
	virtual void
	remove( acl_stats_t & stats_object ) noexcept = 0;

	//! Пробежаться по всем элементам в хранилище.
	/*!
	 * Для обеспечения exception-safety хранилище будет заблокировано
	 * на время выполнения итерации. До тех пор пока enumerate не вернет
	 * управление вызовы add() и remove() будут блокировать вызывающую
	 * сторону. Поэтому делать вызовы add/remove внутри enumerate нельзя.
	 */
	virtual void
	enumerate( acl_stats_enumerator_t & enumerator ) = 0;
};

//
// auto_reg_t
//
/*!
 * @brief Вспомогательный класс для добавления и удаления ссылки
 * на acl_stats объект в acl_stats_reference_manager в стиле RAII.
 */
class auto_reg_t
{
	std::shared_ptr< acl_stats_reference_manager_t > m_manager;
	acl_stats_t & m_stats;

public:
	auto_reg_t(
		std::shared_ptr< acl_stats_reference_manager_t > manager,
		acl_stats_t & stats )
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
// make_std_acl_stats_reference_manager
//
[[nodiscard]]
std::shared_ptr< acl_stats_reference_manager_t >
make_std_acl_stats_reference_manager();

} /* namespace arataga::stats::connections */

