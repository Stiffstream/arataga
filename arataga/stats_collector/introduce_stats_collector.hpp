/*!
 * @file
 * @brief Инструменты для создания агента stats_collector.
 */

#pragma once

#include <arataga/application_context.hpp>

namespace arataga::stats_collector
{

//
// params_t
//
/*!
 * @brief Параметры, необходимые агенту для начала его работы.
 *
 * @note
 * На данный момент это пустая структура, но она добавлена для того,
 * чтобы впоследствии можно было легко добавлять новые параметры для
 * агента stats_collector.
 */
struct params_t
{
};

//
// introduce_stats_collector
//
/*!
 * @brief Функция для создания и запуска агента stats_collector в
 * указанном SObjectizer Environment с привязкой к указанному диспетчеру.
 */
void
introduce_stats_collector(
	//! SObjectizer Environment, в котором нужно работать.
	so_5::environment_t & env,
	//! Родительская кооперация.
	so_5::coop_handle_t parent_coop,
	//! Диспетчер, к которому должен быть привязан новый агент.
	so_5::disp_binder_shptr_t disp_binder,
	//! Контекст всего arataga.
	application_context_t app_ctx,
	//! Индивидуальные параметры для нового агента.
	params_t params );

} /* namespace arataga::stats_collector */

