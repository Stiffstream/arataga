/*!
 * @file
 * @brief Вспомогательная функция для поиска адреса нужного типа из списка.
 */

#pragma once

#include <arataga/dns_resolver/pub.hpp>
#include <arataga/exception.hpp>

namespace arataga::dns_resolver
{

/*!
 * @brief Функция, позоляющая выбрать из списка IP адрес необходимой версии.
 *
 * \note Возвращается первый попавшийся адрес соответствующей версии.
 * \note Если нужен IPv6 адрес, и до конца списка его не нашли, то в итоге
 * конвиртируется в IPv6 первый адрес IPv4.
 *
 * @param list Список с адресами
 * @param ip_version Версия IP.
 * @param address_extractor Функтор, позволяющий извлечь адрес из элемента списка.
 * @return asio::ip::address Адрес с нужной версией IP.
 * @return std::nullopt Если не удалось произвести конвертацию к адресу
 * нужной версии.
 */
template <typename List, typename Extractor>
std::optional<asio::ip::address>
resolve_address_from_list(
	const List & list,
	ip_version_t ip_version,
	Extractor && address_extractor )
{
	for( const auto & element: list )
	{
		const auto & address = address_extractor(element);
		if( address.is_v4() && ip_version == ip_version_t::ip_v4 )
		{
			return address;
		}

		if( address.is_v6() && ip_version == ip_version_t::ip_v6 )
		{
			return address;
		}
	}
	/*
		Если оказались здесь, значит не нашли адрес искомой версии.
		А значит нужно произвести конвертацию адреса имеющейся версии.
	*/
	if( ip_version == ip_version_t::ip_v6 )
	{
		return asio::ip::make_address_v6(
			asio::ip::v4_mapped,
			address_extractor( *(list.begin()) ).to_v4() );
	}
	else
	{
		// Вероятнее всего корректно преобразовать IPv6->IPv4
		// не получится, а значит просто вернем пустой результат.
		return std::nullopt;
	}
}

/*!
 * @brief Получить результат разрешения имени для определенной версии IP.
 *
 * @param list Результаты разрешения имени, пришедшие от DNS-сервера.
 * @param ip_version Версия IP-адреса: IPv4 или IPv6.
 * @param address_extractor Функция, позволяющая извлечь адрес из
 * объекта-результата разрешения имени.
 */
template <typename List, typename Extractor>
forward::resolve_result_t
get_resolve_result(
	const List & list,
	ip_version_t ip_version,
	Extractor && address_extractor )
{
	forward::resolve_result_t result;

	auto address = resolve_address_from_list(
		list,
		std::move(ip_version),
		std::move(address_extractor) );

	if(address)
		result = forward::successful_resolve_t
			{
				*address
			};
	else
		result = forward::failed_resolve_t
			{
				"address with required IP version was not found"
			};

	return result;
}

} /* namespace arataga::dns_resolver */
