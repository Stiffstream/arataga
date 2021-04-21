/*!
 * @file
 * @brief The public part of dns_resolver-agent's interface.
 */

#include <arataga/dns_resolver/pub.hpp>

#include <arataga/dns_resolver/interactor/pub.hpp>

#include <arataga/dns_resolver/lookup_conductor/pub.hpp>

namespace arataga::dns_resolver
{

//
// introduce_dns_resolver
//
std::tuple< so_5::coop_handle_t, so_5::mbox_t >
introduce_dns_resolver(
	so_5::environment_t & env,
	so_5::coop_handle_t parent_coop,
	so_5::disp_binder_shptr_t disp_binder,
	application_context_t app_ctx,
	params_t params )
{
	// We need MPMC mbox for incoming requests.
	auto dns_mbox = env.create_mbox();

	auto coop_holder = env.make_coop( parent_coop, std::move(disp_binder) );

	auto interactor_mbox = interactor::add_interactor_to_coop(
			*coop_holder,
			interactor::params_t{
					params.m_io_ctx,
					params.m_name + ".interactor"
			} );

	lookup_conductor::add_lookup_conductors_to_coop(
			*coop_holder,
			std::move(app_ctx),
			params.m_name + ".conductor",
			dns_mbox,
			interactor_mbox );

	auto h_coop = env.register_coop( std::move(coop_holder) );

	return { std::move(h_coop), std::move(dns_mbox) };
}

} /* namespace arataga::dns_resolver */

