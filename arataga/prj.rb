require 'mxx_ru/cpp'

MxxRu::Cpp::exe_target {

	target 'bin/arataga'

	required_prj 'spdlog-prj.rb'
	required_prj 'fmt-prj.rb'
	required_prj 'asio-prj.rb'

	required_prj 'so_5/prj_s.rb'
	required_prj 'nodejs/http_parser_mxxru/prj.rb'
	required_prj 'restinio/platform_specific_libs.rb'

	required_prj 'arataga/stats/prj.rb'
	required_prj 'arataga/config.rb'
	required_prj 'arataga/logging/logging.rb'
	required_prj 'arataga/user_list_auth_data.rb'
	required_prj 'arataga/acl_handler/connection_handlers.rb'

	lib 'stdc++fs'

	cpp_source 'admin_http_entry/pub.cpp'

	cpp_source 'stats_collector/a_stats_collector.cpp'
	cpp_source 'authentificator/a_authentificator.cpp'

	cpp_source 'dns_resolver/interactor/a_nameserver_interactor.cpp'
	cpp_source 'dns_resolver/a_dns_resolver.cpp'

	cpp_source 'acl_handler/bandlim_manager.cpp'
	cpp_source 'acl_handler/a_handler.cpp'

	cpp_source 'user_list_processor/a_processor.cpp'
	cpp_source 'config_processor/a_processor.cpp'
	cpp_source 'startup_manager/a_manager.cpp'

	cpp_source 'main.cpp'
}

