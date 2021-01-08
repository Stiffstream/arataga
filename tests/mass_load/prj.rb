require 'mxx_ru/cpp'

MxxRu::Cpp::exe_target {

	target 'test-bin/mass_load'

	required_prj 'fmt-prj.rb'
	required_prj 'asio-prj.rb'

	required_prj 'restinio/platform_specific_libs.rb'

	cpp_source 'main.cpp'
}

