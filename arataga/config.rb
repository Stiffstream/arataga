require 'mxx_ru/cpp'

MxxRu::Cpp::lib_target {

	target 'lib/config'

	required_prj 'fmt-prj.rb'
	required_prj 'spdlog-prj.rb'
	required_prj 'asio-prj.rb'

	cpp_source 'config.cpp'
}

