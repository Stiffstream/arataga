require 'mxx_ru/cpp'

MxxRu::Cpp::exe_target {

	target 'test-bin/ut_config_parser'

	required_prj 'arataga/config.rb'

	cpp_source 'main.cpp'
}

