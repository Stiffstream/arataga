require 'mxx_ru/cpp'

MxxRu::Cpp::lib_target {

	target 'lib/stats'

	required_prj 'fmt-prj.rb'

	cpp_source 'auth/pub.cpp'
	cpp_source 'connections/pub.cpp'
	cpp_source 'dns/pub.cpp'
}

