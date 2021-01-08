require 'mxx_ru/cpp'

MxxRu::Cpp::lib_target {

	target 'lib/logging'

	required_prj 'fmt-prj.rb'
	required_prj 'spdlog-prj.rb'

   cpp_source 'stats_counters.cpp'
   cpp_source 'wrap_logging.cpp'
}

