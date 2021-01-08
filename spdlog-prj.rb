require 'mxx_ru/cpp'

MxxRu::Cpp::lib_target {

	target 'lib/spdlog'

	define 'SPDLOG_COMPILED_LIB', MxxRu::Cpp::Target::OPT_UPSPREAD
	define 'SPDLOG_FMT_EXTERNAL', MxxRu::Cpp::Target::OPT_UPSPREAD

	include_path 'spdlog/include', MxxRu::Cpp::Target::OPT_UPSPREAD

	sources_root( 'spdlog' ) {
		cpp_source 'src/spdlog.cpp'
		cpp_source 'src/stdout_sinks.cpp'
		cpp_source 'src/color_sinks.cpp'
		cpp_source 'src/file_sinks.cpp'
		cpp_source 'src/async.cpp'
		cpp_source 'src/fmt.cpp'
	}
}

