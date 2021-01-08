require 'mxx_ru/cpp'

MxxRu::Cpp::lib_target {

	target 'lib/fmt'

	include_path 'fmt/include', MxxRu::Cpp::Target::OPT_UPSPREAD

	sources_root( 'fmt' ) {
		cpp_source 'src/format.cc'
		cpp_source 'src/os.cc'
	}
}

