#!/usr/bin/ruby
require 'mxx_ru/cpp'

MxxRu::Cpp::composite_target( MxxRu::BUILD_ROOT ) {

	toolset.force_cpp17
	global_include_path '.'
	global_include_path './nodejs/http_parser'
	global_include_path './fmt/include'

	global_linker_option '-pthread'
	global_linker_option "-Wl,-rpath='$ORIGIN'"

	# If there is local options file then use it.
	if FileTest.exist?( "local-build.rb" )
		required_prj "local-build.rb"
	else
		global_obj_placement MxxRu::Cpp::PrjAwareRuntimeSubdirObjPlacement.new( 'target' )
		default_runtime_mode( MxxRu::Cpp::RUNTIME_RELEASE )
		MxxRu::enable_show_brief
	end

	required_prj 'arataga/prj.rb'
}

