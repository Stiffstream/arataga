gem 'Mxx_ru', '>=1.6.4'

require 'mxx_ru/cpp'

MxxRu::Cpp::composite_target {

	path = 'tests/http'

	required_prj "#{path}/http_fields/prj.ut.rb"
	required_prj "#{path}/auth_params/prj.ut.rb"
	required_prj "#{path}/chunked_encoding/prj.ut.rb"
	required_prj "#{path}/illegal_responses/prj.ut.rb"
	required_prj "#{path}/connect_data_transfer/prj.ut.rb"
}

