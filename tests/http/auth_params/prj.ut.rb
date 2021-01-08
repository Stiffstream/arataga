require 'mxx_ru/binary_unittest'

path = 'tests/http/auth_params'

MxxRu::setup_target(
	MxxRu::BinaryUnittestTarget.new( "#{path}/prj.ut.rb", "#{path}/prj.rb" )
)

