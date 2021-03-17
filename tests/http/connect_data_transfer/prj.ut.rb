require 'mxx_ru/binary_unittest'

path = 'tests/http/connect_data_transfer'

MxxRu::setup_target(
	MxxRu::BinaryUnittestTarget.new( "#{path}/prj.ut.rb", "#{path}/prj.rb" )
)

