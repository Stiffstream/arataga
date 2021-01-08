require 'mxx_ru/binary_unittest'

path = 'tests/local_user_list_data'

MxxRu::setup_target(
	MxxRu::BinaryUnittestTarget.new( "#{path}/prj.ut.rb", "#{path}/prj.rb" )
)

