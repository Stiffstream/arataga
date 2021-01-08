require 'mxx_ru/binary_unittest'

path = 'tests/socks5/username_password_auth'

MxxRu::setup_target(
	MxxRu::BinaryUnittestTarget.new( "#{path}/prj.ut.rb", "#{path}/prj.rb" )
)

