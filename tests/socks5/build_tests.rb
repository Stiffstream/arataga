gem 'Mxx_ru', '>=1.6.4'

require 'mxx_ru/cpp'

MxxRu::Cpp::composite_target {

	path = 'tests/socks5'

	required_prj "#{path}/illegal_first_pdu/prj.ut.rb"
	required_prj "#{path}/username_password_auth/prj.ut.rb"
	required_prj "#{path}/command_pdu/prj.ut.rb"
	required_prj "#{path}/bind_pdu/prj.ut.rb"
}

