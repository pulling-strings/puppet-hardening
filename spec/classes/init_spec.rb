require 'spec_helper'
describe 'hardening' do

  context 'with defaults for all parameters' do
    it { should contain_class('hardening') }
  end
end
