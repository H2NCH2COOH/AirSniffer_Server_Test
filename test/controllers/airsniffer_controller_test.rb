require 'test_helper'

class AirsnifferControllerTest < ActionController::TestCase
  test "should get wxhandler" do
    get :wxhandler
    assert_response :success
  end

end
