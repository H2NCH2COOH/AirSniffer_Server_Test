class Device < ActiveRecord::Base
end

class PreRegDevice < ActiveRecord::Base
end

class SwitchToCustomDeviceService < ActiveRecord::Migration
  def change
    remove_column :pre_reg_devices, :feed_id
    remove_column :pre_reg_devices, :api_key
    remove_column :pre_reg_devices, :last_retrieve_time
    
    remove_column :devices, :feed_id
    remove_column :devices, :api_key
    add_column :devices, :unit_type, :string
  end
end
