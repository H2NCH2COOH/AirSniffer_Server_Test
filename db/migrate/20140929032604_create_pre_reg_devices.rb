class CreatePreRegDevices < ActiveRecord::Migration
  def change
    create_table :pre_reg_devices do |t|
      t.string :dev_id
      t.string :feed_id
      t.string :api_key
    end
  end
end
