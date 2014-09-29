class CreateDevices < ActiveRecord::Migration
  def change
    create_table :devices do |t|
      t.string :dev_id
      t.string :feed_id
      t.string :api_key
      t.string :owner
      t.string :name
    end
  end
end
