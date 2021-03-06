class PreRegDevice < ActiveRecord::Base
end

class AddLastRetrieveTimeToPreRegDevices < ActiveRecord::Migration
  def change
    add_column :pre_reg_devices, :last_retrieve_time, :string
    
    t=Time.now.utc
    
    PreRegDevice.find_each do |dev|
      dev.last_retrieve_time=t.strftime '%FT%RZ'
      dev.save
    end
    
    PreRegDevice.find_each do |dev|
      data=[]
      endT=t
      sixH=6*60*60
      maxH=300*24
      
      for i in 0..(maxH/6) do
        url="http://api.xively.com/v2/feeds/#{dev.feed_id}/datastreams/PM25?duration=6hour&interval=0&end=#{endT.strftime '%FT%RZ'}"
        url=URI.encode url
        url=URI.parse url
        req=Net::HTTP::Get.new url.to_s
        req["X-ApiKey"]=dev.api_key
        res=Net::HTTP.start(url.host, url.port){|http|http.request req}
        j=JSON.parse res.body
        
        break unless j.has_key? 'datapoints'
        
        td=[]
        j['datapoints'].each do |d|
          v=d['value']
          t=d['at']
          x=DateTime.strptime t, '%FT%T.%LZ'
          td<<[x.to_time.to_i*1000, v.to_i]
        end
        data=td.concat data
        endT-=sixH
      end
      
      File.open(Rails.root.join('device_history', dev.dev_id), 'w') do |f|
        data.each do |p|
          f.write "[#{p[0]},#{p[1]}],"
        end
      end
    end
  end
end
