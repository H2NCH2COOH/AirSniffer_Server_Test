require 'digest/sha1'
require 'rexml/document'
require 'net/http'
require 'json'
require 'lazy_high_charts'
require 'openssl'
require 'mail'
#=============================================================================#
#Mail setup
options = { :address              => "smtp.gmail.com",
            :port                 => 587,
            #:domain               => 'your.host.name',
            :user_name            => 'wzypublic@gmail.com',
            :password             => 'zhiyuanwd',
            :authentication       => 'plain',
            :enable_starttls_auto => true
}

Mail.defaults do
  delivery_method :smtp, options
end
#=============================================================================#
class Device < ActiveRecord::Base
end

class PreRegDevice < ActiveRecord::Base
end

class AirsnifferController < ApplicationController
  TOKEN='AirSniffer'
  KEY='7328956043759284757545839'
  XIVELY_PRODUCT_ID='ioV3xb4qcXATBqOZXccU'
  XIVELY_PRODUCT_SECRET='c71390d4339d6b2f4dc0c700e961f3da1e90c145'
  XIVELY_MASTER_KEY='4tE9zx1Hezmm2rUhrkBsncOGfGmssYTn5VBli3yc9qifzjKB'
  
  def send_admin_email(content, to=nil)
    to='wzypublic@gmail.com' if to.nil?
    
    Mail.deliver do
      to to
      from 'Air Sniffer Server Report <wzypublic@gmail.com>'
      subject 'Air Sniffer Server Report'
      body content
    end
  end
  
  def test_req
    render plain: "Test"
  end
  
  def pre_registered_dev
    id=params[:id]
    key=params[:key]
    
    if id.nil? or key.nil? or key!=KEY
      render plain: 'args error!'
      return
    end
    
    p=PreRegDevice.find_by dev_id: id
    if p.nil?
      ret='Device not found'
    else
      ret="{\"dev_id\"=\"#{p.dev_id}\",\"feed_id\"=\"#{p.feed_id}\",\"api_key\"=\"#{p.api_key}\"}"
    end
    
    render plain: ret
  end
  
  def delete_device
    id=params[:id]
    key=params[:key]

    if id.nil? or key.nil? or key!=KEY
      render plain: 'ARG ERROR!'
      return
    end

    PreRegDevice.where(dev_id: id).each{|d|d.destroy}
    render plain: "Device: #{id} deleted"
  end

  def pre_register
    id=params[:id]
    key=params[:key]
       
    if id.nil? or key.nil? or key!=KEY
      render plain: 'ARG ERROR!'
      return
    end
    
    begin
      dev=PreRegDevice.find_by dev_id: id
      if dev
        render plain: "Device: #{id} already exist"
        return
      end
      
      url="http://api.xively.com/v2/products/#{XIVELY_PRODUCT_ID}/devices"
      url=URI.encode url
      url=URI.parse url
      req=Net::HTTP::Post.new url.to_s
      req['X-ApiKey']=XIVELY_MASTER_KEY
      req.body="{\"devices\":[{\"serial\":\"#{id}\"}]}"
      res=Net::HTTP.start(url.host, url.port){|http|http.request req}
      
      unless res.kind_of? Net::HTTPCreated
        render plain: "Creating new device on xively failed with #{res.code}\n#{res.body}"
        return
      end
      
      digest=OpenSSL::Digest::Digest.new 'sha1'
      activation_code=OpenSSL::HMAC.hexdigest digest, [XIVELY_PRODUCT_SECRET].pack("H*"), id
      
      url="http://api.xively.com/v2/devices/#{activation_code}/activate"
      url=URI.encode url
      url=URI.parse url
      req=Net::HTTP::Get.new url.to_s
      res=Net::HTTP.start(url.host, url.port){|http|http.request req}
      j=JSON.parse res.body
      
      PreRegDevice.create dev_id: id, feed_id: j['feed_id'], api_key: j['apikey'], last_retrieve_time: nil
      
      render plain: JSON.dump(dev_id: id, feed_id: j['feed_id'], api_key: j['apikey'])
    rescue Exception=>e
      logger.error '[Exception]: '+e.to_s
      render plain: 'Error in pre-registration'
    end
  end
  
  def wxhandler
    body=request.body.read
    puts body
    
    doc=REXML::Document.new body
    
    @myId=REXML::XPath.first(doc, '/xml/ToUserName').text
    @uId=REXML::XPath.first(doc, '/xml/FromUserName').text
    msgType=REXML::XPath.first(doc, '/xml/MsgType').text
    
    @devs=Device.where owner: @uId
    
    if msgType.eql? 'text'
      content=REXML::XPath.first(doc, '/xml/Content').text
      ret=text_msg_handler content
      render plain: ret
    else
      #DO Nothing
      render plain: ''
    end
  end
  
  def wxhandler_get
    ret=check_wx_sig
    render plain: ret
  end
  
  def check_wx_sig
    sig=params[:signature]
    time=params[:timestamp]
    nonce=params[:nonce]
    echo=params[:echostr]
    
    if sig.nil? or time.nil? or nonce.nil? or echo.nil?
      return 'ERROR!'
    end
    
    array=[TOKEN, time, nonce].sort
    str=array.join
    hash=Digest::SHA1.hexdigest str
    if hash.eql? sig
      return echo
    else
      return 'ERROR!'
    end
  end
  
  def wx_text_responce_builder text
    time=Time.now.to_i
    
    res=<<-eos
<xml>
  <ToUserName><![CDATA[#{@uId}]]></ToUserName>
  <FromUserName><![CDATA[#{@myId}]]></FromUserName>
  <CreateTime>#{time}</CreateTime>
  <MsgType><![CDATA[text]]></MsgType>
  <Content><![CDATA[#{text}]]></Content>
</xml>
    eos
    
    return res
  end
  
  def wx_article_responce_builder(articles)
    time=Time.now.to_i
    
    items=''
    articles.each do |a|
      items+=<<-eos
    <item>
      <Title><![CDATA[#{a[:text]}]]></Title> 
      #{"<PicUrl><![CDATA[#{a[:pic]}]]></PicUrl>" if a[:pic]}
      <Url><![CDATA[#{a[:url]}]]></Url>
    </item>
    
      eos
    end
    
    res=<<-eos
<xml>
  <ToUserName><![CDATA[#{@uId}]]></ToUserName>
  <FromUserName><![CDATA[#{@myId}]]></FromUserName>
  <CreateTime>#{time}</CreateTime>
  <MsgType><![CDATA[news]]></MsgType>
  <ArticleCount>#{articles.size}</ArticleCount>
  <Articles>
#{items}
  </Articles>
</xml>
    eos
    
    return res
  end
  
  def get_all_datapoints(pdev)
    data=[]
    begin
      c=''
      if Rails.root.join('device_history', pdev.dev_id).exist?
        File.open(Rails.root.join('device_history', pdev.dev_id), 'r') do |f|
          c=f.read
        end
      end
      c.rstrip!
      c.insert 0, '['
      if c.end_with? ','
        c[-1]=']'
      else
        c<<']'
      end
      
      j=JSON.parse c
      j.each do |d|
        data<<[d[0],d[1]]
      end
      if pdev.last_retrieve_time.nil?
        url="http://api.xively.com/v2/feeds/#{pdev.feed_id}/datastreams/PM25?&interval=0&duration=4hour"
      else
        url="http://api.xively.com/v2/feeds/#{pdev.feed_id}/datastreams/PM25?&interval=0&duration=4hour&start=#{pdev.last_retrieve_time}"
      end
      url=URI.encode url
      url=URI.parse url
      req=Net::HTTP::Get.new url.to_s
      req["X-ApiKey"]=pdev.api_key
      res=Net::HTTP.start(url.host, url.port){|http|http.request req}
      j=JSON.parse res.body
      
      if j.has_key? 'datapoints'
        j['datapoints'].each do |d|
          v=d['value']
          t=d['at']
          x=DateTime.strptime t, '%FT%T.%LZ'
          data<<[x.to_time.to_i*1000, v.to_i]
        end
      end
      
      data_interval=5*60*1000
      gap_limit=1000*1000
      if data.size>0
        i=0
        tEnd=Time.now.utc.to_i*1000
        while data[i][0]<tEnd-gap_limit
          if data[i+1].nil?
            data<<[data[i][0]+data_interval, 0]
            data<<[tEnd, 0]
            break
          else
            if data[i+1][0]-data[i][0]>gap_limit
              data.insert i+1, [data[i][0]+data_interval, 0]
              i+=1
              data.insert i+1, [data[i+1][0]-data_interval, 0]
              i+=2
            else
              i+=1
            end
          end
        end
      end
    rescue Exception=>e
      logger.error '[Exception] '+e.to_s
    end
    
    return data
  end
  
  def multichart
    ids=[]
    for i in 1..10
      if params.has_key? i.to_s
        did=params[i.to_s]
        ids<<did if did.size>0
      else
        break
      end
    end
    
    if ids.size==0
      render plain: 'Need at least 1 id'
      return
    end
    
    uid=params[:uid]
    if uid.nil?
      render plain: 'Need uid'
      return
    end
    
    use_admin=false
    if uid=='admin'
      key=params[:key]
      if key.nil? or key!=KEY
        render plain: 'ARG ERROR!'
        return
      end
      use_admin=true
    end
    
    devs=[]
    ids.each do |id|
      pdev=PreRegDevice.find_by dev_id: id
      next if pdev.nil?
      
      name=''
      if use_admin
        name="#{pdev.dev_id}"
      else
        dev=Device.find_by dev_id: id, owner: uid
        if dev.nil?
          next
        end
        name=dev.name
      end

      data=get_all_datapoints pdev
      
      devs<<[name, data] if data.size>0
    end
       
    @dataCount=0
    @chart=LazyHighCharts::HighChart.new('graph') do |f|
      f.xAxis({
        ordinal: false,
        dateTimeLabelFormats: {
          minute: '%H:%M',
          hour: '%H:%M',
          day: '%b %e',
          week: '%b %e',
          month: '%Y %b',
          year: '%Y'
        },
        labels: {
          style: {
            fontSize: '150%'
          },
          step: 3,
          rotation: 45
        }
      })
      
      f.yAxis min: 0 
      
      f.rangeSelector(
        buttons: [
          {type: 'day', count: 1, text: '1天'},
          {type: 'week', count: 1, text: '1周'},
          {type: 'month', count: 1, text: '1月'}
        ],
        selected: 0
      )
      
      f.tooltip({
        valueDecimals: 0
      })
      
      devs.each do |p|
        f.series name: p[0], data: p[1]
      end
      
      f.legend({
        enabled: true,
        itemStyle: {fontSize: '200%'},
      })
    end
    
    render 'chart'
  end
  
  def chart
    id=params[:id]
    uid=params[:uid]
    
    if id.nil? or uid.nil?
      redirect_to '/404'
      return
    end
    
    begin
      pdev=PreRegDevice.find_by dev_id: id
      if pdev.nil?
        render plain: 'Device not found'
        return
      end

      name=''
      if uid=='admin'
        key=params[:key]
        if key.nil? or key!=KEY
          render plain: 'ARG ERROR!'
          return
        end
        name="Device: #{pdev.dev_id}"
      else
        dev=Device.find_by dev_id: id, owner: uid
        if dev.nil?
          render plain: 'Device not found'
          return
        end
        name=dev.name
      end
      
      data=get_all_datapoints pdev
      
      @dataCount=data.size
      @chart=LazyHighCharts::HighChart.new('graph') do |f|
        f.title({
          text: name,
          floating: true,
          style: {
            fontSize: '200%'
          }
        })
        f.xAxis({
          ordinal: false,
          dateTimeLabelFormats: {
            minute: '%H:%M',
            hour: '%H:%M',
            day: '%b %e',
            week: '%b %e',
            month: '%Y %b',
            year: '%Y'
          },
          labels: {
            style: {
              fontSize: '150%'
            },
            step: 3,
            rotation: 45
          }
        })
        f.yAxis min: 0 
        f.rangeSelector(
          buttons: [
            {type: 'day', count: 1, text: '1天'},
            {type: 'week', count: 1, text: '1周'},
            {type: 'month', count: 1, text: '1月'}
          ],
          selected: 0
        )
        f.tooltip({
          valueDecimals: 0
        })
        f.series name: "PM2.5", data: data
      end
    rescue Exception=>e
      logger.error '[Exception] '+e.to_s
      render plain: '出错，请稍后重试'
    end
  end
  
  def force_retrieve
    id=params[:id]
    duration=params[:duration]
    key=params[:key]
    
    if (id.nil? or duration.nil? or key.nil?) and not key.eql? KEY
      render plain: 'ARG ERROR!'
      return
    end
    
    ret=''
    begin
      dev=PreRegDevice.find_by dev_id: id
      if dev.nil?
        render plain: "Device not found!"
        return
      end

      data=[]
      endT=Time.now.utc
      sixH=6*60*60
      maxH=duration.to_i*24
        
      (maxH/6).times do
        url="http://api.xively.com/v2/feeds/#{dev.feed_id}/datastreams/PM25?duration=6hour&interval=0&end=#{endT.strftime '%FT%RZ'}"
        url=URI.encode url
        url=URI.parse url
        req=Net::HTTP::Get.new url.to_s
        req["X-ApiKey"]=dev.api_key
        res=Net::HTTP.start(url.host, url.port){|http|http.request req}
        j=JSON.parse res.body
        #ret+="Retrieve data end=#{endT.strftime '%FT%RZ'} #{j.inspect}\n"
        endT-=sixH
        next unless j.has_key? 'datapoints'
        
        td=[]
        j['datapoints'].each do |d|
          v=d['value']
          t=d['at']
          x=DateTime.strptime t, '%FT%T.%LZ'
          td<<[x.to_time.to_i*1000, v.to_i]
        end
        data=td.concat data
      end
        
      File.open(Rails.root.join('device_history', dev.dev_id), 'w') do |f|
        data.each do |p|
          f.write "[#{p[0]},#{p[1]}],"
        end
      end
      
      ret+="#{data.size} data points retrieved for device_id: #{dev.dev_id}\n"
    rescue Exception=>e
      ret+="Exception when retrieving data points for device_id: #{dev.dev_id}\n\t#{e.to_s}\n"
    ensure
      if dev
        dev.last_retrieve_time=Time.now.utc.strftime '%FT%RZ'
        dev.save
      end
    end
    render plain: ret
  end
  
  def data_retrieve
    ret="[#{Time.now.to_s}]\n"
    PreRegDevice.find_each do |dev|
      times=0
      lastRetrieveTime=dev.last_retrieve_time
      dev.last_retrieve_time=Time.now.utc.strftime '%FT%RZ'
      dev.save
      begin
        data=[]
        if dev.last_retrieve_time.nil?
          url="http://api.xively.com/v2/feeds/#{dev.feed_id}/datastreams/PM25?&interval=0&duration=4hour}"
        else
          url="http://api.xively.com/v2/feeds/#{dev.feed_id}/datastreams/PM25?&interval=0&duration=4hour&start=#{lastRetrieveTime}"
        end
        url=URI.encode url
        url=URI.parse url
        req=Net::HTTP::Get.new url.to_s
        req["X-ApiKey"]=dev.api_key
        res=Net::HTTP.start(url.host, url.port){|http|http.request req}
        j=JSON.parse res.body
        unless j.has_key? 'datapoints'
          ret+="0 data points retrieved for device_id: #{dev.dev_id}\n"
          next
        end
          
        j['datapoints'].each do |d|
          v=d['value']
          t=d['at']
          x=DateTime.strptime t, '%FT%T.%LZ'
          data<<[x.to_time.to_i*1000, v.to_i]
        end
        
        File.open(Rails.root.join('device_history', dev.dev_id), 'a') do |f|
          data.each do |p|
            f.write "[#{p[0]},#{p[1]}],"
          end
        end
        
        ret+="#{data.size} data points retrieved for device_id: #{dev.dev_id}\n"
      rescue Exception=>e
        logger.error '[Exception] '+e.to_s
        ret+="Exception when retrieving data points for device_id: #{dev.dev_id}\n\t#{e.to_s}\n"
        times+=1
        retry if times<3
      end
    end
    render plain: ret
  end
  
  def retrieve_at
    id=params[:id]
    start=params[:start]
    duration=params[:duration]
    key=params[:key]
    
    if (id.nil? or start.nil? or duration.nil? or key.nil?) and not key.eql? KEY
      render plain: 'ARG ERROR!'
      return
    end
    
    ret=''
    devs=[]
    if id=='all'
      devs=PreRegDevice.all
    else
      d=PreRegDevice.find_by dev_id: id
      if d.nil?
        render plain: "Device not found!"
        return
      end
      devs<<d
    end
      
    devs.each do |dev|
      begin
        url="http://api.xively.com/v2/feeds/#{dev.feed_id}/datastreams/PM25?&interval=0&duration=#{duration}&start=#{start}"
        url=URI.encode url
        url=URI.parse url
        req=Net::HTTP::Get.new url.to_s
        req["X-ApiKey"]=dev.api_key
        res=Net::HTTP.start(url.host, url.port){|http|http.request req}
        j=JSON.parse res.body
       
        data=[]
        siz=0
        if j.has_key? 'datapoints'
          j['datapoints'].each do |d|
            v=d['value']
            t=d['at']
            x=DateTime.strptime t, '%FT%T.%LZ'
            data<<[x.to_time.to_i*1000, v.to_i]
          end
          siz=data.size
          s=data[0][0]
          c=''
          File.open(Rails.root.join('device_history', dev.dev_id), 'r') do |f|
            c=f.read
          end
          c.rstrip!
          c.insert 0, '['
          if c.end_with? ','
            c[-1]=']'
          else
            c<<']'
          end
          dupFlag=false
          j=JSON.parse c
          for i in 0...j.size
            if j[i][0]==s
              data.delete_at 0
              if data.size==0
                ret+="All data points duplicated for device_id: #{dev.dev_id}\n"
                dupFlag=true
                break
              end
              s=data[0][0]
            end
            break if j[i][0]>s
          end
          next if dupFlag
          
          if i==j.size-1 and j[i][0]<s
            i+=1
          end
          
          data.each do |p|
            j.insert i, p
            i+=1
          end
          
          File.open(Rails.root.join('device_history', dev.dev_id), 'w') do |f|
            j.each do |p|
              f.write "[#{p[0]},#{p[1]}],"
            end
          end
        end
        ret+="#{siz} data points retrieved for device_id: #{dev.dev_id}\n"
      rescue Exception=>e
        ret+="Exception when retrieving data points for device_id: #{dev.dev_id}\n\t#{e.to_s}\n"
      end
    end
    render plain: ret
  end
  
  def graph
    id=params.delete :id
    uid=params.delete :uid
    
    if id.nil? or uid.nil?
      redirect_to '/404'
      return
    end
    
    dev=Device.find_by dev_id: id, owner: uid
    
    if dev.nil?
      redirect_to '/404'
      return
    end
    
    url="http://api.xively.com/v2/feeds/#{dev.feed_id}/datastreams/PM25.png?"
    params.each do |key, value|
      url+=(key+'='+value+'&')
    end
    url+="t=#{dev.name}"
    
    url=URI.encode url
    url=URI.parse url
    req=Net::HTTP::Get.new url.to_s
    req["X-ApiKey"]=dev.api_key
    res=Net::HTTP.start(url.host, url.port){|http|http.request req}
    
    send_data res.body, type: res.content_type, disposition: 'inline'
  end
  
  def text_msg_handler(content)
    begin
      case content
        when /\A(添加|添加设备|注册|设备注册)\Z/
          return wx_text_responce_builder "注册设备请发送 \"注册 设备序列号 想使用的名称\" 如 \"注册 1234567890 家\""
        when /\A注册[[:space:]]([[:digit:]]+)[[:space:]](.+)\Z/
          id=$1
          name=$2
          
          d=Device.find_by dev_id: id, owner: @uId
          if d
            return wx_text_responce_builder '设备已注册'
          end
          
          p=PreRegDevice.find_by dev_id: id
          if p.nil?
            return wx_text_responce_builder '设备不存在'
          else
            Device.create dev_id: p.dev_id, feed_id: p.feed_id, api_key: p.api_key, owner: @uId, name: name
            return wx_text_responce_builder "设备\"#{name}\"注册成功"
          end
        when /\A移除[[:space:]]([[:digit:]]+)\Z/
          id=$1
          p=Device.find_by dev_id: id, owner: @uId
          if p.nil?
            return wx_text_responce_builder '设备不存在或未注册'
          else
            p.destroy
            return wx_text_responce_builder '移除成功'
          end
        when /\A(查看|查询|当前|查|看|最新)((?:[[:space:]].+?)*)\Z/
          args=$2.strip.split
          
          if @devs.size==0
            return wx_text_responce_builder '没有注册设备'
          end
          
          text="当前数据：\n"
          @devs.each do |dev|
            url=URI.encode "http://api.xively.com/v2/feeds/#{dev.feed_id}/datastreams/PM25"
            url=URI.parse url
            req=Net::HTTP::Get.new url.to_s
            req["X-ApiKey"]=dev.api_key
            res=Net::HTTP.start(url.host, url.port){|http|http.request req}
            cvalue=JSON.parse(res.body)['current_value']
            text+="#{dev.name}: #{cvalue.strip}\n" unless cvalue.nil?
          end
          return wx_text_responce_builder text.rstrip
        when /\A(历史|图|曲线)((?:[[:space:]].+?)*)\Z/
          args=$2.strip.split
          
          dur='1day'
          
          if args
            if args[0]
              m=/\A([[:digit:]]+)(hour|day|week|month|小时|天|周|月)s?\Z/.match args[0]
              if m
                dict={'小时'=>'hour','天'=>'day','周'=>'week','月'=>'month'}
                if dict.has_key? m[2]
                  u=dict[m[2]]
                else
                  u=m[2]
                end
                dur=m[1]+u
              end
            end
          end
          
          if @devs.size==0
            return wx_text_responce_builder '没有注册设备'
          end
          
          arts=[]
          num=0
          
#          @devs.first(10).each do |dev| #10 is weixin limit for article responce
#            url=URI.encode("http://115.29.178.169/airsniffer/graph/#{@uId}/#{dev.dev_id}?&g=true&b=true&timezone=8&duration=#{dur}&end=#{Time.now.utc.strftime '%FT%RZ'}")
#            #&scale=manual&min=0&max=20000
#            num+=1
#            arts<<{text: dev.name, pic: url, url: url}
#          end

          @devs.first(10).each do |dev| #10 is weixin limit for article responce
            url=URI.encode "http://115.29.178.169/airsniffer/chart/#{@uId}/#{dev.dev_id}"
            num+=1
            arts<<{text: dev.name, url: url}
          end
          
          if num>0
            return wx_article_responce_builder arts
          else
            return wx_text_responce_builder '未能获得曲线，请重试'
          end
        when /\A(比较)((?:[[:space:]].+?)*)\Z/
          args=$2.strip.split
          
          if @devs.size==0
            return wx_text_responce_builder '没有注册设备'
          end
          
          url="http://115.29.178.169/airsniffer/multichart/#{@uId}?"
          i=1
          @devs.first(10).each do |dev|
            url+="#{i}=#{dev.dev_id}&"
            i+=1
          end
          url=URI.encode url[0..-2]
          
          return wx_article_responce_builder [{text: '比较', url: url}]
        else
          return wx_text_responce_builder '？'
      end
    rescue Exception=>e
      logger.error '[Exception] '+e.to_s
      return wx_text_responce_builder '出错！'
    end
  end
  
end
