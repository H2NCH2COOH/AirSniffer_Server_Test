require 'digest/sha1'
require 'rexml/document'
require 'net/http'
require 'json'
require 'lazy_high_charts'
require 'openssl'

class Device < ActiveRecord::Base
end

class PreRegDevice < ActiveRecord::Base
end

class AirsnifferController < ApplicationController
  TOKEN='AirSniffer'
  KEY='7328956043759284757545839'
  XIVELY_PRODUCT_SECRET='c71390d4339d6b2f4dc0c700e961f3da1e90c145'
  
  def pre_registered_dev
    id=params[:id]
    key=params[:key]
    
    if (id.nil? or key.nil?) and not key.eql? KEY
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
  
  def pre_register
    id=params[:id]
    
    if id.nil?
      render plain: 'ARG ERROR!'
      return
    end
    
    begin
      digest=OpenSSL::Digest::Digest.new 'sha1'
      activation_code=OpenSSL::HMAC.hexdigest digest, [XIVELY_PRODUCT_SECRET].pack("H*"), id
      
      url="http://api.xively.com/v2/devices/#{activation_code}/activate"
      url=URI.encode url
      url=URI.parse url
      req=Net::HTTP::Get.new url.to_s
      res=Net::HTTP.start(url.host, url.port){|http|http.request req}
      j=JSON.parse res.body
      
      PreRegDevice.where(dev_id: id).each{|p|p.destroy}
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
  
  def chart
    id=params.delete :id
    uid=params.delete :uid
    
    if id.nil? or uid.nil?
      redirect_to '/404'
      return
    end
    
    dev=Device.find_by dev_id: id, owner: uid
    pdev=PreRegDevice.find_by dev_id: id
    
    if dev.nil?
      redirect_to '/404'
      return
    end
    
    data=[]
    c=''
    if Rails.root.join('device_history', dev.dev_id).exist?
      File.open(Rails.root.join('device_history', dev.dev_id), 'r') do |f|
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
      url="http://api.xively.com/v2/feeds/#{dev.feed_id}/datastreams/PM25?&interval=0&duration=6hour"
    else
      url="http://api.xively.com/v2/feeds/#{dev.feed_id}/datastreams/PM25?&interval=0&start=#{pdev.last_retrieve_time}"
    end
    url=URI.encode url
    url=URI.parse url
    req=Net::HTTP::Get.new url.to_s
    req["X-ApiKey"]=dev.api_key
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
    
    @dataCount=data.size
    @chart=LazyHighCharts::HighChart.new('graph') do |f|
      f.title text: dev.name
      f.yAxis min: 0
      f.rangeSelector(
        buttons: [
          {type: 'day', count: 1, text: '1d'},
          {type: 'week', count: 1, text: '1w'},
          {type: 'month', count: 1, text: '1m'}
        ],
        selected: 0
      )
      f.series name: "PM2.5", data: data
    end
  end
  
  def data_retrieve
    PreRegDevice.find_each do |dev|
      data=[]
      if dev.last_retrieve_time.nil?
        url="http://api.xively.com/v2/feeds/#{dev.feed_id}/datastreams/PM25?&interval=0&duration=6hour}"
      else
        url="http://api.xively.com/v2/feeds/#{dev.feed_id}/datastreams/PM25?&interval=0&start=#{dev.last_retrieve_time}"
      end
      url=URI.encode url
      url=URI.parse url
      req=Net::HTTP::Get.new url.to_s
      req["X-ApiKey"]=dev.api_key
      res=Net::HTTP.start(url.host, url.port){|http|http.request req}
      j=JSON.parse res.body
      
      dev.last_retrieve_time=Time.now.utc.strftime '%FT%RZ'
      dev.save
      
      next unless j.has_key? 'datapoints'
        
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
    end
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
          
          @devs.first(10).each do |dev| #10 is weixin limit for article responce
            url=URI.encode("http://115.29.178.169/airsniffer/graph/#{@uId}/#{dev.dev_id}?&g=true&b=true&timezone=8&duration=#{dur}&end=#{Time.now.utc.strftime '%FT%RZ'}")
            #&scale=manual&min=0&max=20000
            num+=1
            arts<<{text: dev.name, pic: url, url: url}
          end
          
          if num>0
            return wx_article_responce_builder arts
          else
            return wx_text_responce_builder '未能获得曲线，请重试'
          end
        when /\Ahighstock\Z/
          if @devs.size==0
            return wx_text_responce_builder '没有注册设备'
          end

          arts=[]
          num=0

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
        else
          return wx_text_responce_builder '？'
      end
    rescue Exception=>e
      logger.error '[Exception]: '+e.to_s
      return wx_text_responce_builder '出错！'
    end
  end
  
end
