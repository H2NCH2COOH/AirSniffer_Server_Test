require 'digest/sha1'
require 'rexml/document'
require 'net/http'
require 'json'

class PreRegDevice < ActiveRecord::Base
end

class Device < ActiveRecord::Base
end

class AirsnifferController < ApplicationController
  TOKEN='AirSniffer'
  KEY='7328956043759284757545839'
  
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
    feedId=params[:feed_id]
    apiKey=params[:api_key]
    
    if id.nil? or feedId.nil? or apiKey.nil?
      render plain: 'ARG ERROR!'
      return
    end
    
    PreRegDevice.where(dev_id: id).each{|p|p.destroy}
    PreRegDevice.create dev_id: id, feed_id: feedId, api_key: apiKey
    
    render plain: 'pre-register success'
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
      ret=test_msg_handler content
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
    
    array=[TOKEN,time,nonce].sort
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
  
  def wx_article_responce_builder(num,texts,urls)
    time=Time.now.to_i
    
    items=''
    for i in 0...num
      items+=<<-eos
    <item>
      <Title><![CDATA[#{texts[i]}]]></Title> 
      <PicUrl><![CDATA[#{urls[i]}]]></PicUrl>
      <Url><![CDATA[#{urls[i]}]]></Url>
    </item>
    
      eos
    end
    
    res=<<-eos
<xml>
  <ToUserName><![CDATA[#{@uId}]]></ToUserName>
  <FromUserName><![CDATA[#{@myId}]]></FromUserName>
  <CreateTime>#{time}</CreateTime>
  <MsgType><![CDATA[news]]></MsgType>
  <ArticleCount>#{num}</ArticleCount>
  <Articles>
#{items}
  </Articles>
</xml>
    eos
    
    return res
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
  
  def test_msg_handler(content)
    begin
      case content
        when /\A(添加|添加设备|注册|设备注册)\Z/
          return wx_text_responce_builder "注册设备请发送 \"注册 设备序列号 想使用的名称\" 如 \"注册 1234567890 家\""
        when /\A注册[[:space:]]([[:digit:]]+)[[:space:]](.+)\Z/
          id=$1
          name=$2
          
          d=Device.find_by dev_id: id, owner: @uId
          if not d.nil?
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
          
          if @devs.size==0
            return wx_text_responce_builder '没有注册设备'
          end
          
          num=0
          texts=[]
          urls=[]
          
          @devs.each do |dev|
            url=URI.encode("http://115.29.178.169/airsniffer/graph/#{@uId}/#{dev.dev_id}?&g=true&b=true&timezone=8&duration=12hours")
            #&scale=manual&min=0&max=20000
            num+=1
            texts<<"#{dev.name}"
            urls<<url
          end
          
          if num>0
            return wx_article_responce_builder num, texts, urls
          else
            return wx_text_responce_builder '未能获得曲线，请重试'
          end
        else
          return wx_text_responce_builder '？'
      end
    rescue
      return wx_text_responce_builder '出错！'
    end
  end
  
end
