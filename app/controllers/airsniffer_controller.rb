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
  
  def pre_register
    id=params[:id]
    feedId=params[:feed_id]
    apiKey=params[:api_key]
    
    if id.nil? or feedId.nil? or apiKey.nil?
      render plain: 'ARG ERROR!'
      return
    end
    
    PreRegDevice.where(dev_id: id).each{|p|p.destroy}
    PreRegDevice.create(dev_id: id,feed_id: feedId, api_key: apiKey)
    
    render plain: 'pre-register success'
  end
  
  def wxhandler
    body=request.body.read
    puts body
    
    doc=REXML::Document.new body
    
    @myId=REXML::XPath.first(doc,'/xml/ToUserName').text
    @uId=REXML::XPath.first(doc,'/xml/FromUserName').text
    msgType=REXML::XPath.first(doc,'/xml/MsgType').text
    
    @devs=Device.where(owner: @uId)
    
    if msgType.eql? 'text'
      content=REXML::XPath.first(doc,'/xml/Content').text
      ret=test_msg_handler(content)
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
    hash=Digest::SHA1.hexdigest(str)
    if hash.eql? sig
      return echo
    else
      return 'ERROR!'
    end
  end
  
  def wx_text_responce_builder(text)
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
  
  def test_msg_handler(content)
    begin
      case content
        when /\A(添加|添加设备|注册|设备注册)\Z/
          return wx_text_responce_builder("注册设备请发送 \"注册 设备序列号 想使用的名称\" 如 \"注册 1234567890 家\"")
        when /\A注册[[:space:]]([[:digit:]]+)[[:space:]](.+)\Z/
          id=$1
          name=$2
          p=PreRegDevice.find_by(dev_id: id)
          Device.create(dev_id: p.dev_id,feed_id: p.feed_id,api_key: p.api_key,owner: @uId,name: name)
          p.destroy
          return wx_text_responce_builder("设备\"#{name}\"注册成功")
        when /\A(查看|查询|当前|查|看|最新)\Z/
          text="当前数据：\n"
          @devs.each do |dev|
            url=URI.parse("http://api.xively.com/v2/feeds/#{dev.feed_id}/datastreams/PM25")
            req=Net::HTTP::Get.new(url.to_s)
            req["X-ApiKey"]=dev.api_key
            res=Net::HTTP.start(url.host,url.port){|http|http.request(req)}
            cvalue=JSON.parse(res.body)['current_value'].strip
            text+="#{dev.name}: #{cvalue}\n"
          end
          return wx_text_responce_builder(text.rstrip)
        when /\A(历史|图|曲线)\Z/
          return wx_text_responce_builder('施工中……')
        else
          return wx_text_responce_builder('？')
      end
    rescue
      return wx_text_responce_builder('出错！')
    end
  end
  
end
