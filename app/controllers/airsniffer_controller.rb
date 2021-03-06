require 'date'
require 'digest/sha1'
require 'rexml/document'
require 'net/http'
require 'json'
require 'lazy_high_charts'
require 'openssl'
require 'mail'
#require 'reloader/sse'
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
  #include ActionController::Live
  
  TOKEN='AirSniffer'
  KEY='7328956043759284757545839'
  XIVELY_PRODUCT_ID='ioV3xb4qcXATBqOZXccU'
  XIVELY_PRODUCT_SECRET='c71390d4339d6b2f4dc0c700e961f3da1e90c145'
  XIVELY_MASTER_KEY='4tE9zx1Hezmm2rUhrkBsncOGfGmssYTn5VBli3yc9qifzjKB'
  
  DEVICE_SERVER='http://127.0.0.1'
  
  PM25RAW_KEY='pm25raw'
  TEMP_KEY='temp'
  
  UNIT_TYPE_PCS='pcs'
  UNIT_TYPE_UG='ug'
  
  def send_admin_email(content, to=nil)
    to='wzypublic@gmail.com' if to.nil?
    
    Mail.deliver do
      to to
      from 'Air Sniffer Server Report <wzypublic@gmail.com>'
      subject 'Air Sniffer Server Report'
      body content
    end
  end
  
  def sse
    response.headers['Content-Type']='text/event-stream'
    sse=Reloader::SSE.new response.stream
    
    begin
      loop do
        obj={time: Time.now}
        sse.write obj
        sleep 3
      end
    rescue IOError
      #Client disconnects
    ensure
      sse.close
    end
  end
  
  def test_req
    render plain: "Test"
  end
  
  def convert(raw, unit_type)
    case unit_type
      when UNIT_TYPE_PCS
        return raw*60000.0
      when UNIT_TYPE_UG
        return raw*3000
      else
        logger.error 'Data convert: unknown unit type'
        return 0
    end
  end
  
  def dev_reg_device(id)
    url="#{DEVICE_SERVER}/dev/#{id}"
    url=URI.encode url
    url=URI.parse url
    req=Net::HTTP::Put.new url.to_s
    res=Net::HTTP.start(url.host, url.port){|http|http.request req}
    
    j=JSON.parse res.body
    
    case j['code']
      when 200
        return true
      else
        return false
    end
  end

  def dev_delete_device(id)
    url="#{DEVICE_SERVER}/dev/#{id}"
    url=URI.encode url
    url=URI.parse url
    req=Net::HTTP::Delete.new url.to_s
    res=Net::HTTP.start(url.host, url.port){|http|http.request req}
    
    j=JSON.parse res.body
    
    case j['code']
      when 200
        return true
      else
        return false
    end
  end

  def dev_get_device_list
    url="#{DEVICE_SERVER}/dev/"
    url=URI.encode url
    url=URI.parse url
    req=Net::HTTP::Get.new url.to_s
    res=Net::HTTP.start(url.host, url.port){|http|http.request req}
    
    j=JSON.parse res.body
    
    if j['code']==200
      return j['data']
    else
      return nil
    end
  end

  def dev_get_device(id, endTime=nil, duration=nil)
    url="#{DEVICE_SERVER}/dev/#{id}#{"/#{endTime}#{"/#{duration}" if duration}" if endTime}"
    
    url=URI.encode url
    url=URI.parse url
    req=Net::HTTP::Get.new url.to_s
    res=Net::HTTP.start(url.host, url.port){|http|http.request req}
    
    j=JSON.parse res.body
    
    if j['code']==200
      ret=j['data'].collect do |d|
        [DateTime.strptime(d['time'], '%F %T'), d['value']]
      end
      ret.reverse!
      #logger.debug ret.inspect
      return ret
    else
      return nil
    end
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
    Device.where(dev_id: id).each{|d|d.destroy}
    render plain: "Device: #{id} deleted"
  end
  
  def new_device
    key=params[:key]
       
    if key.nil? or key!=KEY
      render plain: 'ARG ERROR!'
      return
    end
    
    while true
      new_id=8.times.inject(""){|s|s+=Random.rand(10).to_s}
      break if PreRegDevice.find_by(dev_id: new_id).nil?
    end

    if dev_reg_device new_id
      PreRegDevice.create dev_id: new_id
      Device.create dev_id: new_id, owner: 'admin', name: new_id.to_s, unit_type: UNIT_TYPE_PCS
      render plain: "Device #{new_id} pre-registered"
    else
      render plain: 'Failed'
    end
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
      
      if dev_reg_device id
        PreRegDevice.create dev_id: id
        Device.create dev_id: p.dev_id, owner: 'admin', name: id.to_s, unit_type: UNIT_TYPE_PCS
        render plain: "Device #{id} pre-registered"
      else
        render plain: 'Failed'
      end
    rescue Exception=>e
      logger.error '[Exception]: '+e.to_s
      render plain: 'Error in pre-registration'
    end
  end
  
  def generate_data_points_for_highstock(dev, key, endTime=nil, duration=nil)
    data=[]
    begin
      data=dev_get_device(dev.dev_id, endTime, duration).collect do |d|
        v=0
        if key==PM25RAW_KEY
          v=convert d[1][key], dev.unit_type
        else
          v=d[1][key]
        end
        [d[0].to_time.to_i*1000, v]
      end
      
      data_interval=5*60*1000
      gap_limit=1000*1000
      if data.size>0
        i=0
        if endTime
          tEnd=DateTime.strptime(endTime, '%F %T').to_time
        else
          tEnd=Time.now
        end
        tEnd=tEnd.to_i*1000

        while data[i][0]<tEnd-gap_limit
          if data[i+1].nil?
            data<<[data[i][0]+data_interval, 0]
            data<<[tEnd, 0]
            break
          else
            if data[i+1][0]-data[i][0]>gap_limit
              tZero=data[i][0]
              tZeroEnd=data[i+1][0]
              while tZero+data_interval<tZeroEnd
                tZero+=data_interval
                data.insert i+1, [tZero, 0]
                i+=1
              end
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
    if uid!='admin'
      render plain: 'Need to be admin'
    end
    
    key=params[:key]
    if key.nil? or key!=KEY
      render plain: 'ARG ERROR!'
      return
    end
    
    devs=[]
    ids.each do |id|
      dev=Device.find_by dev_id: id, owner: 'admin'
      next if dev.nil?
      
      data=generate_data_points_for_highstock dev, PM25RAW_KEY, Time.now.strftime('%F %T'), 60*24*32
      devs<<[dev.name, data] if data.size>0
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
    key=params[:type]
    key=PM25RAW_KEY if key.nil?
    
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

      if uid=='admin'
        pass=params[:key]
        if pass.nil? or pass!=KEY
          render plain: 'ARG ERROR!'
          return
        end
      end
      
      dev=Device.find_by dev_id: id, owner: uid
      if dev.nil?
        render plain: 'Device not found'
        return
      end
      name=dev.name
      
      data=generate_data_points_for_highstock dev, key, Time.now.strftime('%F %T'), 60*24*32
      sname=''
      if key==PM25RAW_KEY
        sname='PM2.5'
      else
        sname='温度'
      end
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
        f.series name: sname, data: data
      end
    rescue Exception=>e
      logger.error '[Exception] '+e.to_s
      render plain: '出错，请稍后重试'
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
  
  def usage
    <<-EOF
可用命令：
注册 <设备序列号> <名称>
移除 <名称>
查询
曲线
切换单位
    EOF
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
          
          d=Device.find_by owner: @uId, name: name
          if d
            return wx_text_responce_builder '名称已被使用'
          end
          
          p=PreRegDevice.find_by dev_id: id
          if p.nil?
            return wx_text_responce_builder '设备不存在'
          else
            Device.create dev_id: p.dev_id, owner: @uId, name: name, unit_type: UNIT_TYPE_PCS
            return wx_text_responce_builder "设备\"#{name}\"注册成功"
          end
        when /\A移除[[:space:]](.+)\Z/
          name=$1
          p=Device.find_by name: name, owner: @uId
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
          
          text=""
          @devs.each do |dev|
            text+="#{dev.name}:\n"
            dp=dev_get_device dev.dev_id, Time.now.strftime('%F %R'), '30'
            if dp and dp[-1]
              pm25=convert dp[-1][1][PM25RAW_KEY], dev.unit_type
              text+="-PM2.5: #{pm25.to_i}#{" ug" if dev.unit_type==UNIT_TYPE_UG}\n"
              if dp[-1][1][TEMP_KEY]
                text+="-温度: #{dp[-1][1][TEMP_KEY]}\n"
              end
            else
              text+="-30分钟内无数据\n"
            end
          end
          return wx_text_responce_builder text.rstrip
        when /\A(历史|图|曲线)((?:[[:space:]].+?)*)\Z/
          args=$2.strip.split
          
          type=PM25RAW_KEY
          if args and args[0] and args[0]=='温度'
            type=TEMP_KEY
          end
          
          if @devs.size==0
            return wx_text_responce_builder '没有注册设备'
          end
          
          arts=[]
          num=0
          
          @devs.first(10).each do |dev| #10 is weixin limit for article responce
            url=URI.encode "http://115.29.178.169/airsniffer/chart/#{@uId}/#{dev.dev_id}?type=#{type}"
            num+=1
            arts<<{text: dev.name, url: url}
          end
          
          if num>0
            return wx_article_responce_builder arts
          else
            return wx_text_responce_builder '未能获得曲线，请重试'
          end
        when /\A切换单位\Z/
          @devs.each do |dev|
            if dev.unit_type==UNIT_TYPE_PCS
              dev.unit_type=UNIT_TYPE_UG
            else
              dev.unit_type=UNIT_TYPE_PCS
            end
            dev.save
          end
          return wx_text_responce_builder '切换成功'
        when /\A令(.+)的(.+)为(.+)\Z/
          name=$1
          attr=$2
          value=$3
          
          dev=Device.find_by name: name, owner: @uId
          if dev.nil?
            return wx_text_responce_builder '设备不存在或未注册'
          end
          
          ret='?'
          
          case attr
            when '单位'
              case value
                when /pcs|颗粒数/
                  dev.unit_type=UNIT_TYPE_PCS
                  dev.save
                  ret='设置成功'
                when /ug|微克|微克每立方米/
                  dev.unit_type=UNIT_TYPE_UG
                  dev.save
                  ret='设置成功'
                else
                  ret='无效值'
              end
            else
              ret='无效参数'
          end
          
          return wx_text_responce_builder ret
        else
          return wx_text_responce_builder usage
      end
    rescue Exception=>e
      logger.error '[Exception] '+e.to_s
      return wx_text_responce_builder '出错！'
    end
  end
  
end
