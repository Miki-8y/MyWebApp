require 'digest/md5'
require 'sinatra'
require 'active_record'
require 'securerandom'

set :environment, :production
set :sessions, 
    expire_after: 7200, 
    # 32バイトのランダムなシークレットキーを生成（rubyのバージョンが上がったため必須になった）
    secret:  SecureRandom.hex(32)
    # secret: 'SPLAkyTwYa2L3Q2jwUjy'

# 静的コンテンツ参照のためのパス設定
# set :public, File.dirname(__FILE__) + '/public'

ActiveRecord::Base.configurations = YAML.load_file('database.yml')
ActiveRecord::Base.establish_connection :development

class Writeinfo < ActiveRecord::Base
    #Specifying the name of the database
    #テーブル名を明示的に指定する場合は以下のように記述する!?
    #self.table_name = 'writeinfos'
end

class Subwriteinfo < ActiveRecord::Base
end

class Account < ActiveRecord::Base
end

class Question < ActiveRecord::Base
end

ESCAPE_SS = {
    '&' => '&amp;',
    '<' => '&lt;',
    '>' => '&gt;',
    '"' => '&quot;',
    "'" => '&#39;',
}

CHECK = ["<font","<h1>","<h2>","<h3>","<h4>","<h5>","<h6>","</font>","</h1>","</h2>","</h3>","</h4>","</h5>","</h6>"]

##############################メソッド定義#############################
#ユーザネームの最大長
username_max = 40
#パスワードの最大長
password_max = 40

comment_count = 1

#入力文字が１文字以上，最大長以下であることを確認する関数
# 1 <= inputstr < maxlen : true
#else : false
def checkstr(inputstr,maxlen)
    if inputstr.size==0 then
        return false
    elsif inputstr.size>maxlen then
        return false
    else
        return true
    end
end

#ユーザーネームとパスワードを確認する関数
def checkpasswd(trial_username,trial_passwd)
    #Search recorded info
    begin
        a = Account.find(trial_username)
        db_username = a.username
        db_salt = a.salt
        db_hashed = a.hashed
        db_algo = a.algo
    rescue => e
        return false
    end

    #ハッシュ値を生成
    if db_algo == "1"
        trial_hashed = Digest::MD5.hexdigest(db_salt + trial_passwd)
    else
        return false
    end

    #Success?
    if db_hashed == trial_hashed
        return true#"Login Success"
    else
        return false#"Login Failure"
    end
end

#########################################################################

#############################ログイン処理################################
#loginにリダイレクト
get '/' do
    redirect '/login'
end

#loginの処理（login画面の表示）
get '/login' do
    #例)erb :'/BBS/bbs', :layout => :'/BBS/layout'
    erb :'/LoginLogout/Login/loginscr', :layout => :'/LoginLogout/layout'
end

#logoutの処理（logout画面の表示）
get '/logout' do
    session.clear
    erb :'/LoginLogout/Logout/logout', :layout => :'/LoginLogout/layout'
end

#ログイン管理
#成功 : mainpageにリダイレクト
#失敗 : failureにリダイレクト
post '/auth' do
    checkflg = true
    username = params[:uname].gsub(/[&<>"']/, ESCAPE_SS)
    pass = params[:pass].gsub(/[&<>"']/, ESCAPE_SS)
    if !checkstr(username,username_max) then
        checkflg = false
    elsif !checkstr(pass,password_max) then
        checkflg = false
    end

    if checkflg == false then
        redirect '/failureAccount3'
    else
        if(checkpasswd(username,pass)==true)
            session[:login_flag] = true
            session[:username] = username
            redirect '/mainpage'
        else
            session[:login_flg] = false
            redirect '/failure'
        end
    end
end

#ログイン失敗処理（ログイン失敗画面の表示）
get '/failure' do
    erb :'/LoginLogout/Login/failure', :layout => :'/LoginLogout/layout'
end

#アカウント作成処理（アカウント作成画面の表示）
get '/createaccount' do
    erb :'/LoginLogout/Account/createAccount', :layout => :'/LoginLogout/layout'
end

#アカウント作成管理
#成功 : successnewAccount
#失敗1（usernameが既に存在） : failureAccount1にリダイレクト
#失敗2（pass1,pass2が不一致） : failureAccount2にリダイレクト
#失敗3（入力値エラー） : failureAccount3にリダイレクト
post '/newaccount' do
    checkflg = true
    username = params[:uname].gsub(/[&<>"']/, ESCAPE_SS)
    pass1 = params[:pass1].gsub(/[&<>"']/, ESCAPE_SS)
    pass2 = params[:pass2].gsub(/[&<>"']/, ESCAPE_SS)

    if !checkstr(username,username_max) then
        checkflg = false
    elsif !checkstr(pass1,password_max) then
        checkflg = false
    elsif !checkstr(pass2,password_max) then
        checkflg = false
    end

    if checkflg == false then
        redirect '/failureAccount3'
    else
        begin
            a = Account.find(username)
            redirect '/failureAccount1'
        rescue => e
            if pass1 == pass2 then
                r = Random.new
                algorithm = "1"
                salt = Digest::MD5.hexdigest(r.bytes(20))
                hashed = Digest::MD5.hexdigest(salt+pass1)
                s = Account.new
                s.username = username#s.idを変更
                s.salt = salt
                s.hashed = hashed
                s.algo = algorithm
                s.save
                redirect '/successnewAccount'
            else
                redirect '/failureAccount2'
            end
        end
    end
end

#アカウント作成処理（アカウント作成成功画面の表示）
get '/successnewAccount' do
    erb :'/LoginLogout/Account/successnewAccount', :layout => :'/LoginLogout/layout'
end

#username既存エラー処理（１つめのエラーの画面表示）
get '/failureAccount1' do
    erb :'/LoginLogout/Account/failureAccount1', :layout => :'/LoginLogout/layout'
end

#パスワード一致エラー処理（２つめのエラーの画面表示）
get '/failureAccount2' do
    erb :'/LoginLogout/Account/failureAccount2', :layout => :'/LoginLogout/layout'
end

#入力エラー処理（３つめのエラーの画面表示）
get '/failureAccount3' do
    erb :'/LoginLogout/Account/failureAccount3', :layout => :'/LoginLogout/layout'
end

#パスワードの変更処理（パスワード変更画面表示）
get '/forgetpass' do
    erb :'/LoginLogout/Password/forgetpass', :layout => :'/LoginLogout/layout'
end

#パスワードを再登録する処理
#成功 : successnewpassにリダイレクト
#失敗（usernameが存在しない） : unknownUserにリダイレクト
#失敗（pass1,pass2が不一致） : failureAccount2にリダイレクト
post '/newpassword' do
    checkflg = true
    username = params[:uname].gsub(/[&<>"']/, ESCAPE_SS)
    pass1 = params[:pass1].gsub(/[&<>"']/, ESCAPE_SS)
    pass = params[:pass2].gsub(/[&<>"']/, ESCAPE_SS)
    
    if !checkstr(username,username_max) then
        checkflg = false
    elsif !checkstr(pass1,password_max) then
        checkflg = false
    elsif !checkstr(pass2,password_max) then
        checkflg = false
    end

    if checkflg == false then
        redirect '/failureAccount3'
    else
        begin
            a = Account.find(username)
            if pass1 == pass2 then
                r = Random.new
                algorithm = "1"
                salt = Digest::MD5.hexdigest(r.bytes(20))
                hashed = Digest::MD5.hexdigest(salt+pass1)
                s.salt = salt
                s.hashed = hashed
                s.algo = algorithm
                s.save
                redirect '/successnewpass'
            else
                redirect '/failureAccount2'
            end
        rescue => e
            redirect '/unknownUser'
        end
    end
end

#パスワードの再登録処理（パスワードの再登録成功画面表示）
get '/successnewpass' do
    erb :'/LoginLogout/Password/successnewpass', :layout => :'/LoginLogout/layout'
end

#username未登録処理（usernameが未登録のときのエラー画面表示）
get '/unknownUser' do
    erb :'/LoginLogout/Login/unknownUser', :layout => :'/LoginLogout/layout'
end
#########################################################################

##########################BBSの主な動作に関わる部分########################
post '/privatebbs' do
    redirect '/privatebbs'
end

# ログイン必須
# あなたの投稿ページを表示
get '/privatebbs' do
    if(session[:login_flag] == true)
        # erb内にuser名を表記する記述があるため必要
        @user = session[:username]
        # ログインしているusernameのみのWriteinfoのレコードを取得
        @w = Writeinfo.where(username: session[:username])
        erb :'/BBS/Private/bbs', :layout => :'/BBS/layout'
    else
        erb :'badrequest', :layout => :'/LoginLogout/layout'
    end
end

post '/new' do
    w = Writeinfo.new

    w.id = Time.now.strftime("%Y%m%d%H%M%S")
    # # コメントを書き込まれたときに必要
    # session[:id] = w.id

    w.write_time = Time.now.strftime("%Y/%m/%d %H:%M:%S")

    # w.username = params[:username].gsub(/[&<>"']/, ESCAPE_SS)
    # if w.username.empty?
    #     w.username = 'Nanashi'
    # end

    # if w.username.length > 150
    #     w.username = 'Plese keep within 150 characters'
    # end

    # w.username = session[:username].gsub(/[&<>"']/, ESCAPE_SS)

    # accountsテーブルのusernameをwriteinfosテーブルに格納
    # session[:username]はログイン中のユーザー名である
    w.username = session[:username]

    m = params[:message]

    if m.length > 280
        m = 'Plese keep within 280 characters'
    end

    check = CHECK.any? {|i| m.include? i}
    if check == false
        m.gsub!(/[&<>"']/, ESCAPE_SS)
    else
        m_temp = Marshal.load(Marshal.dump(m))
        flag = 0
        CHECK.each do |z|
            m_slice = m_temp.slice!(z)
            if m_slice == "<font"
                flag = 1
            end
        end
        if flag == 1
            m_temp.delete!('"')
            m_temp.delete!('>')
        end
        check2 = m_temp.match(/[&<>"']/)
        if check2 != nil
            m.gsub!(/[&<>"']/, ESCAPE_SS)
        end
    end
    w.message = m

    w.save
    redirect '/privatebbs'
end

delete '/del' do
    # Writeinfoテーブルのデータ（id）ではないことに注意！
    # findをつけることによってレコード全体のアドレスを取得している！？
    w = Writeinfo.find(params[:id])
    w.destroy
    redirect '/privatebbs'
end

post '/publicbbs' do
    redirect '/publicbbs'
end

# ログイン必須
# みんなの投稿ページを表示
get '/publicbbs' do
    @w = Writeinfo.all

    if(session[:login_flag] == true)
        erb :'/BBS/Public/bbs', :layout => :'/BBS/layout'
    else
        erb :'badrequest', :layout => :'/LoginLogout/layout'
    end
end

post '/subnew' do
    # コメントがクリックされたメインの投稿情報(id,username,write_time,message)を格納
    # $はグローバル変数
    $w = Writeinfo.where(id: params[:id])
    redirect '/subhistory'
end

# ログイン必須
# コメント投稿ページを表示
get '/subhistory' do
    all_writeinfo = Writeinfo.all

    # Debug
    # all_writeinfo.each do |writeinfo|
    #     puts writeinfo.id
    # end   

    all_subwriteinfo = Subwriteinfo.all

    if(session[:login_flag] == true)
        # erb内にuser名を表記する記述があるため必要
        @user = session[:username]
        @w = $w

        # メインの投稿のIDだけを格納
        $w.each do |writeinfo|
            $subwrite_id = writeinfo.id
        end
        
        # if(all_subwriteinfo != nil)
            # メインの投稿に対しての全てのコメントを@swに格納
            $w.each do |writeinfo|
                # all_subwriteinfo.each do |subwriteinfo|
                    @sw = Subwriteinfo.where(id: writeinfo.id)
                # end
            end       
        # end

        # # メインの投稿に対しての全てのコメントを@swに格納
        #     all_writeinfo.each do |writeinfo|
        #         @all_subwriteinfo&.each do |subwriteinfo|
        #             @sw = Subwriteinfo.where(id: writeinfo.id)
        #         end
        #     end       
        erb :'/BBS/subhistory', :layout => :'/BBS/layout'
    else
        erb :'badrequest', :layout => :'/LoginLogout/layout'
    end
end

# コメント追加
post '/subnewhistory' do
    # w = Writeinfo.where(id: params[:id])
    sw = Subwriteinfo.new

    #Debug
    # swtime = Time.now.strftime("%Y%m%d%H%M%S")

    # if $commentcount < 100
    #     $commentcount +=1
    # else
    #     redirect '/commentover'
    # end
    # # コメントは100件まで
    # swnumber = $commentcount
    # swnumber_str = swnumber.to_s

    # sw.subid = swtime + swnumber_str

    #Debug
    # if comment_count < 100
    #     comment_count +=1
    # else
    #     redirect '/commentover'
    # end

    # sw.subid = comment_count

    #Debug
    # sw.subid = SecureRandom.alphanumeric(15)

    #Debug
    #sw.subid = Time.now.strftime("%Y%m%d%H%M%S") + Time.now.usec.to_s

    #Debug
    # sw.subid = SecureRandom.uuid
    # puts sw.subid

    sw.subid = Time.now.strftime("%Y%m%d%H%M%S")

    sw.write_time = Time.now.strftime("%Y/%m/%d %H:%M:%S")
    # メインの投稿に対してのコメントなので，どのコメントがどのメインの投稿のもの
    # なのかを識別するために，subwriteinfosテーブルのidにwriteinfosテーブルのid
    # を格納しておく
    sw.id = $subwrite_id
    # w.each do |winfo|
    #     sw.id = winfo.id
    # end


    sw.username = session[:username]
    
    m = params[:message]

    if m.length > 280
        m = 'Plese keep within 280 characters'
    end

    check = CHECK.any? {|i| m.include? i}
    if check == false
        m.gsub!(/[&<>"']/, ESCAPE_SS)
    else
        m_temp = Marshal.load(Marshal.dump(m))
        flag = 0
        CHECK.each do |z|
            m_slice = m_temp.slice!(z)
            if m_slice == "<font"
                flag = 1
            end
        end
        if flag == 1
            m_temp.delete!('"')
            m_temp.delete!('>')
        end
        check2 = m_temp.match(/[&<>"']/)
        if check2 != nil
            m.gsub!(/[&<>"']/, ESCAPE_SS)
        end
    end
    sw.message = m

    sw.save
    redirect '/subhistory'
end

# ログイン必須
# コメントが100件投稿されているときに表示するコンテンツ
# get '/commentover' do
#     if(session[:login_flag] == true)
#         erb :'/BBS/commentover', :layout => :'/BBS/layout'
#     else
#         erb :'badrequest', :layout => :'/LoginLogout/layout'
#     end
# end
##################################################################

######################APPの主な動作に関わる部分####################
post '/contentspage1' do
    redirect '/contentspage1'
end
#ログイン必須
#１つ目のコンテンツページ表示
#ログイン時: contents1を表示
#未ログイン時: badrequestを表示
get '/contentspage1' do
    $question_count = 0
    $true_count = 0
    $false_count = 0

    if(session[:login_flag] == true)
        @user = session[:username]
        erb :'/APP/Contents/contents1', :layout => :'/APP/layout'
    else
        erb :'badrequest', :layout => :'/LoginLogout/layout'
    end
end

#ログイン必須
#ユーザーマニュアル表示処理
#ログイン時: usersanualを表示
#未ログイン時: badrequestを表示
get '/usersmanual' do
    if(session[:login_flag] == true)
        @user = session[:username]
        erb :'/APP/Contents/usersmanual', :layout => :'/APP/layout'
    else
        erb :'badrequest', :layout => :'/LoginLogout/layout'
    end
end

#コンテンツページから値を受け取る処理
post '/contentspage2' do
    $level = params[:Level]
    redirect '/contentspage2'
end

#ログイン必須
#２つ目のコンテンツページ表示
#ログイン時:contents2を表示
#未ログイン時:badrequestを表示
get '/contentspage2' do
    @a = Account.all
    @q = Question.all

    case $level
    when "600"
        $r_num = rand(1..25)
    when "730"
        $r_num = rand(26..50)
    when "860"
        $r_num = rand(51..75)
    when "900"
        $r_num = rand(76..100)
    end

    if(session[:login_flag] == true)
        @user = session[:username]
        erb :'/APP/Contents/contents2', :layout => :'/APP/layout'
    else
        erb :'badrequest', :layout => :'/LoginLogout/layout'
    end
end

#入力された単語の正誤判定をする処理
#ユーザが入力文字制限を超えて入力した時: wordoverへリダイレクト
#入力された単語が正しい時: trueresultへリダイレクト
#入力された単語が正しくない時: falseresultへリダイレクト
post '/judge' do
    @q = Question.all
    @a = Account.new
    @a.write_word = params[:write_word].gsub(/[&<>"']/, ESCAPE_SS)

    #write_wordが30文字を超えたら
    if @a.write_word.length > 30
        redirect '/wordover'
    end

    #正誤判定するページ指定
    @q.each do |b|
        #もしランダムな番号と問題番号が一致したら
        if b.question_num == $r_num
            #その番号に対応する答えと比較
            #.eql?単語正誤判定
            $eqlflag = (@a.write_word).eql?(b.eanswer_word)
            #正答の文章を作成
            $ae = b.english.gsub(/_____/,b.eanswer_word)
            #誤答の文章を作成
            $fe = b.english.gsub(/_____/,@a.write_word)
        end
    end

    if ($eqlflag).eql?(true)
        #正解だったら
        $true_count += 1
        redirect '/trueresult'
    else
        #不正解だったら
        $false_count += 1
        redirect '/falseresult'
    end
end

#ログイン必須
#入力文字数制限を超えた時の処理
#ログイン時: wordoverを表示
#未ログイン時: badrequestを表示
get '/wordover' do
    if(session[:login_flag] == true)
        @user = session[:username]
        erb :'/APP/Contents/wordover', :layout => :'/APP/layout'
    else
        erb :'badrequest', :layout => :'/LoginLogout/layout'
    end
end

#ログイン必須
#正答ページ表示処理
#ログイン時: trueresultを表示
#未ログイン時: badrequestを表示
get '/trueresult' do
    @a = Account.all
    @q = Question.all

    if(session[:login_flag] == true)
        @user = session[:username]
        erb :'/APP/Contents/trueresult', :layout => :'/APP/layout'
    else
        erb :'badrequest', :layout => :'/LoginLogout/layout'
    end
end

#ログイン必須
#誤答ページ表示処理
#ログイン時: falseresultを表示
#未ログイン時: badrequestを表示
get '/falseresult' do
    @a = Account.all
    @q = Question.all

    if(session[:login_flag] == true)
        @user = session[:username]
        erb :'/APP/Contents/falseresult', :layout => :'/APP/layout'
    else
        erb :'badrequest', :layout => :'/LoginLogout/layout'
    end
end

#ユーザに5問解いてもらうための処理
#question_countが4以下の時: contentspageを表示
#question_countが5以上の時: finishresultを表示
post '/result' do
    $question_count +=1
    if $question_count < 5
        redirect '/contentspage2'
    else
        redirect '/finishresult'
    end
end

#ログイン必須
#結果表示処理
#ログイン時: finishresultを表示
#未ログイン時: badrequestを表示
get '/finishresult' do
    if(session[:login_flag] == true)
        @user = session[:username]
        erb :'/APP/Contents/finishresult', :layout => :'/APP/layout'
    else
        erb :'badrequest', :layout => :'/LoginLogout/layout'
    end
end

######################メインページ####################
#ログイン必須
get '/mainpage' do
    if(session[:login_flag] == true)

        # @image_paths = ['./public/images/MyWebApp_APP.png', './public/images/MyWebApp_BBS.png']
        # puts @image_paths


        #public/images/ にあるファイル，ディレクトリを全て取得し，格納
        # images_name = Dir.glob("public/images/*")
        # puts images_name

        # image_paths = images_name.split(',')
        # puts image_paths

        # public/ を ./ に変換
        # images_name.each do |image|
        #     @images_path = image.gsub("public/", "./")
        # end

        # image_paths.each do |path|
        #     @images_path << path.gsub("public/", "./")
        # end

        @user = session[:username]
        erb :'/Top/top', :layout => :'/Top/layout'
        #erb :'/Top/top'
    else
        erb :'badrequest', :layout => :'/APP/layout'
    end
end


######################プロフィールページ(Aboutページ)####################
#ログイン必須
get '/about' do
    if(session[:login_flag] == true)
        erb :'/About/about', :layout => :'/About/layout'
    else
        erb :'badrequest', :layout => :'/APP/layout'
    end
end


######################連絡先ページ(Contactページ)####################
#ログイン必須
get '/contact' do
    if(session[:login_flag] == true)
        erb :'/Contact/contact', :layout => :'/Contact/layout'
    else
        erb :'badrequest', :layout => :'/APP/layout'
    end
end