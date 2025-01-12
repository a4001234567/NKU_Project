from login_standalone import eam_login,login,new_session
from datetime import datetime, timedelta
import getpass
import json
import time
import os

class account:
    def __init__(self,aid,apassword):
        self.ID = aid
        self.PASSWORD = apassword

target_time = "14:00:00.300"  # Example with milliseconds
pID = '1690'
cID = '595903'

def execute(sess):
    data = dict()
    data['optype'] = 'true'
    data['operator0'] = f'{cID}:true:0'
    data['lesson0'] = cID
    data[f'expLessonGroup_{cID}'] = 'undefined'
    #data = f'optype=true&operator0={cID}%3Atrue%3A0&lesson0={cID}&expLessonGroup_{cID}=undefined'
    headers = dict()
    headers['Content-Type'] = 'application/x-www-form-urlencoded; charset=UTF-8'
    response = sess.post(f'https://eamis.nankai.edu.cn/eams/stdElectCourse!batchOperator.action?profileId={pID}',headers=headers, allow_redirects=False,data = data)
    print(response.text)
    print("Executed at", datetime.now().strftime("%H:%M:%S.%f"))
    time.sleep(1.2)
    response = sess.post(f'https://eamis.nankai.edu.cn/eams/stdElectCourse!batchOperator.action?profileId={pID}', data = data, headers=headers)
    print(response.text)
    print("Executed at", datetime.now().strftime("%H:%M:%S.%f"))

if __name__ == "__main__":
    user_name = input("USERNAME:")
    password = ''
    if os.path.exists("passwords.list"):
        with open("passwords.list",'r') as file:
            for line in file:
                if line.startswith(user_name):
                    password = line.split('\t')[-1].rstrip()
                    print("getting password from cache...")
    if not password:
        password = getpass.getpass("PASSWORD:")
        with open("passwords.list","a") as file:
            file.write(f"\n{user_name}\t{password}")
    my_account = account(user_name,password)
    sess = new_session()
    s = login(sess,'https://sso.nankai.edu.cn/sso/login?service=https://dzpz.nankai.edu.cn',my_account)
    sess = None
    import time
    while True:
        current_time = datetime.now()
        target_datetime = datetime.combine(current_time.date(), datetime.strptime(target_time, "%H:%M:%S.%f").time())
        
        if current_time >= target_datetime:
            execute(sess)
            break

        time_diff = (target_datetime - current_time).total_seconds()
        if time_diff <= 60:
            if not sess:
                sess,_ = eam_login(my_account)
                sess.get('https://eamis.nankai.edu.cn/eams/stdElectCourse.action?_='+str(int(1000*time.time())))
                sess.get(f'https://eamis.nankai.edu.cn/eams/stdElectCourse!defaultPage.action?electionProfile.id={pID}')
                sess.get(f'https://eamis.nankai.edu.cn/eams/stdElectCourse!data.action?profileId={pID}')
        
        sleep_time = max(0.001, time_diff / 2)  # Sleep for half the remaining time, but at least 1 millisecond
        time.sleep(sleep_time)
