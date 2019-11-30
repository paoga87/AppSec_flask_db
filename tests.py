import requests
from bs4 import BeautifulSoup

server_address = 'http://127.0.0.1:5000'

def getElementById(html, theId):
    soup = BeautifulSoup(html, 'html.parser')
    r = soup.find(id=theId)
    return r

def register(uname, pword, twofa, session=None):
    url = server_address + '/register'
    if session is None:
        session = requests.session()
        session.close()

    credentials = {'uname': uname, 'pword': pword, '2fa': twofa}
    r = session.post(url, data=credentials)
    result = getElementById(r.text, 'success')
    if result is None:
        print('Unable to find id=result')
        return {'result': False, 'session': session}

    if 'success' in result.text:
        # Server response = successful
        return {'result': True, 'session': session}
    elif 'failure' in result.text:
        # Server response = failed
        return {'result': False, 'explicit_failure': True, 'session': session}
    else:
        # No response from server
        return {'result': False, 'explicit_failure': False, 'session': session}

def login(uname, pword, twofa, session=None):
    url = server_address + '/login'
    if session is None:
        session = requests.session()
        session.close()  # close any previous session if exist

    creds = {'uname': uname, 'pword': pword, '2fa': twofa}
    r = session.post(url, data=creds)
    result = getElementById(r.text, 'result')
    if result is None:
        print('Cannot find id=result in response')
        return {'result': False, 'session': session}

    if 'success' in result.text:
        return {'result': True, 'session': session}
    else:
        return {'result': False, 'session': session}

def index_page_exists():
    req = requests.get(server_address + '/')
    assert req.status_code == 200, "Status code not 200"

def login_page_exists():
    req = requests.get(server_address + '/login')
    assert req.status_code == 200, "Status code not 200"

def register_page_exists():
    req = requests.get(server_address + '/register')
    assert req.status_code == 200, "Status code not 200"

def spell_page_exists():
    req = requests.get(server_address + '/spell_check')
    assert req.status_code == 200, "Status code not 200"

def logout_page_exists():
    req = requests.get(server_address + '/logout')
    assert req.status_code == 200, "Status code not 200"
