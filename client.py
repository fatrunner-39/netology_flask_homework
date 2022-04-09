import requests
import datetime

HOST = 'http://127.0.0.1:5000'

# data = requests.post(f'{HOST}/user/', json={
#     'username': 'user',
#     'password': '123456789',
# })

data = requests.post(f'{HOST}/login/', json={
    'username': 'admin3',
    'password': '123456789'
})



# data = requests.get(f'{HOST}/user/14/')

print(data.json())
