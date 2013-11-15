import httplib
import json

class StaticFlowPusher(object):

    def __init__(self, server):
        self.server = server

    def get(self, data):
        ret = self.rest_call({}, 'GET')
        return json.loads(ret[2])

    def set(self, data):
        ret = self.rest_call(data, 'POST')
        return ret[0] == 200

#    def remove(self, objtype, data):
    def remove(self, data):
        ret = self.rest_call(data, 'DELETE')
        return ret[0] == 200

    def rest_call(self, data, action):
        path = '/wm/staticflowentrypusher/json'
        headers = {
            'Content-type': 'application/json',
            'Accept': 'application/json',
            }
        body = json.dumps(data)
        conn = httplib.HTTPConnection(self.server, 8080)
        conn.request(action, path, body, headers)
        response = conn.getresponse()
        ret = (response.status, response.reason, response.read())
        print ret
        conn.close()
        return ret

pusher = StaticFlowPusher('p-rambo')

switches = {
    '4':'00:00:4a:9a:54:cc:e8:43',
    '6':'00:00:7a:3c:62:aa:fa:4d',
    '8':'00:00:f6:98:d9:07:6b:42',
    '3':'00:00:9e:28:13:7a:21:4c',
    '2':'00:00:be:5a:aa:32:8c:4f',
    '1':'00:00:d6:2c:14:db:3d:44',
    '7':'00:00:82:12:65:30:4f:4e',
    '5':'00:00:f6:eb:87:fd:73:47'
    }

hosts = {
'hacker02':'00:16:3e:5e:21:83',
'hacker04':'00:16:3e:65:b9:5a',
'web':'00:16:3e:41:75:ed',
'hacker01':'00:16:3e:41:5c:55',
'fw':'00:16:3e:7e:33:bd',
'hacker03':'00:16:3e:72:ab:44',
'dmz':'00:16:3e:04:0d:b7'
        }

def create_dic(switch, inp, outp, hostsrc, hostdst):
    d =	{
        'switch':switches[switch],
        "name":'flow-%s%s%s' % (hostsrc, hostdst, switch),
        "cookie":"0",
        "priority":"32768",
        "ingress-port":'%i' % inp,
        "active":"true",
        "actions":"output=%i" % outp,
        "src-mac":hosts[hostsrc],
        "dst-mac":hosts[hostdst]
        }
    return d

#def create_dic(switch, name, inp, outp, hostsrc, hostdst):

#pusher.set(flow_fwweb6)
#pusher.set(flow_webfw6)

action = pusher.set

action(create_dic('6', 5, 2, 'web', 'fw'))
action(create_dic('6', 2, 5, 'fw', 'web'))

action(create_dic('7', 4, 2, 'fw', 'web'))
action(create_dic('7', 2, 4, 'web', 'fw'))
