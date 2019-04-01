import json
s = {"LHOST":"127.0.0.1",
    "LPORT":"9988",
    "Format":"vbs",
    "payload":"windows/meterpreter/reverse_tcp"
}
print(json.dumps(s))

d = json.loads('{"LPORT": "9988", "Format": "vbs", "LHOST": "127.0.0.1","payload":"windows/meterpreter/reverse_tcp"}')

print(d['LPORT'])