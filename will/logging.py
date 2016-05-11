import json_log_formatter
from datetime import datetime

# json_log_formatter does the following:
message = record.getMessage()
extra = self.extra_from_record(record)
json_record = self.json_record(message, extra, record)
self.mutate_json_record(json_record)
retunr self.json_lib.dumps(json_record)

class AtlasFormat(json_log_formatter.JSONFormatter):
    def json_record(self, message, extra, record):
        results = self.new_logskeleton.copy()
        results["time"] = datetime.utcnow()
        results["level"] = record.levelname
        results["msg"] = record.message
        results["ctx"]["pid"] = record.process
        results["ctx"]["name"] = record.processName
        results["ctx"]["thread"] = record.thread
        results["ctx"]["thread_name"] = record.threadName
        results["ctx"]["product"] = settings!!
        results["ctx"]["request_id"] = extra.get("request_id", None)
        results["ctx"]["transaction_id"] = extra.get("transaction_id", None)


        pass


    def extra_from_record(self,record):
        pass




    new_logskeleton = {
        "time": None,
        "level": None,
        "msg": None,
        "ctx": {
            "pid": None,
            "name": None,
            "thread": None,
            "product": None,
            "request_id": None,
            "transaction_id": None,
            "src_ip": None,
        },
        "user": {
            "uid": None,
            "auth_realm": None,
            "session_id": None,
            "device_id": None,
            "customer": None,

        },
        "host": {
            "dest_ip": None,
            "hostname": None,

        },
        "action": {
            "object": None,
            "action": None,
            "status": None,
            "result": None,
            "stack": None,
        }
    }

    logskeleton = {
        "time": None,
        "level": None,
        "pid": None,
        "thread": None,
        "name": None,
        "msg": None,
        "ctx": {
            "product": None,
            "reqId": None,
            "session": None,
            "userKey": None
        },
        "host": {
            "dc": None,
            "rack": None,
            "node": None,
            "name": None,
            "ip": None,
            "port": None
        },

        "err": {
            "msg": None,
            "stack": None
        }
    }