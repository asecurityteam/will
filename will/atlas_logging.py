import traceback
import json_log_formatter
from datetime import datetime

# json_log_formatter does the following:
# message = record.getMessage()
# extra = self.extra_from_record(record)
# json_record = self.json_record(message, extra, record)
# self.mutate_json_record(json_record)
# return self.json_lib.dumps(json_record)

class AtlasFormat(json_log_formatter.JSONFormatter):

    product = None
    hostname = None

    def __init__(self, **kwargs):
        
        if "hostname" in kwargs:
            self.hostname = kwargs["hostname"]
        if "product" in kwargs:
            self.product = kwargs["product"]




    def json_record(self, message, extra, record):

        results = self.new_logskeleton.copy()
        results["time"] = datetime.utcnow()
        results["level"] = record.levelname
        results["msg"] = message

        results["ctx"]["pid"] = record.process
        results["ctx"]["name"] = record.processName
        results["ctx"]["thread"] = record.thread
        results["ctx"]["thread_name"] = record.threadName
        results["ctx"]["product"] = extra.pop("product", self.product)
        results["ctx"]["request_id"] = extra.pop("request_id", None)
        results["ctx"]["transaction_id"] = extra.pop("transaction_id", None)
        results["ctx"]["src_ip"] = extra.pop("src_ip", None)

        results["user"]["uid"] = extra.pop("uid", extra.pop("user", None)) #is this even legal
        results["user"]["auth_realm"] = extra.pop("auth_realm", None)
        results["user"]["session_id"] = extra.pop("session_id", None)
        results["user"]["device_id"] = extra.pop("device_id", None)
        results["user"]["customer"] = extra.pop("customer", None)

        results["host"]["dest_ip"] = extra.pop("dest_ip", None)
        results["host"]["hostname"] = extra.pop("hostname", self.hostname)

        results["action"]["object"] = extra.pop("object", None)
        results["action"]["action"] = extra.pop("action", None)
        results["action"]["status"] = extra.pop("status", None)
        results["action"]["result"] = extra.pop("result", None)
        
        if record.exc_info:
            record.exc_info = ''.join(
                traceback.format_exception(
                    record.exc_info[0],record.exc_info[1],record.exc_info[2]
                )
            )
            results["action"]["stack"] = record.exc_info

        for k,v in extra.iteritems():
            results["extra"][k]=v

        for key in ["ctx", "user", "host", "action"]:
            for k in results[key].keys():
                if results[key][k] is None:
                    del results[key][k]

        return results

# these do not need to be here. But they are.

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
        },
        "extra": {}
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