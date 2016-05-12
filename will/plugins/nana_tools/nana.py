import logging
import hashlib
import re
import cPickle as pickle
import requests
from datetime import datetime
from datetime import timedelta
from will.plugin import WillPlugin
from will.decorators import respond_to, periodic, hear, randomly, route, rendered_template, require_settings

from types import DictType

class NanaPlugin(WillPlugin):

    times = {
        "1": timedelta(days=365),
        "2": timedelta(days=30),
        "3": timedelta(days=1),
        "4": timedelta(hours=4),
        "5": timedelta(minutes=30)
    }

    yesregex = re.compile("(yes|yeh|yep|yea|yah|yer|affirmative).*", re.IGNORECASE)
    noregex = re.compile("(no|nope|nah|naw|negative|negatory).*", re.IGNORECASE)

    regexes = {"yes": yesregex, "no": noregex}

    def unpickler(self,someval,retval=None):
        if someval is None:
            return retval
        else:
            return pickle.loads(someval)


    def tattle(self,message):
        m = "%s" % message
        self.send_direct_message("1452942", m)


    @route("/questions", method="POST")
    def question_set(self):
        self._create_question(self.request.json)
        return

    def _create_question(self, question):
        self.bootstrap_storage()
        valid, question, comment = self.validate_question(question)
        if not valid:
            logging.error(comment)
            return

        uid = self.target2uid(question)
        if uid is None:
            identifier = "%s %s %s" % (question.get('targetName',''),question.get('targetEmail',''),question.get('targetID',''))
            self.send_room_message('1365492',"I've received a message for a user I can't identify.\nUser details: %s\nQuestion: %s" % (identifier, question['question']))
        question['uid'] = uid


        m = hashlib.sha1()
        m.update(question['question'])
        question['questionID'] = m.hexdigest()

        qlist = self.unpickler(self.storage.hget("questions",uid),[])
        if qlist is None:
            qlist = []

        self.send_direct_message(uid,question['question'])
        question['timestamp'] = datetime.now()
        question['escalate'] = question['timestamp'] + self.times[question['severity']]

        qlist.append(question)
        self.storage.hset("questions",uid,pickle.dumps(qlist))

    @route('/splunk_alert', method="POST")
    def splunk_alert(self):
        alert_data = self.request.json
        session = requests.Session()
        session.auth = ('admin', 'VjPdrDmA2znHRFneyquuRuE72FF=[')
        session.verify = False
        url = 'https://localhost:8089/services/search/jobs/%(sid)s/results' % alert_data
        params = {
            'output_mode': 'json',
        }
        response = session.get(url, params=params)
        data = response.json()
        if 'results' not in data:
            # TODO: log error
            raise ValueError('Invalid response: No results')
        for result in data['results']:
            field_map = {
                'name': 'targetName',
                'email': 'targetEmail',
                'hipchat_uid': 'targetUID',
                'username': 'targetID',
            }
            question = {}
            for key, value in result.items():
                question[field_map.get(key, key)] = value
            self._create_question(question)

    @periodic(minute='*/5')
    def check_questions(self):
        self.bootstrap_storage()
        t_now = datetime.now()
        self.tattle("checking questions %s" % t_now)
        qs = self.storage.hgetall("questions")
        for uid in qs.keys():
            uid_qs = self.unpickler(qs[uid])
            for q in uid_qs:
                self.tattle("%s: %s" % (uid,q['question']))
                if q['escalate'] <= t_now:
                    self.tattle("I've got to escalate this!")
                    self.escalate_response(q)


    @respond_to("who is (?P<identifier>.*)")
    def whois(self, message, identifier=None):
        """ look up identifier, return some info """
        question = {}
        identifier = identifier.strip()
        question['targetEmail'] = identifier
        question['targetName'] = identifier
        uid = self.target2uid(question)
        if uid is None:
            self.say("I'm afraid I don't know who %s is, dear." % identifier, message=message)
        else:
            self.say("I think %s is %s, don't you?" % (identifier, uid), message=message)


    @respond_to(".*")
    def conversate(self,message):
        # bootstrap storage so we can talk to the hand
        self.bootstrap_storage()
        # get userid from message
        uid = message.sender['id']
        # get outstanding questions for userid
        questions = self.unpickler(self.storage.hget("questions",uid),None)
        if questions is None:
            questions = []
            self.say("I'm sorry dear, I've been distracted lately. I can't remember asking you anything.",message)
            return

        # get last comms timestamp
        timestamp = None
        for q in questions:
            if (timestamp is None) or (q['timestamp'] >= timestamp):
                question = q
                timestamp = q.get('timestamp', None)
        # get last comms valid answers
        # evaluate message v answer options
        for k in question['answers'].keys():
            if self.regexes[k].match(message["body"]):
                self.say("met regex condition", message)
                if question['answers'][k]:
                    self.say("Safe condition, will remove question", message)
                    return
                else:
                    self.say("Oh dear, I'll let the Security Intelligence team know immediately.", message)
                    self.emergency_response(question,message)
                    return

        #if you don't match, ask last question again
        self.say("I'm sorry dear, I don't understand. Here's the last question I asked you, maybe that will help clear things up.", message)
        self.say(question['question'], message)





        # if necessary/possible, validate against 2fa
        # log results in a format that splunk can do whatever with them

    def sorry_what(self,message):
        self.say("Sorry, I didn't understand that.", message)


    def emergency_response(self,question,message):
        response = """Hello SecInt team - I asked %s the question "%s" and they responded "%s" - can you please investigate? """
        self.send_room_message('1365492', response % (message.sender["mention_name"], question["question"], message["body"]), notify=True)


    def escalate_response(self,question):
        response = """Hello SecInt team - I asked %s the question "%s" on %s. This has now timed out, can you please investigate? """
        name = self.uid2name(question['uid'])
        self.send_room_message('1365492', response % (name, question['question'],question['timestamp']), notify=True)


    def validate_question(self, question):
        """ return boolean, question (dict),  string for logging """
        # we need:
        # at least one of targetID, targetName, targetEmail, targetUID
        # a value in 'question'
        # severity should be a string of int 1-5 or not exist -> 3
        # multipleChoice should be boolean or not exist -> False
        # answers should be a dict or not exist (of string(integer) keys to bool values)
        # if multipleChoice is true, answers should exist
        # searchURL should be a valid url or not exist
        # format should be 'HTML' or 'text' or not exist.

        targetID = question.get("targetID", None)
        targetName = question.get("targetName", None)
        targetEmail = question.get("targetEmail", None)
        targetUID = question.get("targetUID", None)
        q = question.get("question", None)
        severity = question.get("severity", "3")
        multipleChoice = question.get("multipleChoice", False)
        answers = question.get("answers", None)
        searchURL = question.get("searchURL", None)
        fmt = question.get("format", "text")

        return_comment = ""
        return_value = True

        if q is None:
            return_value = False
            return_comment += " No identifiable question in question."

        if (targetUID is None) and (targetEmail is None) and (targetName is None) and (targetID is None):
            return_value = False
            return_comment += " No identifiable targets in question."

        if severity not in ["1", "2", "3", "4", "5"]:
            return_comment += " Severity incorrect: %s." % severity
            severity = "3"

        if multipleChoice not in [True,False]:
            return_comment += " multipleChoice incorrect: %s." % multipleChoice
            multipleChoice = False

        if answers is None or not isinstance(answers, dict):
            return_comment += " setting answers to default from: %s." % answers
            answers = {"yes": True, "no": False}

        if fmt not in ["HTML","text"]:
            return_comment += " format incorrect: %s." % fmt
            fmt = "text"

        question['question'] = q
        question['targetName'] = targetName
        question['targetID'] = targetID
        question['targetEmail'] = targetEmail
        question['targetUID'] = targetUID
        question['severity'] = severity
        question['multipleChoice'] = multipleChoice
        question['answers'] = answers
        question['searchURL'] = searchURL
        question['format'] = fmt

        return(return_value,question,return_comment)


    def uid2name(self,uid):
        self.bootstrap_storage()
        users = self.load("will_roster")
        u = users[uid]
        return u["mention_name"]


    def target2uid(self, question):
        self.bootstrap_storage()

        targetUID = question.get("targetUID", None)
        if targetUID:
            return targetUID
        self.map_hipchat_users(False)

        for t in ["targetEmail", "targetID", "targetName"]:
            ti = question.get(t, None)
            if ti:
                uid = self.storage.hget("user:transforms", ti)
                if uid:
                    return uid



        # call hipchat, ask them about email address
        te = question.get('targetEmail',None)
        if te:
            try:
                user = self.get_hipchat_user(te)
                logging.info("Got user %s with email %s" % (user['id'],te))
                print user
                #cache this
                #self.storage.hset("user:transforms",te,user['id'])
                return user['id']
            except KeyError:
                user = None
                logging.error("Could not find HipChat user with email %s" % te)

        # failing that, look through users and see if you can find them by name
        if 'targetName' in question:
            users = self.load("will_roster")
            for user in users.values():
                if question['targetName'] in user['name']:
                    uid = user['id']
                    return uid



        return None
