'''
    mqbgp - Module for processing BGP updates (announce/withdraw) with Message Queueing bus 
    
    The implementation uses RabbitMQ as message broker and AMQP as messaging standard
    This library standardize the BGP message types and send and receive functions

    The following types of messages are implemented in this library:
    * PrefixMessage (BGP announce or withdraw)
    * PrefixListMessage (actual list of advertised) BGP prefixes
    * PrefixListRequestMessage (requesting a PrefixListMessage)
    
    The idea with PrefixListMessage is a system keeping track of the PrefixMessages and is able to supply the current
    list of BGP prefixes. This system can sent it by itself (periodcally) or on request, by receiving a PrefixListRequestMessage()

    Created on 30 jun. 2017

    @author: Pim van Stam <pim@svsnet.nl>
    Modifications:
    0.1.1 - 17-09-2018: in channel.exchange_declare use exchange_type, 'type' is deprecated
    0.1.2 - 18-09-2018: removed some logging
    0.1.3 - 09-01-2020: in class Queue define echanges as durable in channel.exchange_declare()
                        parameter 'durable' in config.yml supported
    0.1.4 - 09-01-2020: parameter queue='' in self.channel.queue_declare()
    0.2.0 - 09-01-2020: added as_path and community in class PrefixMessage
    0.2.1 - 15-01-2020: rename to mqbgp
'''
__VERSION__="0.2.1"

import sys
import pika
import json
import logging
import yaml

DEFAULT_CONFIG = "/etc/exabgp/config.yml"


'''
    Message classes:
    _Message(): default message class with predefined attributes and methods
    PrefixMessage(): BGP announce/advertisement or withdraw of a prefix
    PrefixListMessage(): Publish the actual list of advertised prefixes
    PrefixListRequestMessage(): Message for requesting the actual prefix list

'''

class _Message():
    ''' Define the standard message class in the NaWas message queueing module
    '''

    def __init__(self):
        self.routing_key = ".*"
        self.dict={}

    def get_routing_key(self):
        return self.routing_key

    def set_routing_key(self, routing_key):
        self.routing_key = routing_key
        
    def get_message(self):
        return self.dict

    def set_message(self, dict):
        for item in dict.keys():
            self.dict[item] = dict[item]

    def encode_message(self):
        return json.dumps(self.dict)

    def decode_message(self, encoded_message):
        try:
            json_object = json.loads(encoded_message)
        except json.decoder.JSONDecodeError as err:
            logger = logging.getLogger(__name__)
            logger.error("Invalid JSON: " + err.msg)
            return None

        # Loop over class attributes and try to set these based on json data
        for key in self.dict.keys():
            try:
                self.dict[key] = json_object[key]
            except KeyError:
                self.dict[key] = ""

        return self.dict

    def send(self, queue):
        encoded_message = self.encode_message()
        queue.publish_message(self.routing_key, encoded_message)


class PrefixMessage(_Message):
    ''' Announcement/advertisement or withdraw of a BGP prefix
        The AS number of the party of the prefix and the prefix are part of the message
    '''

    TYPE_ANNOUNCE = 'announce'
    TYPE_WITHDRAW = 'withdraw'

    ROUTING_KEY_ANNOUNCE = 'prefix.announce'
    ROUTING_KEY_WITHDRAW = 'prefix.withdraw'
    ROUTING_KEY_ALL = 'prefix.*'

    def __init__(self, asn="", prefix="", nexthop="", announce=True, as_path="", community=""):

        self.dict={"asn": asn,
                   "prefix": prefix,
                   "nexthop": nexthop,
                   "type": self.TYPE_ANNOUNCE if announce else self.TYPE_WITHDRAW,
                   "as_path": as_path,
                   "community": community
        }
        self.routing_key = self.ROUTING_KEY_ANNOUNCE if announce else self.ROUTING_KEY_WITHDRAW


    def set_message(self, asn="", prefix="", nexthop="", announce=True, as_path="", community=""):

        self.dict={"asn": asn,
                   "prefix": prefix,
                   "nexthop": nexthop,
                   "type": self.TYPE_ANNOUNCE if announce else self.TYPE_WITHDRAW,
                   "as_path": as_path,
                   "community": community
        }



class PrefixListMessage(_Message):
    ''' Publish the actual list of prefixes on request or with a new prefix

        The Message body contains a list of PrefixMessages
        Parameter requested is True with an ad-hoc request. It is False with
        periodic updates of the Prefixlist or with a new PrefixMessage.
        Scenarios:
        * The listener of PrefixMessages can send the actual prefixlist. Requested is then False
        * A listener can send regular updates of the actual prefixlist. Requested = False
        * A listener can request a prefixlist on ad-hoc basis. This listener will sent
          a PrefrixListRequestMessage. The response has Requested = True.
    '''

    ROUTING_KEY_UPDATE = 'prefixlist.update'
    ROUTING_KEY_REQUESTED = 'prefixlist.requested'
    ROUTING_KEY_ALL = 'prefixlist.*'

    def __init__(self, list=[], requested=False):

        lst = []
        if len(list) != 0:
            for item in list:
                lst.append(item)

        self.dict = {"list": lst,
                     "requested": requested
        }
        self.routing_key = self.ROUTING_KEY_REQUESTED if requested else self.ROUTING_KEY_UPDATE

    def set_list(self, prefixlist):
        self.dict["list"] = prefixlist

    def get_list(self):
        return self.dict["list"]
    
    def add_prefix(self, prefix_dict):
        self.dict["list"].append(prefix_dict)


class PrefixListRequestMessage(_Message):
    ''' Request a actual list of prefixes
        A listener to this type of requests should publish the list with a PrefixListMessage()
    '''

    ROUTING_KEY_ALL = ROUTING_KEY_REQUEST = 'prefixlist.request'

    def __init__(self):

        self.dict = {"request" :True}
        self.routing_key = self.ROUTING_KEY_REQUEST



'''
    Queue class and functions
    Subscribe to RabbitMQ queues
    Config for the queue is in a yaml config file
'''

class Queue:

    def __init__(self, configfile = DEFAULT_CONFIG):
        ''' Initialize the Queue object with config file as attribute '''
        self.logger = logging.getLogger(__name__)
        self.configfile = configfile

    def connect(self):
        ''' Read the configuration from the config file and connect to the message broker.
            In the config file the credentials, host and exchange to connect to
        '''
        try:
            with open(self.configfile, 'r') as ymlfile:
                cfg = yaml.safe_load(ymlfile)
        except FileNotFoundError as err:
            self.logger.error("Can't load config file: " + str(err))
            sys.exit(1)

        credentials = pika.PlainCredentials(cfg['rabbitmq']['user'], cfg['rabbitmq']['password'])
        parameters = pika.ConnectionParameters(cfg['rabbitmq']['host'],
                                               cfg['rabbitmq']['port'],
                                               '/',
                                               credentials)
        self.exchange = cfg['rabbitmq']['exchange']

        try:
            self.connection = pika.BlockingConnection(parameters)
        except pika.exceptions.ProbableAuthenticationError as err:
            self.logger.error("Authentication error")
            sys.exit(1)

        self.channel = self.connection.channel()

        durable = cfg['rabbitmq'].get('durable', True)
        self.logger.info("Durable = " + str(durable))
        self.channel.exchange_declare(exchange=self.exchange,
                                      exchange_type='topic',
                                      durable=durable)
    

    def disconnect(self):
        self.connection.close()

    def publish_message(self, routing_key, message):

        self.channel.basic_publish(exchange=self.exchange,
                              routing_key=routing_key,
                              body=message)


    def subscribe(self, routing_key, callback):

        result = self.channel.queue_declare(queue='', exclusive=True)
        queue_name = result.method.queue

        self.channel.queue_bind(exchange=self.exchange,
                                 queue=queue_name,
                                 routing_key=routing_key)

        print(queue_name)
        self.channel.basic_consume(queue=queue_name,
                                   on_message_callback=callback)
#                                   auto_ack=True)

        try:
            self.channel.start_consuming()
        except KeyboardInterrupt:
            self.channel.stop_consuming()
            self.disconnect()
            sys.exit(0)
    


'''
    mqbgp listener and send classes and functions
'''

class Listener:
    '''
        Listener for a Message Queue and pass messages to a call back functions
        The listener creates a Queue object and subscribe to the message broker.
        Then waits for incoming messages and pass them on.
    '''

    def __init__(self, configfile = DEFAULT_CONFIG):
        ''' Initialize the listener by creating a Queue object and connect to
            the message broker of this queue. Config in the config file
        '''
        self.mq = Queue(configfile)
        self.mq.connect()
        self.logger = logging.getLogger(__name__)


    def listen(self, message_class:_Message, user_callback, routing_key = None):

        self.user_callback = user_callback
        self.message_class = message_class
        if routing_key == None:
            routing_key = self.message_class.ROUTING_KEY_ALL

        self.mq.subscribe(routing_key, self.convert_to_message_object)
        self.mq.disconnect()


    def convert_to_message_object(self, ch, method, properties, body):

        # Create new blank message object
        message = self.message_class()

        # Try to convert rabbitmq message to message object
        if message.decode_message(body.decode('UTF-8')) != None:

            # Call user callback with the new message object
            self.user_callback(message)

        ch.basic_ack(delivery_tag=method.delivery_tag)
        

        

if __name__ == '__main__':
    pass
