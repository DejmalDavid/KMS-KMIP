#Writed by David Dejmal for Master Thesis 2021
#saves whole object to etcd (etcd version 3)

from kmip.pie import objects

import etcd3
import pickle
import logging

class ETCDwrapper:

    # init method or constructor
    def __init__(self, ip, port):
        self._logger = logging.getLogger('kmip.server.engine')
        self.ip = ip
        self.port = port

    # Sample Method
    def connect(self):
        #read username and password
        try:
            with open ("/home/pykmip-server-user/.secrets/etcd_user_username.txt", "r") as etcd_user_username:
                etcd_username=etcd_user_username.read().strip()
            with open ("/home/pykmip-server-user/.secrets/etcd_user_password.txt", "r") as etcd_user_password:
                etcd_password=etcd_user_password.read().strip()
        except Exception as ex:
            self._logger.warning("Problem with reading username and password from /home/pykmip-server-user/.secrets/")
            raise
        #connect to etcd
        try:
            self.client = etcd3.client(host=self.ip, port=self.port, user=etcd_username, password=etcd_password)
        except Exception as ex:
            self._logger.warning("Cannot connect to ETCD! Please make sure that ETCD is running on "+ self.ip +":" + str(self.port) + " and credentials are correct.")
            raise
        self._logger.info('Connect ETCD')

    def add(self, object):
        self.connect()
        #print('ADD ETCDwrapper')
        #print(object)

        try:
            #if is empty return b'0' == int(0)
            object_counter = self.client.get("/general/object_counter")
            if object_counter[0] is None:
                self._logger.warning("Object:/general/object_counter not found")
                raise

            object_counter = int(object_counter[0])
            #print(object_counter)
            object_counter+=1
            #print(object_counter)

        except Exception as ex:
            self._logger.warning("Error while geting object_counter, please fix etcd...")
            raise

        object.unique_identifier=object_counter
        #refer to line 107 in pie.objects.py
        object.operation_policy_name="default"

        #serializable
        pickled = pickle.dumps(object)

        #print(pickled)
        #print(type(pickled))  # <class 'bytes'>

        store_path = "/managed_objects/" + str(object_counter)
        #print(store_path)

        #check if set path is empty
        object = self.client.get(store_path)
        if object[0] is not None:
            self._logger.warning("Object:" + store_path + " already exist, please check /general/object_counter")
            raise

        #set counter and value itself
        self.client.put('/general/object_counter', str(object_counter))
        self.client.put(store_path, pickled)
        #print("Object counter:" + str(object_counter))
        #print("ADD END ETCDwrapper")

    def find(self, uid): 
        self.connect()
        #print('FIND ETCDwrapper')

        find_path = "/managed_objects/" + str(uid)
        #print(find_path)
        object = self.client.get(find_path)
        #print(object)

        if object[0] is None:
            self._logger.warning("Object:" + uid + " not found")
            raise
        #print("FIND END ETCDwrapper")
        return pickle.loads(object[0])

    def delete(self, uid): 
        self.connect()
        #print('DELETE ETCDwrapper')
        #print(uid)

        path = "/managed_objects/" + str(uid)

        #print(path)

        result = self.client.delete(path)
        if result == False:
            self._logger.warning("Deleted object " + path + "already not exist! Potencial error, chceck database!")
            raise

    def update(self, uid ,object): 
        self.connect()
        #print('UPDATE ETCDwrapper')
        #print(uid)
        #print(object)

        update_path = "/managed_objects/" + str(uid)
        old_object = self.client.get(update_path)
        #print(object)

        if old_object[0] is None:
            self._logger.warning("Object:" + update_path + " not found for update")
            raise

        #serializable
        pickled = pickle.dumps(object)
        self.client.put(update_path, pickled)
        #print('UPDATE END ETCDwrapper')

    def find_all(self):
        self.connect()
        #print('FINDALL ETCDwrapper')

        objects_tuples = self.client.get_prefix("/managed_objects/")

        objects_list = list()

        for object in objects_tuples:
            #print(pickle.loads(object[0]))
            objects_list.append(pickle.loads(object[0]))

        #print(len(objects_list))
        #print('FINDALL END ETCDwrapper')

        return objects_list
