import unittest
import uuid as _uuid

import mysql.hub.errors as _errors
import tests.utils as _test_utils

from mysql.hub.server import MySQLServer, Group
from mysql.hub.persistence import MySQLPersister

class TestGroup(unittest.TestCase):

    __metaclass__ = _test_utils.SkipTests

    def setUp(self):
        self.persister = MySQLPersister("localhost:13000","root", "")
        Group.create(self.persister)
        MySQLServer.create(self.persister)

    def tearDown(self):
        Group.drop(self.persister)
        MySQLServer.drop(self.persister)

    def test_group_constructor(self):
        group_1 = Group.add(self.persister, "mysql.com", "First description.")
        group_2 = Group.fetch(self.persister, "mysql.com")
        self.assertEqual(group_1, group_2)

    def test_add_server(self):
        group_1 = Group.add(self.persister, "mysql.com", "First description.")
        options_1 = {
            "persister" : self.persister,
            "uuid" :  _uuid.UUID("{bb75b12b-98d1-414c-96af-9e9d4b179678}"),
            "uri"  : "server_1.mysql.com:3060",
            "user" : "user",
            "passwd" : "passwd"
        }
        server_1 = MySQLServer.add(**options_1)
        options_2 = {
            "persister" : self.persister,
            "uuid" :  _uuid.UUID("{aa75a12a-98d1-414c-96af-9e9d4b179678}"),
            "uri"  : "server_2.mysql.com:3060",
            "user" : "user",
            "passwd" : "passwd"
        }
        server_2 = MySQLServer.add(**options_2)
        group_1.add_server(self.persister, server_1)
        group_1.add_server(self.persister, server_2)

        self.assertTrue(group_1.contains_server(self.persister, server_1.uuid))
        self.assertTrue(group_1.contains_server(self.persister, server_2.uuid))

    def test_remove_server(self):
        group_1 = Group.add(self.persister, "mysql.com", "First description.")
        options_1 = {
            "persister" : self.persister,
            "uuid" :  _uuid.UUID("{bb75b12b-98d1-414c-96af-9e9d4b179678}"),
            "uri"  : "server_1.mysql.com:3060",
            "user" : "user",
            "passwd" : "passwd"
        }
        server_1 = MySQLServer.add(**options_1)
        options_2 = {
            "persister" : self.persister,
            "uuid" :  _uuid.UUID("{aa75a12a-98d1-414c-96af-9e9d4b179678}"),
            "uri"  : "server_2.mysql.com:3060",
            "user" : "user",
            "passwd" : "passwd"
        }
        server_2 = MySQLServer.add(**options_2)
        group_1.add_server(self.persister, server_1)
        group_1.add_server(self.persister, server_2)

        self.assertTrue(group_1.contains_server(self.persister,
            server_1.uuid))
        self.assertTrue(group_1.contains_server(self.persister,
            server_2.uuid))

        group_1.remove_server(self.persister, server_1)
        group_1.remove_server(self.persister, server_2)

        self.assertFalse(group_1.contains_server(self.persister,
            server_1.uuid))
        self.assertFalse(group_1.contains_server(self.persister,
            server_2.uuid))

    def test_update_description(self):
         group_1 = Group("mysql.com", "First description.")
         group_1.set_description(self.persister, "Second Description.")
         self.assertEqual(group_1.get_description(), "Second Description.")

    def test_remove_group(self):
         group_1 = Group.add(self.persister, "mysql.com", "First description.")
         group_1.remove(self.persister)
         self.assertEqual(Group.fetch
                          (self.persister, "mysql.com"), None)

    def test_MySQLServer_create(self):
        options_1 = {
            "persister" : self.persister,
            "uuid" :  _uuid.UUID("{bb75b12b-98d1-414c-96af-9e9d4b179678}"),
            "uri"  : "server_1.mysql.com:3060",
            "user" : "user",
            "passwd" : "passwd"
        }
        server_1 = MySQLServer.add(**options_1)
        options_2 = {
            "persister" : self.persister,
            "uuid" :  _uuid.UUID("{aa75a12a-98d1-414c-96af-9e9d4b179678}"),
            "uri"  : "server_2.mysql.com:3060",
            "user" : "user",
            "passwd" : "passwd"
        }
        server_2 = MySQLServer.add(**options_2)
        MySQLServer.fetch(self.persister, options_1["uuid"])
        MySQLServer.fetch(self.persister, options_2["uuid"])

    def test_MySQLServer_User(self):
        options_1 = {
            "persister" : self.persister,
            "uuid" :  _uuid.UUID("{bb75b12b-98d1-414c-96af-9e9d4b179678}"),
            "uri"  : "server_1.mysql.com:3060",
            "user" : "user",
            "passwd" : "passwd"
        }
        server_1 = MySQLServer.add(**options_1)

        options_2 = {
            "persister" : self.persister,
            "uuid" :  _uuid.UUID("{aa75a12a-98d1-414c-96af-9e9d4b179678}"),
            "uri"  : "server_2.mysql.com:3060",
            "user" : "user",
            "passwd" : "passwd"
        }
        server_2 = MySQLServer.add(**options_2)

        server_1.set_user(self.persister, "u1")
        server_2.set_user(self.persister, "u2")

        server_1_ = MySQLServer.fetch(self.persister, options_1["uuid"])
        server_2_ = MySQLServer.fetch(self.persister, options_2["uuid"])

        self.assertEqual(server_1.get_user(), "u1")
        self.assertEqual(server_2.get_user(), "u2")

        self.assertEqual(server_1, server_1_)
        self.assertEqual(server_2, server_2_)


    def test_MySQLServer_Password(self):
        options_1 = {
            "persister" : self.persister,
            "uuid" :  _uuid.UUID("{bb75b12b-98d1-414c-96af-9e9d4b179678}"),
            "uri"  : "server_1.mysql.com:3060",
            "user" : "user",
            "passwd" : "passwd"
        }
        server_1 = MySQLServer.add(**options_1)
        options_2 = {
            "persister" : self.persister,
            "uuid" :  _uuid.UUID("{aa75a12a-98d1-414c-96af-9e9d4b179678}"),
            "uri"  : "server_2.mysql.com:3060",
            "user" : "user",
            "passwd" : "passwd"
        }
        server_2 = MySQLServer.add(**options_2)

        server_1.set_passwd(self.persister, "p1")
        server_2.set_passwd(self.persister, "p2")

        server_1_ = MySQLServer.fetch(self.persister, options_1["uuid"])
        server_2_ = MySQLServer.fetch(self.persister, options_2["uuid"])

        self.assertEqual(server_1.get_passwd(), "p1")
        self.assertEqual(server_2.get_passwd(), "p2")

        self.assertEqual(server_1, server_1_)
        self.assertEqual(server_2, server_2_)

    def test_MySQLServer_Remove(self):
        options_1 = {
            "persister" : self.persister,
            "uuid" :  _uuid.UUID("{bb75b12b-98d1-414c-96af-9e9d4b179678}"),
            "uri"  : "server_1.mysql.com:3060",
            "user" : "user",
            "passwd" : "passwd"
        }
        server_1 = MySQLServer.add(**options_1)
        options_2 = {
            "persister" : self.persister,
            "uuid" :  _uuid.UUID("{aa75a12a-98d1-414c-96af-9e9d4b179678}"),
            "uri"  : "server_2.mysql.com:3060",
            "user" : "user",
            "passwd" : "passwd"
        }
        server_2 = MySQLServer.add(**options_2)

        MySQLServer.fetch(self.persister, options_1["uuid"])
        MySQLServer.fetch(self.persister, options_2["uuid"])
        server_1.remove(self.persister)
        server_2.remove(self.persister)

        server_1_ = MySQLServer.fetch(self.persister, options_1["uuid"])
        server_2_ = MySQLServer.fetch(self.persister, options_2["uuid"])

        self.assertEqual(server_1_, None)
        self.assertEqual(server_2_, None)
