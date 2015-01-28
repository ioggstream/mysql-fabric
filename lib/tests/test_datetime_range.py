#
# Copyright (c) 2014, Oracle and/or its affiliates. All rights reserved.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; version 2 of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
#

"""Tests RANGE shard splits and also the impact of the splits
on the global server.
"""

import unittest
import uuid as _uuid
import time
import tests.utils

from mysql.fabric import executor as _executor
from mysql.fabric.server import (
    Group,
    MySQLServer,
)

import mysql.fabric.errors as _errors

from tests.utils import MySQLInstances

class TestDateTimeRange(tests.utils.TestCase):
    """Contains unit tests for testing the shard split operation and for
    verifying that the global server configuration remains constant after
    the shard split configuration.
    """

    def assertStatus(self, status, expect):
        items = (item['diagnosis'] for item in status[1] if item['diagnosis'])
        self.check_xmlrpc_command_result(status)

    def setUp(self):
        """Creates the topology for testing.
        """
        tests.utils.cleanup_environment()
        self.manager, self.proxy = tests.utils.setup_xmlrpc()

        self.__options_1 = {
            "uuid" :  _uuid.UUID("{aa75b12b-98d1-414c-96af-9e9d4b179678}"),
            "address"  : MySQLInstances().get_address(0),
            "user" : MySQLInstances().user,
            "passwd": MySQLInstances().passwd,
        }

        uuid_server1 = MySQLServer.discover_uuid(self.__options_1["address"])
        self.__options_1["uuid"] = _uuid.UUID(uuid_server1)
        self.__server_1 = MySQLServer(**self.__options_1)
        MySQLServer.add(self.__server_1)
        self.__server_1.connect()
        self.__server_1.exec_stmt("CREATE DATABASE IF NOT EXISTS db1")
        self.__server_1.exec_stmt("CREATE TABLE IF NOT EXISTS db1.t1"
                                  "(date_of_joining DATETIME, name VARCHAR(30))")
        self.__server_1.exec_stmt("CREATE DATABASE IF NOT EXISTS db2")
        self.__server_1.exec_stmt("CREATE TABLE IF NOT EXISTS db2.t2"
                                  "(date_of_joining DATETIME, name VARCHAR(30))")
        self.__server_1.exec_stmt("CREATE DATABASE IF NOT EXISTS db3")
        self.__server_1.exec_stmt("CREATE TABLE IF NOT EXISTS db3.t3"
                                  "(date_of_joining VARCHAR(30), name VARCHAR(30))")
        self.__server_1.exec_stmt("CREATE DATABASE IF NOT EXISTS db4")
        self.__server_1.exec_stmt("CREATE TABLE IF NOT EXISTS db4.t4"
                                  "(date_of_joining TEXT, name VARCHAR(30))")

        self.__group_1 = Group("GROUPID1", "First description.")
        Group.add(self.__group_1)
        self.__group_1.add_server(self.__server_1)
        tests.utils.configure_decoupled_master(self.__group_1, self.__server_1)

        self.__options_2 = {
            "uuid" :  _uuid.UUID("{aa45b12b-98d1-414c-96af-9e9d4b179678}"),
            "address"  : MySQLInstances().get_address(1),
            "user" : MySQLInstances().user,
            "passwd": MySQLInstances().passwd,
        }

        uuid_server2 = MySQLServer.discover_uuid(self.__options_2["address"])
        self.__options_2["uuid"] = _uuid.UUID(uuid_server2)
        self.__server_2 = MySQLServer(**self.__options_2)
        MySQLServer.add(self.__server_2)
        self.__server_2.connect()
        self.__server_2.exec_stmt("DROP DATABASE IF EXISTS db1")
        self.__server_2.exec_stmt("CREATE DATABASE db1")
        self.__server_2.exec_stmt("CREATE TABLE db1.t1"
                                  "(date_of_joining DATETIME, name VARCHAR(30))")

        self.__server_2.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('2014-05-27 11:45:00', 'name 1')")
        self.__server_2.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('2014-05-26 10:45:00', 'name 2')")
        self.__server_2.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('2014-05-25 09:45:00', 'name 3')")
        self.__server_2.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('2014-05-24 08:45:00', 'name 4')")
        self.__server_2.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('2014-05-23 13:45:00', 'name 5')")
        self.__server_2.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('2013-05-27 11:45:00', 'name 6')")
        self.__server_2.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('2012-05-26 10:45:00', 'name 7')")
        self.__server_2.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('2011-05-25 09:45:00', 'name 8')")
        self.__server_2.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('2010-05-24 08:45:00', 'name 9')")
        self.__server_2.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('2009-05-23 13:45:00', 'name 10')")

        self.__server_2.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('1914-05-27 11:45:00', 'name 1')")
        self.__server_2.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('1914-05-26 10:45:00', 'name 2')")
        self.__server_2.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('1914-05-25 09:45:00', 'name 3')")
        self.__server_2.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('1914-05-24 08:45:00', 'name 4')")
        self.__server_2.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('1914-05-23 13:45:00', 'name 5')")
        self.__server_2.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('1913-05-27 11:45:00', 'name 6')")
        self.__server_2.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('1912-05-26 10:45:00', 'name 7')")
        self.__server_2.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('1911-05-25 09:45:00', 'name 8')")
        self.__server_2.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('1910-05-24 08:45:00', 'name 9')")
        self.__server_2.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('1909-05-23 13:45:00', 'name 10')")

        self.__server_2.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('1814-05-27 11:45:00', 'name 1')")
        self.__server_2.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('1814-05-26 10:45:00', 'name 2')")
        self.__server_2.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('1814-05-25 09:45:00', 'name 3')")
        self.__server_2.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('1814-05-24 08:45:00', 'name 4')")
        self.__server_2.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('1814-05-23 13:45:00', 'name 5')")
        self.__server_2.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('1813-05-27 11:45:00', 'name 6')")
        self.__server_2.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('1812-05-26 10:45:00', 'name 7')")
        self.__server_2.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('1811-05-25 09:45:00', 'name 8')")
        self.__server_2.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('1810-05-24 08:45:00', 'name 9')")
        self.__server_2.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('1809-05-23 13:45:00', 'name 10')")

        self.__server_2.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('1714-05-27 11:45:00', 'name 1')")
        self.__server_2.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('1714-05-26 10:45:00', 'name 2')")
        self.__server_2.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('1714-05-25 09:45:00', 'name 3')")
        self.__server_2.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('1714-05-24 08:45:00', 'name 4')")
        self.__server_2.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('1714-05-23 13:45:00', 'name 5')")
        self.__server_2.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('1713-05-27 11:45:00', 'name 6')")
        self.__server_2.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('1712-05-26 10:45:00', 'name 7')")
        self.__server_2.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('1711-05-25 09:45:00', 'name 8')")
        self.__server_2.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('1710-05-24 08:45:00', 'name 9')")
        self.__server_2.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('1709-05-23 13:45:00', 'name 10')")
        self.__server_2.exec_stmt("DROP DATABASE IF EXISTS db2")
        self.__server_2.exec_stmt("CREATE DATABASE db2")
        self.__server_2.exec_stmt("CREATE TABLE db2.t2"
                                  "(date_of_joining DATETIME, name VARCHAR(30))")

        self.__server_2.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('2014-05-27 11:45:00', 'name 1')")
        self.__server_2.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('2014-05-26 10:45:00', 'name 2')")
        self.__server_2.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('2014-05-25 09:45:00', 'name 3')")
        self.__server_2.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('2014-05-24 08:45:00', 'name 4')")
        self.__server_2.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('2014-05-23 13:45:00', 'name 5')")
        self.__server_2.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('2013-05-27 11:45:00', 'name 6')")
        self.__server_2.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('2012-05-26 10:45:00', 'name 7')")
        self.__server_2.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('2011-05-25 09:45:00', 'name 8')")
        self.__server_2.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('2010-05-24 08:45:00', 'name 9')")
        self.__server_2.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('2009-05-23 13:45:00', 'name 10')")

        self.__server_2.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('1914-05-27 11:45:00', 'name 1')")
        self.__server_2.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('1914-05-26 10:45:00', 'name 2')")
        self.__server_2.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('1914-05-25 09:45:00', 'name 3')")
        self.__server_2.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('1914-05-24 08:45:00', 'name 4')")
        self.__server_2.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('1914-05-23 13:45:00', 'name 5')")
        self.__server_2.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('1913-05-27 11:45:00', 'name 6')")
        self.__server_2.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('1912-05-26 10:45:00', 'name 7')")
        self.__server_2.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('1911-05-25 09:45:00', 'name 8')")
        self.__server_2.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('1910-05-24 08:45:00', 'name 9')")
        self.__server_2.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('1909-05-23 13:45:00', 'name 10')")

        self.__server_2.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('1814-05-27 11:45:00', 'name 1')")
        self.__server_2.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('1814-05-26 10:45:00', 'name 2')")
        self.__server_2.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('1814-05-25 09:45:00', 'name 3')")
        self.__server_2.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('1814-05-24 08:45:00', 'name 4')")
        self.__server_2.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('1814-05-23 13:45:00', 'name 5')")
        self.__server_2.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('1813-05-27 11:45:00', 'name 6')")
        self.__server_2.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('1812-05-26 10:45:00', 'name 7')")
        self.__server_2.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('1811-05-25 09:45:00', 'name 8')")
        self.__server_2.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('1810-05-24 08:45:00', 'name 9')")
        self.__server_2.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('1809-05-23 13:45:00', 'name 10')")

        self.__server_2.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('1714-05-27 11:45:00', 'name 1')")
        self.__server_2.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('1714-05-26 10:45:00', 'name 2')")
        self.__server_2.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('1714-05-25 09:45:00', 'name 3')")
        self.__server_2.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('1714-05-24 08:45:00', 'name 4')")
        self.__server_2.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('1714-05-23 13:45:00', 'name 5')")
        self.__server_2.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('1713-05-27 11:45:00', 'name 6')")
        self.__server_2.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('1712-05-26 10:45:00', 'name 7')")
        self.__server_2.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('1711-05-25 09:45:00', 'name 8')")
        self.__server_2.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('1710-05-24 08:45:00', 'name 9')")
        self.__server_2.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('1709-05-23 13:45:00', 'name 10')")

        self.__server_2.exec_stmt("DROP DATABASE IF EXISTS db3")
        self.__server_2.exec_stmt("CREATE DATABASE db3")
        self.__server_2.exec_stmt("CREATE TABLE db3.t3"
                                  "(date_of_joining VARCHAR(30), name VARCHAR(30))")

        self.__server_2.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('2014-05-27 11:45:00', 'name 1')")
        self.__server_2.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('2014-05-26 10:45:00', 'name 2')")
        self.__server_2.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('2014-05-25 09:45:00', 'name 3')")
        self.__server_2.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('2014-05-24 08:45:00', 'name 4')")
        self.__server_2.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('2014-05-23 13:45:00', 'name 5')")
        self.__server_2.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('2013-05-27 11:45:00', 'name 6')")
        self.__server_2.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('2012-05-26 10:45:00', 'name 7')")
        self.__server_2.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('2011-05-25 09:45:00', 'name 8')")
        self.__server_2.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('2010-05-24 08:45:00', 'name 9')")
        self.__server_2.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('2009-05-23 13:45:00', 'name 10')")

        self.__server_2.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('1914-05-27 11:45:00', 'name 1')")
        self.__server_2.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('1914-05-26 10:45:00', 'name 2')")
        self.__server_2.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('1914-05-25 09:45:00', 'name 3')")
        self.__server_2.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('1914-05-24 08:45:00', 'name 4')")
        self.__server_2.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('1914-05-23 13:45:00', 'name 5')")
        self.__server_2.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('1913-05-27 11:45:00', 'name 6')")
        self.__server_2.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('1912-05-26 10:45:00', 'name 7')")
        self.__server_2.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('1911-05-25 09:45:00', 'name 8')")
        self.__server_2.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('1910-05-24 08:45:00', 'name 9')")
        self.__server_2.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('1909-05-23 13:45:00', 'name 10')")

        self.__server_2.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('1814-05-27 11:45:00', 'name 1')")
        self.__server_2.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('1814-05-26 10:45:00', 'name 2')")
        self.__server_2.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('1814-05-25 09:45:00', 'name 3')")
        self.__server_2.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('1814-05-24 08:45:00', 'name 4')")
        self.__server_2.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('1814-05-23 13:45:00', 'name 5')")
        self.__server_2.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('1813-05-27 11:45:00', 'name 6')")
        self.__server_2.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('1812-05-26 10:45:00', 'name 7')")
        self.__server_2.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('1811-05-25 09:45:00', 'name 8')")
        self.__server_2.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('1810-05-24 08:45:00', 'name 9')")
        self.__server_2.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('1809-05-23 13:45:00', 'name 10')")

        self.__server_2.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('1714-05-27 11:45:00', 'name 1')")
        self.__server_2.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('1714-05-26 10:45:00', 'name 2')")
        self.__server_2.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('1714-05-25 09:45:00', 'name 3')")
        self.__server_2.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('1714-05-24 08:45:00', 'name 4')")
        self.__server_2.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('1714-05-23 13:45:00', 'name 5')")
        self.__server_2.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('1713-05-27 11:45:00', 'name 6')")
        self.__server_2.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('1712-05-26 10:45:00', 'name 7')")
        self.__server_2.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('1711-05-25 09:45:00', 'name 8')")
        self.__server_2.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('1710-05-24 08:45:00', 'name 9')")
        self.__server_2.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('1709-05-23 13:45:00', 'name 10')")

        self.__server_2.exec_stmt("DROP DATABASE IF EXISTS db4")
        self.__server_2.exec_stmt("CREATE DATABASE db4")
        self.__server_2.exec_stmt("CREATE TABLE db4.t4"
                                  "(date_of_joining TEXT, name VARCHAR(30))")

        self.__server_2.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('2014-05-27 11:45:00', 'name 1')")
        self.__server_2.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('2014-05-26 10:45:00', 'name 2')")
        self.__server_2.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('2014-05-25 09:45:00', 'name 3')")
        self.__server_2.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('2014-05-24 08:45:00', 'name 4')")
        self.__server_2.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('2014-05-23 13:45:00', 'name 5')")
        self.__server_2.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('2013-05-27 11:45:00', 'name 6')")
        self.__server_2.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('2012-05-26 10:45:00', 'name 7')")
        self.__server_2.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('2011-05-25 09:45:00', 'name 8')")
        self.__server_2.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('2010-05-24 08:45:00', 'name 9')")
        self.__server_2.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('2009-05-23 13:45:00', 'name 10')")

        self.__server_2.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('1914-05-27 11:45:00', 'name 1')")
        self.__server_2.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('1914-05-26 10:45:00', 'name 2')")
        self.__server_2.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('1914-05-25 09:45:00', 'name 3')")
        self.__server_2.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('1914-05-24 08:45:00', 'name 4')")
        self.__server_2.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('1914-05-23 13:45:00', 'name 5')")
        self.__server_2.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('1913-05-27 11:45:00', 'name 6')")
        self.__server_2.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('1912-05-26 10:45:00', 'name 7')")
        self.__server_2.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('1911-05-25 09:45:00', 'name 8')")
        self.__server_2.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('1910-05-24 08:45:00', 'name 9')")
        self.__server_2.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('1909-05-23 13:45:00', 'name 10')")

        self.__server_2.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('1814-05-27 11:45:00', 'name 1')")
        self.__server_2.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('1814-05-26 10:45:00', 'name 2')")
        self.__server_2.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('1814-05-25 09:45:00', 'name 3')")
        self.__server_2.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('1814-05-24 08:45:00', 'name 4')")
        self.__server_2.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('1814-05-23 13:45:00', 'name 5')")
        self.__server_2.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('1813-05-27 11:45:00', 'name 6')")
        self.__server_2.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('1812-05-26 10:45:00', 'name 7')")
        self.__server_2.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('1811-05-25 09:45:00', 'name 8')")
        self.__server_2.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('1810-05-24 08:45:00', 'name 9')")
        self.__server_2.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('1809-05-23 13:45:00', 'name 10')")

        self.__server_2.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('1714-05-27 11:45:00', 'name 1')")
        self.__server_2.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('1714-05-26 10:45:00', 'name 2')")
        self.__server_2.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('1714-05-25 09:45:00', 'name 3')")
        self.__server_2.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('1714-05-24 08:45:00', 'name 4')")
        self.__server_2.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('1714-05-23 13:45:00', 'name 5')")
        self.__server_2.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('1713-05-27 11:45:00', 'name 6')")
        self.__server_2.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('1712-05-26 10:45:00', 'name 7')")
        self.__server_2.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('1711-05-25 09:45:00', 'name 8')")
        self.__server_2.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('1710-05-24 08:45:00', 'name 9')")
        self.__server_2.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('1709-05-23 13:45:00', 'name 10')")

        self.__group_2 = Group("GROUPID2", "Second description.")
        Group.add(self.__group_2)
        self.__group_2.add_server(self.__server_2)
        tests.utils.configure_decoupled_master(self.__group_2, self.__server_2)

        self.__options_3 = {
            "uuid" :  _uuid.UUID("{bb75b12b-98d1-414c-96af-9e9d4b179678}"),
            "address"  : MySQLInstances().get_address(2),
            "user" : MySQLInstances().user,
            "passwd": MySQLInstances().passwd,
        }

        uuid_server3 = MySQLServer.discover_uuid(self.__options_3["address"])
        self.__options_3["uuid"] = _uuid.UUID(uuid_server3)
        self.__server_3 = MySQLServer(**self.__options_3)
        MySQLServer.add( self.__server_3)
        self.__server_3.connect()
        self.__server_3.exec_stmt("DROP DATABASE IF EXISTS db1")
        self.__server_3.exec_stmt("CREATE DATABASE db1")
        self.__server_3.exec_stmt("CREATE TABLE db1.t1"
                                  "(date_of_joining DATETIME, name VARCHAR(30))")

        self.__server_3.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('2014-05-27 11:45:00', 'name 1')")
        self.__server_3.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('2014-05-26 10:45:00', 'name 2')")
        self.__server_3.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('2014-05-25 09:45:00', 'name 3')")
        self.__server_3.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('2014-05-24 08:45:00', 'name 4')")
        self.__server_3.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('2014-05-23 13:45:00', 'name 5')")
        self.__server_3.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('2013-05-27 11:45:00', 'name 6')")
        self.__server_3.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('2012-05-26 10:45:00', 'name 7')")
        self.__server_3.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('2011-05-25 09:45:00', 'name 8')")
        self.__server_3.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('2010-05-24 08:45:00', 'name 9')")
        self.__server_3.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('2009-05-23 13:45:00', 'name 10')")

        self.__server_3.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('1914-05-27 11:45:00', 'name 1')")
        self.__server_3.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('1914-05-26 10:45:00', 'name 2')")
        self.__server_3.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('1914-05-25 09:45:00', 'name 3')")
        self.__server_3.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('1914-05-24 08:45:00', 'name 4')")
        self.__server_3.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('1914-05-23 13:45:00', 'name 5')")
        self.__server_3.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('1913-05-27 11:45:00', 'name 6')")
        self.__server_3.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('1912-05-26 10:45:00', 'name 7')")
        self.__server_3.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('1911-05-25 09:45:00', 'name 8')")
        self.__server_3.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('1910-05-24 08:45:00', 'name 9')")
        self.__server_3.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('1909-05-23 13:45:00', 'name 10')")

        self.__server_3.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('1814-05-27 11:45:00', 'name 1')")
        self.__server_3.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('1814-05-26 10:45:00', 'name 2')")
        self.__server_3.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('1814-05-25 09:45:00', 'name 3')")
        self.__server_3.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('1814-05-24 08:45:00', 'name 4')")
        self.__server_3.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('1814-05-23 13:45:00', 'name 5')")
        self.__server_3.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('1813-05-27 11:45:00', 'name 6')")
        self.__server_3.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('1812-05-26 10:45:00', 'name 7')")
        self.__server_3.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('1811-05-25 09:45:00', 'name 8')")
        self.__server_3.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('1810-05-24 08:45:00', 'name 9')")
        self.__server_3.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('1809-05-23 13:45:00', 'name 10')")

        self.__server_3.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('1714-05-27 11:45:00', 'name 1')")
        self.__server_3.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('1714-05-26 10:45:00', 'name 2')")
        self.__server_3.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('1714-05-25 09:45:00', 'name 3')")
        self.__server_3.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('1714-05-24 08:45:00', 'name 4')")
        self.__server_3.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('1714-05-23 13:45:00', 'name 5')")
        self.__server_3.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('1713-05-27 11:45:00', 'name 6')")
        self.__server_3.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('1712-05-26 10:45:00', 'name 7')")
        self.__server_3.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('1711-05-25 09:45:00', 'name 8')")
        self.__server_3.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('1710-05-24 08:45:00', 'name 9')")
        self.__server_3.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('1709-05-23 13:45:00', 'name 10')")
        self.__server_3.exec_stmt("DROP DATABASE IF EXISTS db2")
        self.__server_3.exec_stmt("CREATE DATABASE db2")
        self.__server_3.exec_stmt("CREATE TABLE db2.t2"
                                  "(date_of_joining DATETIME, name VARCHAR(30))")

        self.__server_3.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('2014-05-27 11:45:00', 'name 1')")
        self.__server_3.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('2014-05-26 10:45:00', 'name 2')")
        self.__server_3.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('2014-05-25 09:45:00', 'name 3')")
        self.__server_3.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('2014-05-24 08:45:00', 'name 4')")
        self.__server_3.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('2014-05-23 13:45:00', 'name 5')")
        self.__server_3.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('2013-05-27 11:45:00', 'name 6')")
        self.__server_3.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('2012-05-26 10:45:00', 'name 7')")
        self.__server_3.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('2011-05-25 09:45:00', 'name 8')")
        self.__server_3.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('2010-05-24 08:45:00', 'name 9')")
        self.__server_3.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('2009-05-23 13:45:00', 'name 10')")

        self.__server_3.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('1914-05-27 11:45:00', 'name 1')")
        self.__server_3.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('1914-05-26 10:45:00', 'name 2')")
        self.__server_3.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('1914-05-25 09:45:00', 'name 3')")
        self.__server_3.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('1914-05-24 08:45:00', 'name 4')")
        self.__server_3.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('1914-05-23 13:45:00', 'name 5')")
        self.__server_3.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('1913-05-27 11:45:00', 'name 6')")
        self.__server_3.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('1912-05-26 10:45:00', 'name 7')")
        self.__server_3.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('1911-05-25 09:45:00', 'name 8')")
        self.__server_3.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('1910-05-24 08:45:00', 'name 9')")
        self.__server_3.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('1909-05-23 13:45:00', 'name 10')")

        self.__server_3.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('1814-05-27 11:45:00', 'name 1')")
        self.__server_3.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('1814-05-26 10:45:00', 'name 2')")
        self.__server_3.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('1814-05-25 09:45:00', 'name 3')")
        self.__server_3.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('1814-05-24 08:45:00', 'name 4')")
        self.__server_3.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('1814-05-23 13:45:00', 'name 5')")
        self.__server_3.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('1813-05-27 11:45:00', 'name 6')")
        self.__server_3.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('1812-05-26 10:45:00', 'name 7')")
        self.__server_3.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('1811-05-25 09:45:00', 'name 8')")
        self.__server_3.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('1810-05-24 08:45:00', 'name 9')")
        self.__server_3.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('1809-05-23 13:45:00', 'name 10')")

        self.__server_3.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('1714-05-27 11:45:00', 'name 1')")
        self.__server_3.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('1714-05-26 10:45:00', 'name 2')")
        self.__server_3.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('1714-05-25 09:45:00', 'name 3')")
        self.__server_3.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('1714-05-24 08:45:00', 'name 4')")
        self.__server_3.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('1714-05-23 13:45:00', 'name 5')")
        self.__server_3.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('1713-05-27 11:45:00', 'name 6')")
        self.__server_3.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('1712-05-26 10:45:00', 'name 7')")
        self.__server_3.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('1711-05-25 09:45:00', 'name 8')")
        self.__server_3.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('1710-05-24 08:45:00', 'name 9')")
        self.__server_3.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('1709-05-23 13:45:00', 'name 10')")

        self.__server_3.exec_stmt("DROP DATABASE IF EXISTS db3")
        self.__server_3.exec_stmt("CREATE DATABASE db3")
        self.__server_3.exec_stmt("CREATE TABLE db3.t3"
                                  "(date_of_joining VARCHAR(30), name VARCHAR(30))")

        self.__server_3.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('2014-05-27 11:45:00', 'name 1')")
        self.__server_3.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('2014-05-26 10:45:00', 'name 2')")
        self.__server_3.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('2014-05-25 09:45:00', 'name 3')")
        self.__server_3.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('2014-05-24 08:45:00', 'name 4')")
        self.__server_3.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('2014-05-23 13:45:00', 'name 5')")
        self.__server_3.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('2013-05-27 11:45:00', 'name 6')")
        self.__server_3.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('2012-05-26 10:45:00', 'name 7')")
        self.__server_3.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('2011-05-25 09:45:00', 'name 8')")
        self.__server_3.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('2010-05-24 08:45:00', 'name 9')")
        self.__server_3.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('2009-05-23 13:45:00', 'name 10')")

        self.__server_3.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('1914-05-27 11:45:00', 'name 1')")
        self.__server_3.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('1914-05-26 10:45:00', 'name 2')")
        self.__server_3.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('1914-05-25 09:45:00', 'name 3')")
        self.__server_3.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('1914-05-24 08:45:00', 'name 4')")
        self.__server_3.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('1914-05-23 13:45:00', 'name 5')")
        self.__server_3.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('1913-05-27 11:45:00', 'name 6')")
        self.__server_3.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('1912-05-26 10:45:00', 'name 7')")
        self.__server_3.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('1911-05-25 09:45:00', 'name 8')")
        self.__server_3.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('1910-05-24 08:45:00', 'name 9')")
        self.__server_3.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('1909-05-23 13:45:00', 'name 10')")

        self.__server_3.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('1814-05-27 11:45:00', 'name 1')")
        self.__server_3.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('1814-05-26 10:45:00', 'name 2')")
        self.__server_3.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('1814-05-25 09:45:00', 'name 3')")
        self.__server_3.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('1814-05-24 08:45:00', 'name 4')")
        self.__server_3.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('1814-05-23 13:45:00', 'name 5')")
        self.__server_3.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('1813-05-27 11:45:00', 'name 6')")
        self.__server_3.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('1812-05-26 10:45:00', 'name 7')")
        self.__server_3.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('1811-05-25 09:45:00', 'name 8')")
        self.__server_3.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('1810-05-24 08:45:00', 'name 9')")
        self.__server_3.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('1809-05-23 13:45:00', 'name 10')")

        self.__server_3.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('1714-05-27 11:45:00', 'name 1')")
        self.__server_3.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('1714-05-26 10:45:00', 'name 2')")
        self.__server_3.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('1714-05-25 09:45:00', 'name 3')")
        self.__server_3.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('1714-05-24 08:45:00', 'name 4')")
        self.__server_3.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('1714-05-23 13:45:00', 'name 5')")
        self.__server_3.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('1713-05-27 11:45:00', 'name 6')")
        self.__server_3.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('1712-05-26 10:45:00', 'name 7')")
        self.__server_3.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('1711-05-25 09:45:00', 'name 8')")
        self.__server_3.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('1710-05-24 08:45:00', 'name 9')")
        self.__server_3.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('1709-05-23 13:45:00', 'name 10')")

        self.__server_3.exec_stmt("DROP DATABASE IF EXISTS db4")
        self.__server_3.exec_stmt("CREATE DATABASE db4")
        self.__server_3.exec_stmt("CREATE TABLE db4.t4"
                                  "(date_of_joining TEXT, name VARCHAR(30))")

        self.__server_3.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('2014-05-27 11:45:00', 'name 1')")
        self.__server_3.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('2014-05-26 10:45:00', 'name 2')")
        self.__server_3.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('2014-05-25 09:45:00', 'name 3')")
        self.__server_3.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('2014-05-24 08:45:00', 'name 4')")
        self.__server_3.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('2014-05-23 13:45:00', 'name 5')")
        self.__server_3.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('2013-05-27 11:45:00', 'name 6')")
        self.__server_3.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('2012-05-26 10:45:00', 'name 7')")
        self.__server_3.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('2011-05-25 09:45:00', 'name 8')")
        self.__server_3.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('2010-05-24 08:45:00', 'name 9')")
        self.__server_3.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('2009-05-23 13:45:00', 'name 10')")

        self.__server_3.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('1914-05-27 11:45:00', 'name 1')")
        self.__server_3.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('1914-05-26 10:45:00', 'name 2')")
        self.__server_3.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('1914-05-25 09:45:00', 'name 3')")
        self.__server_3.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('1914-05-24 08:45:00', 'name 4')")
        self.__server_3.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('1914-05-23 13:45:00', 'name 5')")
        self.__server_3.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('1913-05-27 11:45:00', 'name 6')")
        self.__server_3.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('1912-05-26 10:45:00', 'name 7')")
        self.__server_3.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('1911-05-25 09:45:00', 'name 8')")
        self.__server_3.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('1910-05-24 08:45:00', 'name 9')")
        self.__server_3.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('1909-05-23 13:45:00', 'name 10')")

        self.__server_3.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('1814-05-27 11:45:00', 'name 1')")
        self.__server_3.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('1814-05-26 10:45:00', 'name 2')")
        self.__server_3.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('1814-05-25 09:45:00', 'name 3')")
        self.__server_3.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('1814-05-24 08:45:00', 'name 4')")
        self.__server_3.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('1814-05-23 13:45:00', 'name 5')")
        self.__server_3.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('1813-05-27 11:45:00', 'name 6')")
        self.__server_3.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('1812-05-26 10:45:00', 'name 7')")
        self.__server_3.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('1811-05-25 09:45:00', 'name 8')")
        self.__server_3.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('1810-05-24 08:45:00', 'name 9')")
        self.__server_3.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('1809-05-23 13:45:00', 'name 10')")

        self.__server_3.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('1714-05-27 11:45:00', 'name 1')")
        self.__server_3.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('1714-05-26 10:45:00', 'name 2')")
        self.__server_3.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('1714-05-25 09:45:00', 'name 3')")
        self.__server_3.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('1714-05-24 08:45:00', 'name 4')")
        self.__server_3.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('1714-05-23 13:45:00', 'name 5')")
        self.__server_3.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('1713-05-27 11:45:00', 'name 6')")
        self.__server_3.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('1712-05-26 10:45:00', 'name 7')")
        self.__server_3.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('1711-05-25 09:45:00', 'name 8')")
        self.__server_3.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('1710-05-24 08:45:00', 'name 9')")
        self.__server_3.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('1709-05-23 13:45:00', 'name 10')")

        self.__group_3 = Group("GROUPID3", "Third description.")
        Group.add( self.__group_3)
        self.__group_3.add_server(self.__server_3)
        tests.utils.configure_decoupled_master(self.__group_3, self.__server_3)

        self.__options_4 = {
            "uuid" :  _uuid.UUID("{bb45b12b-98d1-414c-96af-9e9d4b179678}"),
            "address"  : MySQLInstances().get_address(3),
            "user" : MySQLInstances().user,
            "passwd": MySQLInstances().passwd,
        }

        uuid_server4 = MySQLServer.discover_uuid(self.__options_4["address"])
        self.__options_4["uuid"] = _uuid.UUID(uuid_server4)
        self.__server_4 = MySQLServer(**self.__options_4)
        MySQLServer.add(self.__server_4)
        self.__server_4.connect()
        self.__server_4.exec_stmt("DROP DATABASE IF EXISTS db1")
        self.__server_4.exec_stmt("CREATE DATABASE db1")
        self.__server_4.exec_stmt("CREATE TABLE db1.t1"
                                  "(date_of_joining DATETIME, name VARCHAR(30))")

        self.__server_4.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('2014-05-27 11:45:00', 'name 1')")
        self.__server_4.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('2014-05-26 10:45:00', 'name 2')")
        self.__server_4.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('2014-05-25 09:45:00', 'name 3')")
        self.__server_4.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('2014-05-24 08:45:00', 'name 4')")
        self.__server_4.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('2014-05-23 13:45:00', 'name 5')")
        self.__server_4.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('2013-05-27 11:45:00', 'name 6')")
        self.__server_4.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('2012-05-26 10:45:00', 'name 7')")
        self.__server_4.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('2011-05-25 09:45:00', 'name 8')")
        self.__server_4.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('2010-05-24 08:45:00', 'name 9')")
        self.__server_4.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('2009-05-23 13:45:00', 'name 10')")

        self.__server_4.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('1914-05-27 11:45:00', 'name 1')")
        self.__server_4.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('1914-05-26 10:45:00', 'name 2')")
        self.__server_4.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('1914-05-25 09:45:00', 'name 3')")
        self.__server_4.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('1914-05-24 08:45:00', 'name 4')")
        self.__server_4.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('1914-05-23 13:45:00', 'name 5')")
        self.__server_4.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('1913-05-27 11:45:00', 'name 6')")
        self.__server_4.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('1912-05-26 10:45:00', 'name 7')")
        self.__server_4.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('1911-05-25 09:45:00', 'name 8')")
        self.__server_4.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('1910-05-24 08:45:00', 'name 9')")
        self.__server_4.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('1909-05-23 13:45:00', 'name 10')")

        self.__server_4.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('1814-05-27 11:45:00', 'name 1')")
        self.__server_4.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('1814-05-26 10:45:00', 'name 2')")
        self.__server_4.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('1814-05-25 09:45:00', 'name 3')")
        self.__server_4.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('1814-05-24 08:45:00', 'name 4')")
        self.__server_4.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('1814-05-23 13:45:00', 'name 5')")
        self.__server_4.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('1813-05-27 11:45:00', 'name 6')")
        self.__server_4.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('1812-05-26 10:45:00', 'name 7')")
        self.__server_4.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('1811-05-25 09:45:00', 'name 8')")
        self.__server_4.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('1810-05-24 08:45:00', 'name 9')")
        self.__server_4.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('1809-05-23 13:45:00', 'name 10')")

        self.__server_4.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('1714-05-27 11:45:00', 'name 1')")
        self.__server_4.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('1714-05-26 10:45:00', 'name 2')")
        self.__server_4.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('1714-05-25 09:45:00', 'name 3')")
        self.__server_4.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('1714-05-24 08:45:00', 'name 4')")
        self.__server_4.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('1714-05-23 13:45:00', 'name 5')")
        self.__server_4.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('1713-05-27 11:45:00', 'name 6')")
        self.__server_4.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('1712-05-26 10:45:00', 'name 7')")
        self.__server_4.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('1711-05-25 09:45:00', 'name 8')")
        self.__server_4.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('1710-05-24 08:45:00', 'name 9')")
        self.__server_4.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('1709-05-23 13:45:00', 'name 10')")
        self.__server_4.exec_stmt("DROP DATABASE IF EXISTS db2")
        self.__server_4.exec_stmt("CREATE DATABASE db2")
        self.__server_4.exec_stmt("CREATE TABLE db2.t2"
                                  "(date_of_joining DATETIME, name VARCHAR(30))")

        self.__server_4.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('2014-05-27 11:45:00', 'name 1')")
        self.__server_4.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('2014-05-26 10:45:00', 'name 2')")
        self.__server_4.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('2014-05-25 09:45:00', 'name 3')")
        self.__server_4.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('2014-05-24 08:45:00', 'name 4')")
        self.__server_4.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('2014-05-23 13:45:00', 'name 5')")
        self.__server_4.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('2013-05-27 11:45:00', 'name 6')")
        self.__server_4.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('2012-05-26 10:45:00', 'name 7')")
        self.__server_4.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('2011-05-25 09:45:00', 'name 8')")
        self.__server_4.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('2010-05-24 08:45:00', 'name 9')")
        self.__server_4.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('2009-05-23 13:45:00', 'name 10')")

        self.__server_4.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('1914-05-27 11:45:00', 'name 1')")
        self.__server_4.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('1914-05-26 10:45:00', 'name 2')")
        self.__server_4.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('1914-05-25 09:45:00', 'name 3')")
        self.__server_4.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('1914-05-24 08:45:00', 'name 4')")
        self.__server_4.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('1914-05-23 13:45:00', 'name 5')")
        self.__server_4.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('1913-05-27 11:45:00', 'name 6')")
        self.__server_4.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('1912-05-26 10:45:00', 'name 7')")
        self.__server_4.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('1911-05-25 09:45:00', 'name 8')")
        self.__server_4.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('1910-05-24 08:45:00', 'name 9')")
        self.__server_4.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('1909-05-23 13:45:00', 'name 10')")

        self.__server_4.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('1814-05-27 11:45:00', 'name 1')")
        self.__server_4.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('1814-05-26 10:45:00', 'name 2')")
        self.__server_4.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('1814-05-25 09:45:00', 'name 3')")
        self.__server_4.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('1814-05-24 08:45:00', 'name 4')")
        self.__server_4.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('1814-05-23 13:45:00', 'name 5')")
        self.__server_4.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('1813-05-27 11:45:00', 'name 6')")
        self.__server_4.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('1812-05-26 10:45:00', 'name 7')")
        self.__server_4.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('1811-05-25 09:45:00', 'name 8')")
        self.__server_4.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('1810-05-24 08:45:00', 'name 9')")
        self.__server_4.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('1809-05-23 13:45:00', 'name 10')")

        self.__server_4.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('1714-05-27 11:45:00', 'name 1')")
        self.__server_4.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('1714-05-26 10:45:00', 'name 2')")
        self.__server_4.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('1714-05-25 09:45:00', 'name 3')")
        self.__server_4.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('1714-05-24 08:45:00', 'name 4')")
        self.__server_4.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('1714-05-23 13:45:00', 'name 5')")
        self.__server_4.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('1713-05-27 11:45:00', 'name 6')")
        self.__server_4.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('1712-05-26 10:45:00', 'name 7')")
        self.__server_4.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('1711-05-25 09:45:00', 'name 8')")
        self.__server_4.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('1710-05-24 08:45:00', 'name 9')")
        self.__server_4.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('1709-05-23 13:45:00', 'name 10')")

        self.__server_4.exec_stmt("DROP DATABASE IF EXISTS db3")
        self.__server_4.exec_stmt("CREATE DATABASE db3")
        self.__server_4.exec_stmt("CREATE TABLE db3.t3"
                                  "(date_of_joining VARCHAR(30), name VARCHAR(30))")

        self.__server_4.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('2014-05-27 11:45:00', 'name 1')")
        self.__server_4.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('2014-05-26 10:45:00', 'name 2')")
        self.__server_4.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('2014-05-25 09:45:00', 'name 3')")
        self.__server_4.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('2014-05-24 08:45:00', 'name 4')")
        self.__server_4.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('2014-05-23 13:45:00', 'name 5')")
        self.__server_4.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('2013-05-27 11:45:00', 'name 6')")
        self.__server_4.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('2012-05-26 10:45:00', 'name 7')")
        self.__server_4.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('2011-05-25 09:45:00', 'name 8')")
        self.__server_4.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('2010-05-24 08:45:00', 'name 9')")
        self.__server_4.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('2009-05-23 13:45:00', 'name 10')")

        self.__server_4.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('1914-05-27 11:45:00', 'name 1')")
        self.__server_4.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('1914-05-26 10:45:00', 'name 2')")
        self.__server_4.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('1914-05-25 09:45:00', 'name 3')")
        self.__server_4.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('1914-05-24 08:45:00', 'name 4')")
        self.__server_4.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('1914-05-23 13:45:00', 'name 5')")
        self.__server_4.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('1913-05-27 11:45:00', 'name 6')")
        self.__server_4.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('1912-05-26 10:45:00', 'name 7')")
        self.__server_4.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('1911-05-25 09:45:00', 'name 8')")
        self.__server_4.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('1910-05-24 08:45:00', 'name 9')")
        self.__server_4.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('1909-05-23 13:45:00', 'name 10')")

        self.__server_4.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('1814-05-27 11:45:00', 'name 1')")
        self.__server_4.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('1814-05-26 10:45:00', 'name 2')")
        self.__server_4.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('1814-05-25 09:45:00', 'name 3')")
        self.__server_4.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('1814-05-24 08:45:00', 'name 4')")
        self.__server_4.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('1814-05-23 13:45:00', 'name 5')")
        self.__server_4.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('1813-05-27 11:45:00', 'name 6')")
        self.__server_4.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('1812-05-26 10:45:00', 'name 7')")
        self.__server_4.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('1811-05-25 09:45:00', 'name 8')")
        self.__server_4.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('1810-05-24 08:45:00', 'name 9')")
        self.__server_4.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('1809-05-23 13:45:00', 'name 10')")

        self.__server_4.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('1714-05-27 11:45:00', 'name 1')")
        self.__server_4.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('1714-05-26 10:45:00', 'name 2')")
        self.__server_4.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('1714-05-25 09:45:00', 'name 3')")
        self.__server_4.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('1714-05-24 08:45:00', 'name 4')")
        self.__server_4.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('1714-05-23 13:45:00', 'name 5')")
        self.__server_4.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('1713-05-27 11:45:00', 'name 6')")
        self.__server_4.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('1712-05-26 10:45:00', 'name 7')")
        self.__server_4.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('1711-05-25 09:45:00', 'name 8')")
        self.__server_4.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('1710-05-24 08:45:00', 'name 9')")
        self.__server_4.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('1709-05-23 13:45:00', 'name 10')")

        self.__server_4.exec_stmt("DROP DATABASE IF EXISTS db4")
        self.__server_4.exec_stmt("CREATE DATABASE db4")
        self.__server_4.exec_stmt("CREATE TABLE db4.t4"
                                  "(date_of_joining TEXT, name VARCHAR(30))")

        self.__server_4.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('2014-05-27 11:45:00', 'name 1')")
        self.__server_4.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('2014-05-26 10:45:00', 'name 2')")
        self.__server_4.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('2014-05-25 09:45:00', 'name 3')")
        self.__server_4.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('2014-05-24 08:45:00', 'name 4')")
        self.__server_4.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('2014-05-23 13:45:00', 'name 5')")
        self.__server_4.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('2013-05-27 11:45:00', 'name 6')")
        self.__server_4.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('2012-05-26 10:45:00', 'name 7')")
        self.__server_4.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('2011-05-25 09:45:00', 'name 8')")
        self.__server_4.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('2010-05-24 08:45:00', 'name 9')")
        self.__server_4.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('2009-05-23 13:45:00', 'name 10')")

        self.__server_4.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('1914-05-27 11:45:00', 'name 1')")
        self.__server_4.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('1914-05-26 10:45:00', 'name 2')")
        self.__server_4.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('1914-05-25 09:45:00', 'name 3')")
        self.__server_4.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('1914-05-24 08:45:00', 'name 4')")
        self.__server_4.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('1914-05-23 13:45:00', 'name 5')")
        self.__server_4.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('1913-05-27 11:45:00', 'name 6')")
        self.__server_4.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('1912-05-26 10:45:00', 'name 7')")
        self.__server_4.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('1911-05-25 09:45:00', 'name 8')")
        self.__server_4.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('1910-05-24 08:45:00', 'name 9')")
        self.__server_4.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('1909-05-23 13:45:00', 'name 10')")

        self.__server_4.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('1814-05-27 11:45:00', 'name 1')")
        self.__server_4.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('1814-05-26 10:45:00', 'name 2')")
        self.__server_4.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('1814-05-25 09:45:00', 'name 3')")
        self.__server_4.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('1814-05-24 08:45:00', 'name 4')")
        self.__server_4.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('1814-05-23 13:45:00', 'name 5')")
        self.__server_4.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('1813-05-27 11:45:00', 'name 6')")
        self.__server_4.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('1812-05-26 10:45:00', 'name 7')")
        self.__server_4.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('1811-05-25 09:45:00', 'name 8')")
        self.__server_4.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('1810-05-24 08:45:00', 'name 9')")
        self.__server_4.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('1809-05-23 13:45:00', 'name 10')")

        self.__server_4.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('1714-05-27 11:45:00', 'name 1')")
        self.__server_4.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('1714-05-26 10:45:00', 'name 2')")
        self.__server_4.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('1714-05-25 09:45:00', 'name 3')")
        self.__server_4.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('1714-05-24 08:45:00', 'name 4')")
        self.__server_4.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('1714-05-23 13:45:00', 'name 5')")
        self.__server_4.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('1713-05-27 11:45:00', 'name 6')")
        self.__server_4.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('1712-05-26 10:45:00', 'name 7')")
        self.__server_4.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('1711-05-25 09:45:00', 'name 8')")
        self.__server_4.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('1710-05-24 08:45:00', 'name 9')")
        self.__server_4.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('1709-05-23 13:45:00', 'name 10')")

        self.__group_4 = Group("GROUPID4", "Fourth description.")
        Group.add( self.__group_4)
        self.__group_4.add_server(self.__server_4)
        tests.utils.configure_decoupled_master(self.__group_4, self.__server_4)

        self.__options_5 = {
            "uuid" :  _uuid.UUID("{cc75b12b-98d1-414c-96af-9e9d4b179678}"),
            "address"  : MySQLInstances().get_address(4),
            "user" : MySQLInstances().user,
            "passwd": MySQLInstances().passwd,
        }

        uuid_server5 = MySQLServer.discover_uuid(self.__options_5["address"])
        self.__options_5["uuid"] = _uuid.UUID(uuid_server5)
        self.__server_5 = MySQLServer(**self.__options_5)
        MySQLServer.add(self.__server_5)
        self.__server_5.connect()
        self.__server_5.exec_stmt("DROP DATABASE IF EXISTS db1")
        self.__server_5.exec_stmt("CREATE DATABASE db1")
        self.__server_5.exec_stmt("CREATE TABLE db1.t1"
                                  "(date_of_joining DATETIME, name VARCHAR(30))")

        self.__server_5.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('2014-05-27 11:45:00', 'name 1')")
        self.__server_5.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('2014-05-26 10:45:00', 'name 2')")
        self.__server_5.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('2014-05-25 09:45:00', 'name 3')")
        self.__server_5.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('2014-05-24 08:45:00', 'name 4')")
        self.__server_5.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('2014-05-23 13:45:00', 'name 5')")
        self.__server_5.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('2013-05-27 11:45:00', 'name 6')")
        self.__server_5.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('2012-05-26 10:45:00', 'name 7')")
        self.__server_5.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('2011-05-25 09:45:00', 'name 8')")
        self.__server_5.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('2010-05-24 08:45:00', 'name 9')")
        self.__server_5.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('2009-05-23 13:45:00', 'name 10')")

        self.__server_5.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('1914-05-27 11:45:00', 'name 1')")
        self.__server_5.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('1914-05-26 10:45:00', 'name 2')")
        self.__server_5.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('1914-05-25 09:45:00', 'name 3')")
        self.__server_5.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('1914-05-24 08:45:00', 'name 4')")
        self.__server_5.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('1914-05-23 13:45:00', 'name 5')")
        self.__server_5.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('1913-05-27 11:45:00', 'name 6')")
        self.__server_5.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('1912-05-26 10:45:00', 'name 7')")
        self.__server_5.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('1911-05-25 09:45:00', 'name 8')")
        self.__server_5.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('1910-05-24 08:45:00', 'name 9')")
        self.__server_5.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('1909-05-23 13:45:00', 'name 10')")

        self.__server_5.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('1814-05-27 11:45:00', 'name 1')")
        self.__server_5.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('1814-05-26 10:45:00', 'name 2')")
        self.__server_5.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('1814-05-25 09:45:00', 'name 3')")
        self.__server_5.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('1814-05-24 08:45:00', 'name 4')")
        self.__server_5.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('1814-05-23 13:45:00', 'name 5')")
        self.__server_5.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('1813-05-27 11:45:00', 'name 6')")
        self.__server_5.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('1812-05-26 10:45:00', 'name 7')")
        self.__server_5.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('1811-05-25 09:45:00', 'name 8')")
        self.__server_5.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('1810-05-24 08:45:00', 'name 9')")
        self.__server_5.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('1809-05-23 13:45:00', 'name 10')")

        self.__server_5.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('1714-05-27 11:45:00', 'name 1')")
        self.__server_5.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('1714-05-26 10:45:00', 'name 2')")
        self.__server_5.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('1714-05-25 09:45:00', 'name 3')")
        self.__server_5.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('1714-05-24 08:45:00', 'name 4')")
        self.__server_5.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('1714-05-23 13:45:00', 'name 5')")
        self.__server_5.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('1713-05-27 11:45:00', 'name 6')")
        self.__server_5.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('1712-05-26 10:45:00', 'name 7')")
        self.__server_5.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('1711-05-25 09:45:00', 'name 8')")
        self.__server_5.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('1710-05-24 08:45:00', 'name 9')")
        self.__server_5.exec_stmt("INSERT INTO db1.t1 "
                              "VALUES('1709-05-23 13:45:00', 'name 10')")
        self.__server_5.exec_stmt("DROP DATABASE IF EXISTS db2")
        self.__server_5.exec_stmt("CREATE DATABASE db2")
        self.__server_5.exec_stmt("CREATE TABLE db2.t2"
                                  "(date_of_joining DATETIME, name VARCHAR(30))")

        self.__server_5.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('2014-05-27 11:45:00', 'name 1')")
        self.__server_5.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('2014-05-26 10:45:00', 'name 2')")
        self.__server_5.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('2014-05-25 09:45:00', 'name 3')")
        self.__server_5.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('2014-05-24 08:45:00', 'name 4')")
        self.__server_5.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('2014-05-23 13:45:00', 'name 5')")
        self.__server_5.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('2013-05-27 11:45:00', 'name 6')")
        self.__server_5.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('2012-05-26 10:45:00', 'name 7')")
        self.__server_5.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('2011-05-25 09:45:00', 'name 8')")
        self.__server_5.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('2010-05-24 08:45:00', 'name 9')")
        self.__server_5.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('2009-05-23 13:45:00', 'name 10')")

        self.__server_5.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('1914-05-27 11:45:00', 'name 1')")
        self.__server_5.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('1914-05-26 10:45:00', 'name 2')")
        self.__server_5.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('1914-05-25 09:45:00', 'name 3')")
        self.__server_5.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('1914-05-24 08:45:00', 'name 4')")
        self.__server_5.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('1914-05-23 13:45:00', 'name 5')")
        self.__server_5.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('1913-05-27 11:45:00', 'name 6')")
        self.__server_5.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('1912-05-26 10:45:00', 'name 7')")
        self.__server_5.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('1911-05-25 09:45:00', 'name 8')")
        self.__server_5.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('1910-05-24 08:45:00', 'name 9')")
        self.__server_5.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('1909-05-23 13:45:00', 'name 10')")

        self.__server_5.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('1814-05-27 11:45:00', 'name 1')")
        self.__server_5.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('1814-05-26 10:45:00', 'name 2')")
        self.__server_5.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('1814-05-25 09:45:00', 'name 3')")
        self.__server_5.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('1814-05-24 08:45:00', 'name 4')")
        self.__server_5.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('1814-05-23 13:45:00', 'name 5')")
        self.__server_5.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('1813-05-27 11:45:00', 'name 6')")
        self.__server_5.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('1812-05-26 10:45:00', 'name 7')")
        self.__server_5.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('1811-05-25 09:45:00', 'name 8')")
        self.__server_5.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('1810-05-24 08:45:00', 'name 9')")
        self.__server_5.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('1809-05-23 13:45:00', 'name 10')")

        self.__server_5.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('1714-05-27 11:45:00', 'name 1')")
        self.__server_5.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('1714-05-26 10:45:00', 'name 2')")
        self.__server_5.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('1714-05-25 09:45:00', 'name 3')")
        self.__server_5.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('1714-05-24 08:45:00', 'name 4')")
        self.__server_5.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('1714-05-23 13:45:00', 'name 5')")
        self.__server_5.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('1713-05-27 11:45:00', 'name 6')")
        self.__server_5.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('1712-05-26 10:45:00', 'name 7')")
        self.__server_5.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('1711-05-25 09:45:00', 'name 8')")
        self.__server_5.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('1710-05-24 08:45:00', 'name 9')")
        self.__server_5.exec_stmt("INSERT INTO db2.t2 "
                              "VALUES('1709-05-23 13:45:00', 'name 10')")

        self.__server_5.exec_stmt("DROP DATABASE IF EXISTS db3")
        self.__server_5.exec_stmt("CREATE DATABASE db3")
        self.__server_5.exec_stmt("CREATE TABLE db3.t3"
                                  "(date_of_joining VARCHAR(30), name VARCHAR(30))")

        self.__server_5.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('2014-05-27 11:45:00', 'name 1')")
        self.__server_5.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('2014-05-26 10:45:00', 'name 2')")
        self.__server_5.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('2014-05-25 09:45:00', 'name 3')")
        self.__server_5.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('2014-05-24 08:45:00', 'name 4')")
        self.__server_5.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('2014-05-23 13:45:00', 'name 5')")
        self.__server_5.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('2013-05-27 11:45:00', 'name 6')")
        self.__server_5.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('2012-05-26 10:45:00', 'name 7')")
        self.__server_5.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('2011-05-25 09:45:00', 'name 8')")
        self.__server_5.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('2010-05-24 08:45:00', 'name 9')")
        self.__server_5.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('2009-05-23 13:45:00', 'name 10')")

        self.__server_5.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('1914-05-27 11:45:00', 'name 1')")
        self.__server_5.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('1914-05-26 10:45:00', 'name 2')")
        self.__server_5.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('1914-05-25 09:45:00', 'name 3')")
        self.__server_5.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('1914-05-24 08:45:00', 'name 4')")
        self.__server_5.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('1914-05-23 13:45:00', 'name 5')")
        self.__server_5.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('1913-05-27 11:45:00', 'name 6')")
        self.__server_5.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('1912-05-26 10:45:00', 'name 7')")
        self.__server_5.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('1911-05-25 09:45:00', 'name 8')")
        self.__server_5.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('1910-05-24 08:45:00', 'name 9')")
        self.__server_5.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('1909-05-23 13:45:00', 'name 10')")

        self.__server_5.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('1814-05-27 11:45:00', 'name 1')")
        self.__server_5.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('1814-05-26 10:45:00', 'name 2')")
        self.__server_5.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('1814-05-25 09:45:00', 'name 3')")
        self.__server_5.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('1814-05-24 08:45:00', 'name 4')")
        self.__server_5.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('1814-05-23 13:45:00', 'name 5')")
        self.__server_5.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('1813-05-27 11:45:00', 'name 6')")
        self.__server_5.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('1812-05-26 10:45:00', 'name 7')")
        self.__server_5.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('1811-05-25 09:45:00', 'name 8')")
        self.__server_5.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('1810-05-24 08:45:00', 'name 9')")
        self.__server_5.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('1809-05-23 13:45:00', 'name 10')")

        self.__server_5.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('1714-05-27 11:45:00', 'name 1')")
        self.__server_5.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('1714-05-26 10:45:00', 'name 2')")
        self.__server_5.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('1714-05-25 09:45:00', 'name 3')")
        self.__server_5.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('1714-05-24 08:45:00', 'name 4')")
        self.__server_5.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('1714-05-23 13:45:00', 'name 5')")
        self.__server_5.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('1713-05-27 11:45:00', 'name 6')")
        self.__server_5.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('1712-05-26 10:45:00', 'name 7')")
        self.__server_5.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('1711-05-25 09:45:00', 'name 8')")
        self.__server_5.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('1710-05-24 08:45:00', 'name 9')")
        self.__server_5.exec_stmt("INSERT INTO db3.t3 "
                              "VALUES('1709-05-23 13:45:00', 'name 10')")

        self.__server_5.exec_stmt("DROP DATABASE IF EXISTS db4")
        self.__server_5.exec_stmt("CREATE DATABASE db4")
        self.__server_5.exec_stmt("CREATE TABLE db4.t4"
                                  "(date_of_joining TEXT, name VARCHAR(30))")

        self.__server_5.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('2014-05-27 11:45:00', 'name 1')")
        self.__server_5.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('2014-05-26 10:45:00', 'name 2')")
        self.__server_5.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('2014-05-25 09:45:00', 'name 3')")
        self.__server_5.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('2014-05-24 08:45:00', 'name 4')")
        self.__server_5.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('2014-05-23 13:45:00', 'name 5')")
        self.__server_5.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('2013-05-27 11:45:00', 'name 6')")
        self.__server_5.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('2012-05-26 10:45:00', 'name 7')")
        self.__server_5.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('2011-05-25 09:45:00', 'name 8')")
        self.__server_5.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('2010-05-24 08:45:00', 'name 9')")
        self.__server_5.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('2009-05-23 13:45:00', 'name 10')")

        self.__server_5.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('1914-05-27 11:45:00', 'name 1')")
        self.__server_5.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('1914-05-26 10:45:00', 'name 2')")
        self.__server_5.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('1914-05-25 09:45:00', 'name 3')")
        self.__server_5.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('1914-05-24 08:45:00', 'name 4')")
        self.__server_5.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('1914-05-23 13:45:00', 'name 5')")
        self.__server_5.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('1913-05-27 11:45:00', 'name 6')")
        self.__server_5.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('1912-05-26 10:45:00', 'name 7')")
        self.__server_5.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('1911-05-25 09:45:00', 'name 8')")
        self.__server_5.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('1910-05-24 08:45:00', 'name 9')")
        self.__server_5.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('1909-05-23 13:45:00', 'name 10')")

        self.__server_5.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('1814-05-27 11:45:00', 'name 1')")
        self.__server_5.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('1814-05-26 10:45:00', 'name 2')")
        self.__server_5.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('1814-05-25 09:45:00', 'name 3')")
        self.__server_5.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('1814-05-24 08:45:00', 'name 4')")
        self.__server_5.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('1814-05-23 13:45:00', 'name 5')")
        self.__server_5.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('1813-05-27 11:45:00', 'name 6')")
        self.__server_5.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('1812-05-26 10:45:00', 'name 7')")
        self.__server_5.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('1811-05-25 09:45:00', 'name 8')")
        self.__server_5.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('1810-05-24 08:45:00', 'name 9')")
        self.__server_5.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('1809-05-23 13:45:00', 'name 10')")

        self.__server_5.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('1714-05-27 11:45:00', 'name 1')")
        self.__server_5.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('1714-05-26 10:45:00', 'name 2')")
        self.__server_5.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('1714-05-25 09:45:00', 'name 3')")
        self.__server_5.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('1714-05-24 08:45:00', 'name 4')")
        self.__server_5.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('1714-05-23 13:45:00', 'name 5')")
        self.__server_5.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('1713-05-27 11:45:00', 'name 6')")
        self.__server_5.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('1712-05-26 10:45:00', 'name 7')")
        self.__server_5.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('1711-05-25 09:45:00', 'name 8')")
        self.__server_5.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('1710-05-24 08:45:00', 'name 9')")
        self.__server_5.exec_stmt("INSERT INTO db4.t4 "
                              "VALUES('1709-05-23 13:45:00', 'name 10')")


        self.__group_5 = Group("GROUPID5", "Fifth description.")
        Group.add( self.__group_5)
        self.__group_5.add_server(self.__server_5)
        tests.utils.configure_decoupled_master(self.__group_5, self.__server_5)

        self.__options_6 = {
            "uuid" :  _uuid.UUID("{cc45b12b-98d1-414c-96af-9e9d4b179678}"),
            "address"  : MySQLInstances().get_address(5),
            "user" : MySQLInstances().user,
            "passwd": MySQLInstances().passwd,
        }

        uuid_server6 = MySQLServer.discover_uuid(self.__options_6["address"])
        self.__options_6["uuid"] = _uuid.UUID(uuid_server6)
        self.__server_6 = MySQLServer(**self.__options_6)
        MySQLServer.add(self.__server_6)
        self.__server_6.connect()

        self.__group_6 = Group("GROUPID6", "Sixth description.")
        Group.add( self.__group_6)
        self.__group_6.add_server(self.__server_6)
        tests.utils.configure_decoupled_master(self.__group_6, self.__server_6)

        status = self.proxy.sharding.create_definition("RANGE_DATETIME", "GROUPID1")
        self.check_xmlrpc_command_result(status)
        self.assertEqual(status[2], 1)

        status = self.proxy.sharding.add_table(1, "db1.t1", "date_of_joining",
                                                True)
        self.check_xmlrpc_command_result(status)
        status = self.proxy.sharding.add_table(1, "db2.t2", "date_of_joining",
                                                True)
        self.check_xmlrpc_command_result(status)
        status = self.proxy.sharding.add_table(1, "db3.t3", "date_of_joining",
                                                True)
        self.check_xmlrpc_command_result(status)
        status = self.proxy.sharding.add_table(1, "db4.t4", "date_of_joining",
                                                True)
        self.check_xmlrpc_command_result(status)

        status = self.proxy.sharding.add_shard(
            1,
            "GROUPID2/1700-01-01,GROUPID3/1800-01-01,GROUPID4/1900-01-01,GROUPID5/2000-01-01",
            "ENABLED"
        )
        self.assertStatus(status, _executor.Job.SUCCESS)
        self.check_xmlrpc_command_result(status)

        status = self.proxy.sharding.prune_shard("db1.t1")
        self.check_xmlrpc_command_result(status)

    def test_datetime_range_trigger(self):
        '''Test that the triggers defined on the shards, work, and verify
        that they ensure that the shard keys confine to the defined ranges.
        '''
        status = self.proxy.sharding.lookup_servers("db1.t1", "1750-10-11",  "LOCAL")
        found = False
        for obtained_server in  self.check_xmlrpc_iter(status):
            if obtained_server['status'] == "PRIMARY" and obtained_server['mode'] == "READ_WRITE":
                found = True
                break;
        self.assertTrue(found) 
        shard_uuid = obtained_server['server_uuid']
        shard_server = MySQLServer.fetch(shard_uuid)
        shard_server.connect()
        #Inserting a row out of range should fail.
        self.assertRaises(_errors.DatabaseError, shard_server.exec_stmt,
                          "INSERT INTO db1.t1 VALUES('1600-10-11','Data220')")
        self.assertRaises(_errors.DatabaseError, shard_server.exec_stmt,
                          "INSERT INTO db1.t1 VALUES('1650-08-09','Data220')")
        self.assertRaises(_errors.DatabaseError, shard_server.exec_stmt,
                          "INSERT INTO db1.t1 VALUES('1900-10-11','Data220')")
        self.assertRaises(_errors.DatabaseError, shard_server.exec_stmt,
                          "INSERT INTO db1.t1 VALUES('1950-08-09','Data220')")

        self.assertRaises(_errors.DatabaseError, shard_server.exec_stmt,
                          "INSERT INTO db2.t2 VALUES('1600-10-11','Data220')")
        self.assertRaises(_errors.DatabaseError, shard_server.exec_stmt,
                          "INSERT INTO db2.t2 VALUES('1650-08-09','Data220')")
        self.assertRaises(_errors.DatabaseError, shard_server.exec_stmt,
                          "INSERT INTO db2.t2 VALUES('1900-10-11','Data220')")
        self.assertRaises(_errors.DatabaseError, shard_server.exec_stmt,
                          "INSERT INTO db2.t2 VALUES('1950-08-09','Data220')")

        self.assertRaises(_errors.DatabaseError, shard_server.exec_stmt,
                          "INSERT INTO db3.t3 VALUES('1600-10-11','Data220')")
        self.assertRaises(_errors.DatabaseError, shard_server.exec_stmt,
                          "INSERT INTO db3.t3 VALUES('1650-08-09','Data220')")
        self.assertRaises(_errors.DatabaseError, shard_server.exec_stmt,
                          "INSERT INTO db3.t3 VALUES('1900-10-11','Data220')")
        self.assertRaises(_errors.DatabaseError, shard_server.exec_stmt,
                          "INSERT INTO db3.t3 VALUES('1950-08-09','Data220')")

        self.assertRaises(_errors.DatabaseError, shard_server.exec_stmt,
                          "INSERT INTO db4.t4 VALUES('1600-10-11','Data220')")
        self.assertRaises(_errors.DatabaseError, shard_server.exec_stmt,
                          "INSERT INTO db4.t4 VALUES('1650-08-09','Data220')")
        self.assertRaises(_errors.DatabaseError, shard_server.exec_stmt,
                          "INSERT INTO db4.t4 VALUES('1900-10-11','Data220')")
        self.assertRaises(_errors.DatabaseError, shard_server.exec_stmt,
                          "INSERT INTO db4.t4 VALUES('1950-08-09','Data220')")

        #Inserting a value within the valid range should pass.
        shard_server.exec_stmt(
            "INSERT INTO db1.t1 VALUES('1750-10-11','Data007')"
        )
        shard_server.exec_stmt(
            "INSERT INTO db1.t1 VALUES('1760-05-06','Data007')"
        )
        shard_server.exec_stmt(
            "INSERT INTO db1.t1 VALUES('1770-06-07','Data007')"
        )
        shard_server.exec_stmt(
            "INSERT INTO db2.t2 VALUES('1750-10-11','Data007')"
        )
        shard_server.exec_stmt(
            "INSERT INTO db2.t2 VALUES('1760-05-06','Data007')"
        )
        shard_server.exec_stmt(
            "INSERT INTO db2.t2 VALUES('1770-06-07','Data007')"
        )
        shard_server.exec_stmt(
            "INSERT INTO db3.t3 VALUES('1750-10-11','Data007')"
        )
        shard_server.exec_stmt(
            "INSERT INTO db3.t3 VALUES('1760-05-06','Data007')"
        )
        shard_server.exec_stmt(
            "INSERT INTO db3.t3 VALUES('1770-06-07','Data007')"
        )
        shard_server.exec_stmt(
            "INSERT INTO db4.t4 VALUES('1750-10-11','Data007')"
        )
        shard_server.exec_stmt(
            "INSERT INTO db4.t4 VALUES('1760-05-06','Data007')"
        )
        shard_server.exec_stmt(
            "INSERT INTO db4.t4 VALUES('1770-06-07','Data007')"
        )

        status = self.proxy.sharding.lookup_servers("db1.t1", "1850-10-11",  "LOCAL")
        found = False
        for obtained_server in  self.check_xmlrpc_iter(status):
            if obtained_server['status'] == "PRIMARY" and obtained_server['mode'] == "READ_WRITE":
                found = True
                break;
        self.assertTrue(found) 
        shard_uuid = obtained_server['server_uuid']
        shard_server = MySQLServer.fetch(shard_uuid)
        shard_server.connect()
        #Inserting a row out of range should fail.
        self.assertRaises(_errors.DatabaseError, shard_server.exec_stmt,
                          "INSERT INTO db1.t1 VALUES('1700-10-11','Data220')")
        self.assertRaises(_errors.DatabaseError, shard_server.exec_stmt,
                          "INSERT INTO db1.t1 VALUES('1750-08-09','Data220')")
        self.assertRaises(_errors.DatabaseError, shard_server.exec_stmt,
                          "INSERT INTO db1.t1 VALUES('2000-10-11','Data220')")
        self.assertRaises(_errors.DatabaseError, shard_server.exec_stmt,
                          "INSERT INTO db1.t1 VALUES('2050-08-09','Data220')")
        #Inserting a value within the valid range should pass.
        shard_server.exec_stmt(
            "INSERT INTO db1.t1 VALUES('1850-10-11','Data007')"
        )
        shard_server.exec_stmt(
            "INSERT INTO db1.t1 VALUES('1860-05-06','Data007')"
        )
        shard_server.exec_stmt(
            "INSERT INTO db1.t1 VALUES('1870-06-07','Data007')"
        )


        status = self.proxy.sharding.lookup_servers("db1.t1", "1950-10-11",  "LOCAL")
        found = False
        for obtained_server in  self.check_xmlrpc_iter(status):
            if obtained_server['status'] == "PRIMARY" and obtained_server['mode'] == "READ_WRITE":
                found = True
                break;
        self.assertTrue(found) 
        shard_uuid = obtained_server['server_uuid']
        shard_server = MySQLServer.fetch(shard_uuid)
        shard_server.connect()
        #Inserting a row out of range should fail.
        self.assertRaises(_errors.DatabaseError, shard_server.exec_stmt,
                          "INSERT INTO db1.t1 VALUES('1800-10-11','Data220')")
        self.assertRaises(_errors.DatabaseError, shard_server.exec_stmt,
                          "INSERT INTO db1.t1 VALUES('1850-08-09','Data220')")
        self.assertRaises(_errors.DatabaseError, shard_server.exec_stmt,
                          "INSERT INTO db1.t1 VALUES('2100-10-11','Data220')")
        self.assertRaises(_errors.DatabaseError, shard_server.exec_stmt,
                          "INSERT INTO db1.t1 VALUES('2150-08-09','Data220')")
        #Inserting a value within the valid range should pass.
        shard_server.exec_stmt(
            "INSERT INTO db1.t1 VALUES('1950-10-11','Data007')"
        )
        shard_server.exec_stmt(
            "INSERT INTO db1.t1 VALUES('1960-05-06','Data007')"
        )
        shard_server.exec_stmt(
            "INSERT INTO db1.t1 VALUES('1970-06-07','Data007')"
        )

        status = self.proxy.sharding.lookup_servers("db1.t1", "2050-10-11",  "LOCAL")
        found = False
        for obtained_server in  self.check_xmlrpc_iter(status):
            if obtained_server['status'] == "PRIMARY" and obtained_server['mode'] == "READ_WRITE":
                found = True
                break;
        self.assertTrue(found) 
        shard_uuid = obtained_server['server_uuid']
        shard_server = MySQLServer.fetch(shard_uuid)
        shard_server.connect()
        #Inserting a row out of range should fail.
        self.assertRaises(_errors.DatabaseError, shard_server.exec_stmt,
                          "INSERT INTO db1.t1 VALUES('1900-10-11','Data220')")
        self.assertRaises(_errors.DatabaseError, shard_server.exec_stmt,
                          "INSERT INTO db1.t1 VALUES('1950-08-09','Data220')")
        self.assertRaises(_errors.DatabaseError, shard_server.exec_stmt,
                          "INSERT INTO db1.t1 VALUES('1800-10-11','Data220')")
        self.assertRaises(_errors.DatabaseError, shard_server.exec_stmt,
                          "INSERT INTO db1.t1 VALUES('1850-08-09','Data220')")
        #Inserting a value within the valid range should pass.
        shard_server.exec_stmt(
            "INSERT INTO db1.t1 VALUES('2050-10-11','Data007')"
        )
        shard_server.exec_stmt(
            "INSERT INTO db1.t1 VALUES('2060-05-06','Data007')"
        )
        shard_server.exec_stmt(
            "INSERT INTO db1.t1 VALUES('2170-06-07','Data007')"
        )

    def tearDown(self):
        status = self.proxy.sharding.disable_shard("1")
        status = self.proxy.sharding.disable_shard("2")
        status = self.proxy.sharding.disable_shard("3")
        status = self.proxy.sharding.disable_shard("4")
        status = self.proxy.sharding.disable_shard("5")
        status = self.proxy.sharding.disable_shard("6")

        status = self.proxy.sharding.remove_shard("1")
        status = self.proxy.sharding.remove_shard("2")
        status = self.proxy.sharding.remove_shard("3")
        status = self.proxy.sharding.remove_shard("4")
        status = self.proxy.sharding.remove_shard("5")
        status = self.proxy.sharding.remove_shard("6")

        status = self.proxy.sharding.remove_table("db1.t1")
        self.check_xmlrpc_command_result(status)

        status = self.proxy.sharding.remove_table("db2.t2")
        self.check_xmlrpc_command_result(status)

        status = self.proxy.sharding.remove_table("db3.t3")
        self.check_xmlrpc_command_result(status)

        status = self.proxy.sharding.remove_table("db4.t4")
        self.check_xmlrpc_command_result(status)

        status = self.proxy.sharding.remove_definition("1")
        self.check_xmlrpc_command_result(status)

        self.proxy.group.demote("GROUPID1")
        self.proxy.group.demote("GROUPID2")
        self.proxy.group.demote("GROUPID3")
        self.proxy.group.demote("GROUPID4")
        self.proxy.group.demote("GROUPID5")
        self.proxy.group.demote("GROUPID6")

        for group_id in ("GROUPID1", "GROUPID2", "GROUPID3",
            "GROUPID4", "GROUPID5", "GROUPID6"):
            status = self.proxy.group.lookup_servers(group_id)
            for obtained_server in  self.check_xmlrpc_iter(status):
                status = self.proxy.group.remove(
                    group_id, obtained_server["server_uuid"]
                )
                self.check_xmlrpc_command_result(status)
            status = self.proxy.group.destroy(group_id)
            self.check_xmlrpc_command_result(status)

        tests.utils.cleanup_environment()
