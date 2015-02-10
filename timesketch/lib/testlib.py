# Copyright 2015 Google Inc. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""This module contains common test utilities for Timesketch."""

from flask_testing import TestCase

from timesketch import create_app
from timesketch.lib import datastore
from timesketch.lib.definitions import HTTP_STATUS_CODE_REDIRECT
from timesketch.models import init_db
from timesketch.models import drop_all
from timesketch.models import db_session
from timesketch.models.user import User
from timesketch.models.sketch import Sketch
from timesketch.models.sketch import Timeline
from timesketch.models.sketch import SearchIndex
from timesketch.models.sketch import View
from timesketch.models.sketch import Event


class TestConfig(object):
    """Config for the test environment."""
    DEBUG = True
    SECRET_KEY = 'testing'
    SQLALCHEMY_DATABASE_URI = "sqlite://"
    WTF_CSRF_ENABLED = False
    ELASTIC_HOST = None
    ELASTIC_PORT = None


class MockDataStore(datastore.DataStore):
    """A mock implementation of a Datastore."""
    event_dict = {
        "_index": [],
        "_id": "adc123",
        "_type": "plaso_event",
        "_source": {
            "es_index": "",
            "es_id": "",
            "label": "",
            "timestamp": 1410895419859714,
            "timestamp_desc": "",
            "datetime": "2014-09-16T19:23:40+00:00",
            "source_short": "",
            "source_long": "",
            "message": "",
            }
    }
    search_result_dict = {
        "hits": {
            "hits": [
                {
                    "sort": [
                        1410593223000
                    ],
                    "_type": "plaso_event",
                    "_source": {
                        "timestamp": 1410593222543942,
                        "message": "Test event",
                        "timesketch_label": [
                            {
                                "user_id": 1,
                                "name": "__ts_star",
                                "sketch_id": 1
                            },
                            {
                                "user_id": 2,
                                "name": "__ts_star",
                                "sketch_id": 99
                            },
                        ],
                        "timestamp_desc": "Content Modification Time",
                        "datetime": "2014-09-13T07:27:03+00:00"
                    },
                    "_score": "null",
                    "_index": "test",
                    "_id": "test"
                }
            ],
            "total": 1,
            "max_score": "null"
        },
        "_shards": {
            "successful": 10,
            "failed": 0,
            "total": 10
        },
        "took": 5,
        "timed_out": False
    }

    def __init__(self, host, port):
        """Initialize the datastore.

        Args:
            host: Hostname or IP address to the datastore
            port: The port used by the datastore
        """
        self.host = host
        self.port = port

    def search(
            self, unused_sketch_id, unused_query, unused_query_filter,
            unused_indices):
        """Mock a search query.

        Returns:
            A dictionary with search result.
        """
        return self.search_result_dict

    def get_event(self, unused_searchindex_id, unused_event_id):
        """Mock returning a single event from the datastore.

        Returns:
            A dictionary with event data.
        """
        return self.event_dict

    def set_label(
            self, searchindex_id, event_id, sketch_id, user_id, label,
            toggle=False):
        """Mock adding a label to an event."""
        return


class BaseTest(TestCase):
    """Base class for tests."""

    COLOR_WHITE = 'FFFFFF'

    def create_app(self):
        """Setup the Flask application.

        Returns:
            Flask application (instance of flask.app.Flask)
        """
        app = create_app(TestConfig)
        return app

    def _commit_to_database(self, model):
        """Add object to the database session and commit.

        Args:
            model: Instance of timesketch.models.[model] object
        """
        db_session.add(model)
        db_session.commit()

    def _create_user(self, username, set_password=False):
        """Create a user in the database.

        Args:
            username: Username (string)
            set_password: Boolean value to decide if a password should be set
        Returns:
            A user (instance of timesketch.models.user.User)
        """
        user = User(username=username)
        if set_password:
            user.set_password(plaintext='test', rounds=1)
        self._commit_to_database(user)
        return user

    def _create_sketch(self, name, user, acl=False):
        """Create a sketch in the database.

        Args:
            name: Name of the sketch (string)
            user: A user (instance of timesketch.models.user.User)
            acl: Boolean value to decide if ACL permissions should be set

        Returns:
            A sketch (instance of timesketch.models.sketch.Sketch)
        """
        sketch = Sketch(name=name, description=name, user=user)
        if acl:
            for permission in ['read', 'write', 'delete']:
                sketch.grant_permission(user=user, permission=permission)
        label = sketch.Label(label='Test label', user=user)
        status = sketch.Status(status='Test status', user=user)
        sketch.labels.append(label)
        sketch.status.append(status)
        self._commit_to_database(sketch)
        return sketch

    def _create_searchindex(self, name, user):
        """Create a searchindex in the database.

        Args:
            name: Name of the searchindex (string)
            user: A user (instance of timesketch.models.user.User)

        Returns:
            A searchindex (instance of timesketch.models.sketch.SearchIndex)
        """
        searchindex = SearchIndex(
            name=name, description=name, index_name=name, user=user)
        self._commit_to_database(searchindex)
        return searchindex

    def _create_event(self, sketch, searchindex, user):
        """Create an event in the database.

        Args:
            sketch: A sketch (instance of timesketch.models.sketch.Sketch)
            searchindex:
                A searchindex (instance of timesketch.models.sketch.SearchIndex)
            user: A user (instance of timesketch.models.user.User)

        Returns:
            An event (instance of timesketch.models.sketch.Event)
        """
        event = Event(
            sketch=sketch, searchindex=searchindex, document_id='test')
        comment = event.Comment(comment='test', user=user)
        event.comments.append(comment)
        self._commit_to_database(event)
        return event

    def _create_timeline(self, name, sketch, searchindex, user):
        """Create a timeline in the database.

        Args:
            name: Name of the timeline (string)
            sketch: A sketch (instance of timesketch.models.sketch.Sketch)
            searchindex:
                A searchindex (instance of timesketch.models.sketch.SearchIndex)
            user: A user (instance of timesketch.models.user.User)

        Returns:
            A timeline (instance of timesketch.models.sketch.Timeline)
        """
        timeline = Timeline(
            name=name, description=name, user=user, sketch=sketch,
            searchindex=searchindex, color=self.COLOR_WHITE)
        self._commit_to_database(timeline)
        return timeline

    def _create_view(self, name, sketch, user):
        """Create a view in the database.

        Args:
            name: Name of the view (string)
            sketch: A sketch (instance of timesketch.models.sketch.Sketch)
            user: A user (instance of timesketch.models.user.User)

        Returns:
            A view (instance of timesketch.models.sketch.View)
        """
        view = View(
            name=name, query_string=name, query_filter="", user=user,
            sketch=sketch)
        self._commit_to_database(view)
        return view

    def setUp(self):
        """Setup the test database."""
        init_db()

        self.user1 = self._create_user(username="test1", set_password=True)
        self.user2 = self._create_user(username="test2", set_password=False)

        self.sketch1 = self._create_sketch(
            name="Test 1", user=self.user1, acl=True)
        self.sketch2 = self._create_sketch(
            name="Test 2", user=self.user1, acl=False)

        self.searchindex = self._create_searchindex(
            name='test', user=self.user1)

        self.timeline = self._create_timeline(
            name="Timeline 1", sketch=self.sketch1,
            searchindex=self.searchindex, user=self.user1)

        self.view1 = self._create_view(
            name='View 1', sketch=self.sketch1, user=self.user1)
        self.view2 = self._create_view(
            name='View 2', sketch=self.sketch2, user=self.user1)
        self.view3 = self._create_view(
            name='', sketch=self.sketch1, user=self.user2)

        self.event = self._create_event(
            sketch=self.sketch1, searchindex=self.searchindex, user=self.user1)

    def tearDown(self):
        """Tear down the test database."""
        db_session.remove()
        drop_all()

    def login(self):
        """Authenticate the test user."""
        self.client.post(
            '/login/', data=dict(username='test1', password='test'),
            follow_redirects=True)

    def test_unauthenticated(self):
        """
        Generic test for all resources. It tests that no
        unauthenticated request are accepted.
        """
        if not getattr(self, 'resource_url', False):
            self.skipTest(self)

        response = self.client.get(self.resource_url)
        if response.status_code == 405:
            response = self.client.post(self.resource_url)
        self.assertIn('/login/', response.data)
        self.assertEquals(response.status_code, HTTP_STATUS_CODE_REDIRECT)


class ModelBaseTest(BaseTest):
    """Base class for database model tests."""
    def _test_db_object(self, expected_result=None, model_cls=None):
        """Generic test that checks if the stored data is correct."""
        db_obj = model_cls.query.get(1)
        for x in expected_result:
            k, v = x[0], x[1]
            self.assertEquals(db_obj.__getattribute__(k), v)