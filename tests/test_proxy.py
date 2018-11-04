# -*- coding: utf-8 -*-
#
#   oauthkit-google: OAuthKit for Google
#   Copyright (C) 2015-2018 mete0r <mete0r@sarangbang.or.kr>
#
#   This program is free software: you can redistribute it and/or modify
#   it under the terms of the GNU Lesser General Public License as published by
#   the Free Software Foundation, either version 3 of the License, or
#   (at your option) any later version.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU Lesser General Public License for more details.
#
#   You should have received a copy of the GNU Lesser General Public License
#   along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
from __future__ import absolute_import
from __future__ import print_function
from __future__ import unicode_literals
from unittest import TestCase

from zope.interface import providedBy


class GoogleClientSecretTest(TestCase):

    def test_proxy(self):
        from jsonable_objects.interfaces import IJsonable
        from oauthkit_google.interfaces import IGoogleClientSecret
        from oauthkit_google.proxy import GoogleClientSecret

        d = {
            "installed": {
                "client_id": "12345678-invalid.apps.googleusercontent.com",
                "client_secret": "not-a-secret",
                "project_id": "foobar",
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://www.googleapis.com/oauth2/v3/token",
                "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",  # noqa
                "redirect_uris": [
                    "urn:ietf:wg:oauth:2.0:oob",
                    "http://localhost"
                ]
            }
        }

        clientsecret = GoogleClientSecret(d['installed'])
        self.assertTrue(IGoogleClientSecret in list(providedBy(clientsecret)))
        self.assertTrue(IJsonable in list(providedBy(clientsecret)))
        self.assertEquals(d['installed'], clientsecret.__jsonable__)
        self.assertEquals(
            d['installed']['client_id'],
            clientsecret.client_id
        )
        self.assertEquals(
            d['installed']['client_secret'],
            clientsecret.client_secret
        )
        self.assertEquals(
            d['installed']['auth_uri'],
            clientsecret.auth_uri
        )
        self.assertEquals(
            d['installed']['token_uri'],
            clientsecret.token_uri
        )
        self.assertEquals(
            d['installed']['auth_provider_x509_cert_url'],
            clientsecret.auth_provider_x509_cert_url
        )
        self.assertEquals(
            d['installed']['redirect_uris'],
            clientsecret.redirect_uris
        )
        self.assertEquals(
            None,
            clientsecret.client_email,
        )
        self.assertEquals(
            None,
            clientsecret.client_x509_cert_url,
        )


class GoogleTokenResponseTest(TestCase):

    def test_proxy_without_refreshtoken(self):
        from jsonable_objects.interfaces import IJsonable
        from oauthkit_google.interfaces import IGoogleTokenResponse
        from oauthkit_google.proxy import GoogleTokenResponse

        d = {
            "access_token": "invalid-token",
            "expires_in": 3600,
            "token_type": "Bearer"
        }
        resp = GoogleTokenResponse(d)

        self.assertTrue(IGoogleTokenResponse in list(providedBy(resp)))
        self.assertTrue(IJsonable in list(providedBy(resp)))
        self.assertEquals(d, resp.__jsonable__)
        self.assertEquals(
            d['access_token'], resp.access_token
        )
        self.assertEquals(
            d['expires_in'], resp.expires_in
        )
        self.assertEquals(
            d['token_type'], resp.token_type
        )
        self.assertEquals(
            None, resp.refresh_token
        )

    def test_proxy(self):
        from jsonable_objects.interfaces import IJsonable
        from oauthkit_google.interfaces import IGoogleTokenResponse
        from oauthkit_google.proxy import GoogleTokenResponse

        d = {
            "access_token": "invalid-token",
            "expires_in": 3600,
            "token_type": "Bearer",
            "refresh_token": "invalid-refresh-token",
        }
        resp = GoogleTokenResponse(d)

        self.assertTrue(IGoogleTokenResponse, list(providedBy(resp)))
        self.assertTrue(IJsonable in list(providedBy(resp)))
        self.assertEquals(d, resp.__jsonable__)
        self.assertEquals(
            d['access_token'], resp.access_token
        )
        self.assertEquals(
            d['expires_in'], resp.expires_in
        )
        self.assertEquals(
            d['token_type'], resp.token_type
        )
        self.assertEquals(
            d['refresh_token'], resp.refresh_token
        )
