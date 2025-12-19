#! /usr/bin/env python
# Copyright 2024 please-open.it
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

from ldaptor.protocols import pureldap
from ldaptor.protocols.ldap.ldapclient import LDAPClient
from ldaptor.protocols.ldap.ldapconnector import connectToLDAPEndpoint
from ldaptor.protocols.ldap.proxybase import ProxyBase
from ldaptor.protocols.ldap import ldapserver, ldaperrors
from twisted.internet import protocol, reactor
from twisted.python import log
from functools import partial
import sys
import requests
import os

from mock import Mock
import json

class OidcProxy(ProxyBase):
    """
    A simple example of using `ProxyBase` to log requests and responses.
    """

    def __init__(self):
        super().__init__()
        # Dictionary to store user session information: {bind_dn: {'access_token': ..., 'groups': [...]} }
        self.user_sessions = {}

    def get_groups_from_token(self, access_token):
        """
        Extract group information from OIDC access token.
        This is a simplified implementation - in reality, you might need to 
        decode the JWT token or call userinfo endpoint to get group memberships.
        """
        try:
            # In a real implementation, we would decode the JWT token
            # or call the userinfo endpoint to get user's groups
            # For now, we'll simulate extracting groups from token
            # assuming the token response includes group information
            
            # Usually OIDC tokens contain group info in claims
            # This depends on how your OIDC provider is configured
            # For demonstration purposes, we'll parse it as JSON if possible
            token_data = json.loads(access_token) if isinstance(access_token, str) and access_token.startswith('{') else {}
            return token_data.get('groups', [])
        except:
            # If parsing fails, return empty list
            return []

    def filter_entries_by_group_membership(self, entries, required_groups, user_groups):
        """
        Filter LDAP entries based on group membership information obtained from OIDC.
        Only return entries that the user has permission to access based on their group membership.
        """
        # In a real implementation, this would validate each entry against 
        # the user's actual group memberships from OIDC token
        filtered_entries = []
        
        # For now, we'll implement a simple check: if user_groups contains any of required_groups,
        # they can access these entries
        if not required_groups or any(user_group in required_groups for user_group in user_groups):
            filtered_entries = entries
        # Otherwise, return empty list (no access)
        
        return filtered_entries

    def handleBeforeForwardRequest(self, request, controls, reply):
        """
        Log the representation of the request received.
        """
        print(repr(request))
        if isinstance(request, pureldap.LDAPBindRequest):
            # Get OIDC token through password grant
            ## Quick and dirty username from DN assuming it is CN
            username = request.dn.split(b',')[0][3:]
            password = request.auth

            ## TODO : Nice to have Add support for OTP within password

            url = os.environ.get("LDAP_PROXY_TOKEN_URL")
            client_id = os.environ.get("LDAP_PROXY_CLIENT_ID")
            client_secret = os.environ.get("LDAP_PROXY_CLIENT_SECRET")

            payload = 'client_id={client_id}&client_secret={client_secret}&grant_type=password&username={username}&password={password}'.format(client_id=client_id, client_secret=client_secret, username=username.decode('utf-8'), password=password.decode('utf-8'))
            headers = {
            'Content-Type': 'application/x-www-form-urlencoded'
            }
            print(url)
            oidc_response = requests.request("POST", url, headers=headers, data=payload)

            # Logging username and status code
            print(username.decode('utf-8') + " " + str(oidc_response.status_code))
            
            if oidc_response.status_code == requests.codes['ok']:
                # LDAP Bind success
                # Store user session info including groups from OIDC token
                response_json = oidc_response.json()
                access_token = json.dumps(response_json)  # Store entire response as string
                user_groups = self.get_groups_from_token(access_token)
                
                # Store session info: bind DN -> {token, groups}
                self.user_sessions[request.dn] = {
                    'access_token': access_token,
                    'groups': user_groups
                }
                
                # Set the current bound DN for this connection
                self.current_bound_dn = request.dn
                
                msg= pureldap.LDAPBindResponse(
                        resultCode=ldaperrors.Success.resultCode
                    )
            else:
                # Invalid credentials (see keycloak logs)
                msg= pureldap.LDAPBindResponse(
                        resultCode=ldaperrors.LDAPInvalidCredentials.resultCode
                    )
            reply(msg)
        if isinstance(request, pureldap.LDAPSearchRequest):
            # Process LDAP search requests with group filtering
            baseDN = request.base
            scope = request.scope
            derefAliases = request.derefAliases
            sizeLimit = request.sizeLimit
            timeLimit = request.timeLimit
            typesOnly = request.typesOnly
            filterStr = str(request.filter)
            
            # Check if the filter contains a group membership check
            # Example filters could be:
            # - (memberOf=cn=groupname,ou=groups,dc=example,dc=org)
            # - (&(objectClass=user)(memberOf=cn=developers,ou=groups,dc=example,dc=org))
            print(f"Search request: base={baseDN}, filter={filterStr}")
            
            # Extract group information from the filter if present
            group_filter_parts = []
            if 'memberOf' in filterStr:
                # Parse the memberOf attribute to extract group names
                import re
                group_matches = re.findall(r'memberOf=([^,]+)', filterStr)
                group_filter_parts.extend(group_matches)
            
            # Since we now have a real LDAP connection, let's perform the actual search
            # but we need to consider the user's group memberships from OIDC
            
            # For demonstration, we'll forward the request to the real LDAP server
            # In a complete implementation, we would:
            # 1. Determine the authenticated user
            # 2. Get their group memberships from OIDC token
            # 3. Modify the search filter based on allowed groups
            # 4. Perform the search
            # 5. Potentially filter results based on group access rights
            
            # Get the user's groups from the session (based on the bind DN of the connection)
            # For now, we'll assume the connection represents a bound user
            # In a real implementation, we would track which user is associated with each connection
            user_groups = []
            if hasattr(self, 'current_bound_dn') and self.current_bound_dn in self.user_sessions:
                user_groups = self.user_sessions[self.current_bound_dn]['groups']
            # In this implementation, we'll temporarily store the current bound DN during bind operation
            
            def handle_search_response(response):
                if isinstance(response, pureldap.LDAPSearchResultEntry):
                    # This is a search result entry
                    # Apply group-based filtering if needed
                    if group_filter_parts:
                        # If the original filter was checking for specific groups,
                        # verify that the current user has access to those groups
                        filtered_entries = self.filter_entries_by_group_membership([response], group_filter_parts, user_groups)
                        if filtered_entries:
                            reply(filtered_entries[0])
                    else:
                        # No group filtering needed, just forward the entry
                        reply(response)
                elif isinstance(response, pureldap.LDAPSearchResultDone):
                    # Search is complete, forward the done message
                    reply(response)
                    return False  # Stop processing
                return True  # Continue processing
            
            # Forward the search request to the real LDAP server
            d = self.client.send_request(request, handle_search_response)
            
            # We need to handle the response properly, but since this is async,
            # we return early (None) and let the callback handle responses
            return None
        if isinstance(request, pureldap.LDAPExtendedRequest):
            msg = pureldap.LDAPExtendedResponse(
                resultCode=ldaperrors.Success.resultCode
            )
            reply(msg)
        if isinstance(request, pureldap.LDAPUnbindRequest):
            msg = pureldap.LDAPBindResponse(
                resultCode=ldaperrors.Success.resultCode
            )
            reply(msg)
        return None

    ## TODO: This is a Workaround, implement a cleaner proxy class from class ServerBase
    def connectionMade(self):
        """ Overridden method to setup proxy with real LDAP server connection for searches.
        We need a real connection to perform searches and apply group filters """
        print("connectionMade called")
        # Initialize the client connection to the real LDAP server
        # Get LDAP server details from environment variables
        ldap_server = os.environ.get("REAL_LDAP_SERVER", "ldap://localhost:389")
        proxiedEndpointStr = ldap_server
        
        d = self.clientConnector(
            overrides={},
            bindAddress=None,
        )

        def error(err):
            print(f"Could not connect to real LDAP server: {err}")
            return err

        def connected(client):
            self.client = client
            client.serviceIdentity = self.serviceIdentity
            # Forward any pending requests
            self._continuePumping()
            return client

        d.addCallback(connected)
        d.addErrback(error)
        # Store the deferred for later use
        self.clientConnectionDeferred = d
        # Initialize current bound DN to None
        self.current_bound_dn = None
        ldapserver.BaseLDAPServer.connectionMade(self)
    
if __name__ == '__main__':
    """
    Demonstration LDAP OIDC proxy; listens on localhost:389 and translate to OIDC protocol
    """
    log.startLogging(sys.stderr)
    factory = protocol.ServerFactory()
    proxiedEndpointStr = 'NoEndpointneeded'
    use_tls = False
    clientConnector = partial(
        connectToLDAPEndpoint,
        reactor,
        proxiedEndpointStr,
        LDAPClient)

    def buildProtocol():
        proto = OidcProxy()
        proto.clientConnector = clientConnector
        proto.use_tls = use_tls
        return proto

    factory.protocol = buildProtocol
    reactor.listenTCP(389, factory)
    reactor.run()