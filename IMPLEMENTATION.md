# LDAP Filter by Group Implementation

## Overview
This document describes the implementation of LDAP filtering by group membership in the OIDC LDAP proxy.

## Changes Made

### 1. Session Management
- Added `user_sessions` dictionary to store user session information
- Each session contains: `{bind_dn: {'access_token': ..., 'groups': [...]}}`
- Added `current_bound_dn` to track the currently authenticated user per connection

### 2. Group Information Extraction
- Implemented `get_groups_from_token()` method to extract group information from OIDC access tokens
- Added `filter_entries_by_group_membership()` method to filter LDAP entries based on user's group membership

### 3. Authentication Updates
- Modified `LDAPBindRequest` handling to store user session information after successful authentication
- Set `current_bound_dn` when a user successfully binds to the LDAP server

### 4. Search Request Processing
- Enhanced `LDAPSearchRequest` processing to extract group information from search filters
- Implemented filtering of search results based on user's group membership
- Forward search requests to the real LDAP server while applying group-based access controls

## LDAP Filter Examples

The implementation handles various LDAP group filter patterns:

1. **Direct group membership**:
   - `(memberOf=cn=developers,ou=groups,dc=example,dc=org)`

2. **Combined filters**:
   - `(&(objectClass=user)(memberOf=cn=developers,ou=groups,dc=example,dc=org))`

## How Group Filtering Works

1. When a user authenticates via OIDC, their group memberships are extracted from the access token
2. When a search request is made, the proxy extracts group filters from the search query
3. The proxy forwards the search to the real LDAP server
4. Before returning results, the proxy filters entries based on the user's group membership
5. Only entries that the user has permission to access are returned

## Configuration

The proxy uses the following environment variables:

- `LDAP_PROXY_TOKEN_URL`: OIDC token endpoint
- `LDAP_PROXY_CLIENT_ID`: OIDC client ID
- `LDAP_PROXY_CLIENT_SECRET`: OIDC client secret
- `REAL_LDAP_SERVER`: Real LDAP server endpoint (default: ldap://localhost:389)

## Architecture

The proxy now establishes a real connection to an LDAP server for performing searches, while maintaining the OIDC authentication layer. This allows for proper group-based filtering of search results.