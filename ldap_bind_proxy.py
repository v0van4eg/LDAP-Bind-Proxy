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
    Простой пример использования `ProxyBase` для логирования запросов и ответов.
    """

    def __init__(self):
        super().__init__()
        # Dictionary to store user session information: {bind_dn: {'access_token': ..., 'groups': [...]} }
        self.user_sessions = {}

    def get_groups_from_token(self, access_token):
        """
        Извлечение информации о группах из OIDC токена доступа.
        Это упрощенная реализация - на практике вам может потребоваться 
        декодировать JWT токен или вызвать конечную точку userinfo для получения членства в группах.
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
        Фильтрация записей LDAP на основе информации о членстве в группах, полученной из OIDC.
        Возвращаются только те записи, к которым пользователь имеет доступ на основе своего членства в группах.
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
        Логирование представления полученного запроса.
        """
        print(repr(request))
        if isinstance(request, pureldap.LDAPBindRequest):
            # Получение OIDC токена через грант пароля
            ## Быстрое и грязное извлечение имени пользователя из DN, предполагая, что это CN
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

            # Логирование имени пользователя и кода состояния
            print(username.decode('utf-8') + " " + str(oidc_response.status_code))
            
            if oidc_response.status_code == requests.codes['ok']:
                # Успешная привязка LDAP
                # Сохранение информации о сессии пользователя, включая группы из OIDC токена
                response_json = oidc_response.json()
                access_token = json.dumps(response_json)  # Сохранение всего ответа в виде строки
                user_groups = self.get_groups_from_token(access_token)
                
                # Сохранение информации о сессии: bind DN -> {token, groups}
                self.user_sessions[request.dn] = {
                    'access_token': access_token,
                    'groups': user_groups
                }
                
                # Установка текущего привязанного DN для этого соединения
                self.current_bound_dn = request.dn
                
                msg= pureldap.LDAPBindResponse(
                        resultCode=ldaperrors.Success.resultCode
                    )
            else:
                # Неверные учетные данные (см. логи keycloak)
                msg= pureldap.LDAPBindResponse(
                        resultCode=ldaperrors.LDAPInvalidCredentials.resultCode
                    )
            reply(msg)
        if isinstance(request, pureldap.LDAPSearchRequest):
            # Обработка запросов поиска LDAP с фильтрацией по группам
            baseDN = request.base
            scope = request.scope
            derefAliases = request.derefAliases
            sizeLimit = request.sizeLimit
            timeLimit = request.timeLimit
            typesOnly = request.typesOnly
            filterStr = str(request.filter)
            
            # Проверка, содержит ли фильтр проверку членства в группе
            # Примеры фильтров могут быть:
            # - (memberOf=cn=groupname,ou=groups,dc=example,dc=org)
            # - (&(objectClass=user)(memberOf=cn=developers,ou=groups,dc=example,dc=org))
            print(f"Search request: base={baseDN}, filter={filterStr}")
            
            # Извлечение информации о группах из фильтра, если она присутствует
            group_filter_parts = []
            if 'memberOf' in filterStr:
                # Разбор атрибута memberOf для извлечения имен групп
                import re
                group_matches = re.findall(r'memberOf=([^,]+)', filterStr)
                group_filter_parts.extend(group_matches)
            
            # Поскольку теперь у нас есть реальное соединение с LDAP, давайте выполним фактический поиск
            # но мы должны учитывать членство пользователя в группах из OIDC
            
            # Для демонстрации мы перешлем запрос на реальный сервер LDAP
            # В полной реализации мы бы:
            # 1. Определили аутентифицированного пользователя
            # 2. Получили их членство в группах из OIDC токена
            # 3. Изменили бы фильтр поиска на основе разрешенных групп
            # 4. Выполнили бы поиск
            # 5. Потенциально отфильтровали бы результаты на основе прав доступа к группам
            
            # Получение групп пользователя из сессии (на основе bind DN соединения)
            # Пока мы предположим, что соединение представляет собой привязанного пользователя
            # В реальной реализации мы бы отслеживали, какой пользователь связан с каждым соединением
            user_groups = []
            if hasattr(self, 'current_bound_dn') and self.current_bound_dn in self.user_sessions:
                user_groups = self.user_sessions[self.current_bound_dn]['groups']
            # В этой реализации мы временно сохраним текущий привязанный DN во время операции привязки
            
            def handle_search_response(response):
                if isinstance(response, pureldap.LDAPSearchResultEntry):
                    # Это запись результата поиска
                    # Применить фильтрацию на основе групп, если необходимо
                    if group_filter_parts:
                        # Если исходный фильтр проверял конкретные группы,
                        # проверим, что у текущего пользователя есть доступ к этим группам
                        filtered_entries = self.filter_entries_by_group_membership([response], group_filter_parts, user_groups)
                        if filtered_entries:
                            reply(filtered_entries[0])
                    else:
                        # Фильтрация по группам не требуется, просто пересылаем запись
                        reply(response)
                elif isinstance(response, pureldap.LDAPSearchResultDone):
                    # Поиск завершен, пересылаем сообщение о завершении
                    reply(response)
                    return False  # Остановить обработку
                return True  # Продолжить обработку
            
            # Пересылка запроса поиска на реальный сервер LDAP
            d = self.client.send_request(request, handle_search_response)
            
            # Нам нужно правильно обработать ответ, но поскольку это асинхронно,
            # мы возвращаемся рано (None), а обратный вызов обрабатывает ответы
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

    ## TODO: Это обходной путь, реализовать более чистый класс прокси от класса ServerBase
    def connectionMade(self):
        """ Переопределенный метод для настройки прокси с реальным соединением с сервером LDAP для поиска.
        Нам нужно реальное соединение для выполнения поиска и применения фильтров по группам """
        print("connectionMade called")
        # Инициализация клиентского соединения с реальным сервером LDAP
        # Получение данных о сервере LDAP из переменных окружения
        ldap_server = os.environ.get("REAL_LDAP_SERVER", "ldap://localhost:389")
        proxiedEndpointStr = ldap_server
        
        d = self.clientConnector(
            overrides={},
            bindAddress=None,
        )

        def error(err):
            print(f"Не удалось подключиться к реальному серверу LDAP: {err}")
            return err

        def connected(client):
            self.client = client
            client.serviceIdentity = self.serviceIdentity
            # Пересылка любых ожидающих запросов
            self._continuePumping()
            return client

        d.addCallback(connected)
        d.addErrback(error)
        # Сохранение отложенного объекта для дальнейшего использования
        self.clientConnectionDeferred = d
        # Инициализация текущего привязанного DN значением None
        self.current_bound_dn = None
        ldapserver.BaseLDAPServer.connectionMade(self)
    
if __name__ == '__main__':
    """
    Демонстрационный LDAP OIDC прокси; прослушивает localhost:389 и преобразует в протокол OIDC
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