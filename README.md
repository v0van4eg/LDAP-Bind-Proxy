


# Избавьтесь от устаревшего Active Directory/LDAP с помощью Keycloak и небольшого кусочка кастомного ПО

## Кратко

Как запустить простой прокси привязки LDAP для гранта пароля Keycloak OIDC в двух словах.

## Отказ от ответственности и лицензия

Принципы и код, представленные здесь, являются лишь доказательством концепции и не должны использоваться в продакшене как есть. Используйте на свой страх и риск. Если вы видите какие-либо проблемы с концепцией или реализацией, не стесняйтесь открывать issue или отправлять pull request на github. [https://github.com/please-openit/LDAP-Bind-Proxy](https://github.com/please-openit/LDAP-Bind-Proxy)

Этот прототип распространяется под лицензией Apache 2.0. См. LICENSE.md в репозитории git.

## LDAP/AD все чаще становится устаревшим сервисом, но не всегда

Если вы используете Active Directory в качестве основного инструмента управления пользователями и довольны этим, эта статья может быть не для вас.
Нет ничего плохого в использовании Active Directory или LDAP в качестве ядра вашей системы, эта статья предназначена для тех, кто вынужден иметь дело с одним или двумя устаревшими приложениями, поддерживающими только протокол LDAP.

В этом случае обычный способ сделать это с Keycloak - использовать OpenLDAP в качестве бэкенда пользователей Keycloak. Это позволяет включить как OpenID Connect, так и LDAP, но имеет серьезные недостатки. Если OpenLDAP выходит из строя, Keycloak также выходит из строя, это новая точка отказа в вашей инфраструктуре. Таким образом, необходимо обслуживать и реплицировать этот элемент. Иногда это может быть много работы, только чтобы поддерживать совместимость с не критичным устаревшим приложением.

![Старая конфигурация с двумя точками отказа](image.png)

## Элегантный минималистичный LDAP прокси для Keycloak

Чтобы справиться с описанной выше ситуацией, было бы здорово иметь минималистичный прокси для выполнения и преобразования LDAP bind запроса к серверу keycloak.


Keycloak реализует прямой грант пароля OpenID Connect, это позволяет представить более простую и надежную архитектуру.

![Новая архитектура с одной точкой отказа](image-1.png)

Количество компонентов такое же, но LDAP прокси не имеет состояния и менее критичен в зависимости от приложений, которые на него полагаются.

Это также более простой компонент, который можно запустить где угодно, где он нужен, даже рядом с клиентским приложением для обычного использования.

## Как работает LDAP Bind прокси

Ldap bind прокси просто "переведет" полученный LDAPBind запрос в грант пароля. Для этого ему нужен свой собственный выделенный конфиденциальный клиент, который позволяет прямой доступ по гранту.

![Диаграмма последовательности LDAP Bind прокси](image-2.png)

Пользователь входит в систему так, как всегда, устаревшее приложение отправляет LDAPBindRequest так, как всегда, затем LDAP Bind прокси преобразует его в грант пароля и дает LDAP Bind Response в соответствии с ответом keycloak.

Для обеспечения безопасности входа, клиент должен быть конфиденциальным, а LDAP bind прокси должен быть развернут в безопасной сети и на безопасной виртуальной машине, чтобы сохранить конфиденциальность учетных данных клиента.

## Реализация

Полная демонстрация доступна на github, не стесняйтесь попробовать самостоятельно. [https://github.com/please-openit/LDAP-Bind-Proxy](https://github.com/please-openit/LDAP-Bind-Proxy)

Прототип опирается на LDAPProxy от twisted/ldaptor для удобства. Но он мог быть построен на основе любого современного LDAP слоя.

Все параметры поступают из переменных окружения со стандартными именами, которые вы уже знаете.

- LDAP_PROXY_TOKEN_URL
- LDAP_PROXY_CLIENT_ID
- LDAP_PROXY_CLIENT_SECRET


Here is the core part of the code doing the main operation :

```python
            # Get username and password from LDAPBind request
            username = request.dn.split(b',')[0][3:]
            password = request.auth

            
            # Url of the token endpoint of OIDC provider
            url = os.environ.get("LDAP_PROXY_TOKEN_URL")
            client_id = os.environ.get("LDAP_PROXY_CLIENT_ID")
            client_secret = os.environ.get("LDAP_PROXY_CLIENT_SECRET")

            # Payload of the password grant request
            payload = 'client_id={client_id}&client_secret={client_secret}&grant_type=password&username={username}&password={password}'.format(client_id=client_id, client_secret=client_secret, username=username.decode('utf-8'), password=password.decode('utf-8'))
            headers = {
            'Content-Type': 'application/x-www-form-urlencoded'
            }

            # Doing le password grand request
            oidc_response = requests.request("POST", url, headers=headers, data=payload)

            # Logging username and status code
            print(username.decode('utf-8') + " " + str(oidc_response.status_code))


            # Build a LDAPBindResponse, succes or failure depending of the status code of the password grant request
            if oidc_response.status_code == requests.codes['ok']:
                # LDAP Bind success
                msg= pureldap.LDAPBindResponse(
                        resultCode=ldaperrors.Success.resultCode
                    )
            else:
                # Invalid credentials LDAP error 49 (see keycloak logs for details)
                msg= pureldap.LDAPBindResponse(
                        resultCode=ldaperrors.LDAPInvalidCredentials.resultCode
                    )
            reply(msg)
```

The operation used (grant_type=password) is the same as described in oidc-bash.sh : [https://github.com/please-openit/oidc-bash-client/blob/master/oidc-client.sh#L33](https://github.com/please-openit/oidc-bash-client/blob/master/oidc-client.sh#L33)


Interesting note on implementation of this poc :

The library used is designed to forward its requests to a backend LDAP server. In this case we don't want that to occur so the LDAPClient object handling upstream LDAP communication is replaced by a Mock object. A cleaner implementation using the same library is possible.

```python
    ## TODO: This is a Workaround, implement a cleaner proxy class from class ServerBase
    def connectionMade(self):
        """ Overridden method to prevent proxy from trying to connect non-existing backend server.
        Mocking client class to drop every operation made to it"""
        print("connectionMade called")
        self.client = Mock()
        ldapserver.BaseLDAPServer.connectionMade(self)
```

## Proof of concept usage

Build and start keycloak and LDAP Bind proxy from `docker compose`.

```bash
docker compose up -d --build
```

Test with `python ./ldap_client_bind.py` or any client you want.
The test binddn and the test password are the followings :
* Bind DN : cn=test,ou=people,dc=example,dc=org
* Password : pwtest

In fact in this configuration **only the CN part of the Bind DN is important** and used as username.
You can even try by yourself to create another user in keycloak (admin/admin for admin console), in that case you must login for the first time through the account console of keycloak. Any required action on the account or temporary password will block password grant. Login into the account console is the most straightforward way to ensure everything is fine.

Example using ldap-utils ldapwhoami :

```bash
$ ldapwhoami -D "cn=test,ou=people,dc=example,dc=org" -w pwtest; echo $?
0
```
In this case `ldapwhoami` sends a `LDAPExtendedRequest` to get details and the proxy response is an empty ``LDAPExtendedResponse`. Therefore there is nothing printed in the output of the command but the return code is 0 and the log of the proxy indicates a successful bind. It would be nice in the future to map some information from IDtoken to the `LDAPExtendedResponse`

Example using ldap-utils ldapsearch :

```bash
$ ldapsearch -x -D 'cn=test,ou=people,dc=example,dc=org' -w pwtest
# extended LDIF
#
# LDAPv3
# base <> (default) with scope subtree
# filter: (objectclass=*)
# requesting: ALL
#

# search result
search: 2
result: 0 Success

# numResponses: 1
```

`ldapsearch` has a more verbose output despite the fact it receives an empty `LDAPSearchResultDone`. Maybe better for testing.

Only the LDAPBindRequest is really supported, other replies are empty dummies, this will be enough for login operation but don't expect showing anything in an LDAP admin tool for now.

## Keycloak configuration

A client (with authentication) is needed. No "standard flow", of course no URI in configuration. Just "Direct access grant" enabled.

![Direct acces grant configuration](image-3.png)

## Conclusion/Going further

This piece of code and documentation demonstrate the opportunity of such an architecture. The possibility to save a lot of time in MOC by not having to maintain an LDAP service which is often poorly integrated with modern cloud platform. Sometimes the LDAP connection depends on a VPN link between a local infrastructure and a server or cloud provider. Given the fact that keycloak relies on its LDAP backend when configured, we often recommend our clients to put an LDAP replica alongside the keycloak but this solution comes with a cost. In some cases this heavy configuration could have been avoided with a tool like the LDAP Bind proxy presented here. 

However, to date, it isn't near to be suitable for production use.

A lot of thing has to be done to make this concept ready for production, including but not limited to :
* Implement mapping with the token and a real ldapwhoami.
* Add basic read-only search.
* Track LDAP sessions and keep OpenID tokens in a key-value cache store.
* Implement real logout.

