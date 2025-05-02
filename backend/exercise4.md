# Benutzerverwaltung

## Authentisierung und Autorisierung

In "klassischen" Webanwendungen erfolgt die Autorisierung einzelner Zugriffe in der Regel über eine *Session* auf dem Server: Nachdem der Benutzer sich angemeldet hat, 
wird ein *Session-Cookie* gesetzt und der Server merkt sich, zu welchem Benutzer die Session gehört.

Dieses Vorgehen hat Nachteile, wenn die Anwendung aus mehreren *Micro Services* besteht oder wenn man das Backend skalieren möchte.

Eine Alternative ist die Autorisierung einzelner Zugriffe über *JSON Web Token*. Mit so einem – von einem Authentication Server ausgestellten – Token weißt sich das 
Frontend gegenüber dem Backend aus.   

```mermaid
sequenceDiagram
    participant Frontend
    participant Auth-Server
    participant Backend
    Frontend->>Auth-Server: /auth
    Auth-Server->>Frontend: redirect to login page
    Note right of Auth-Server: Follow Openid Connect<br>flow
    Frontend->>Auth-Server: Send username & password
    Auth-Server->>Frontend: Return access token

    Frontend->>Backend: DELETE /todos/4711
    Note right of Backend: Authorization via <br>JSON Web Token
```

## Keycloak-Server auf jupiter.fh-swf.de

Für das Praktikum ist auf jupiter.fh-swf.de ein Keycloak-Server mit der Realm `webentwicklung` eingerichtet. Dort gibt es einen Benutzer `public` mit dem Passwort `todo`.
Ein JSON Web Token für diesen Benutzer kann wie folgt mithilfe von `curl` abgerufen werden:

```shell
curl --location --request POST 'https://keycloak.gawron.cloud/realms/webentwicklung/protocol/openid-connect/token' \
     --header 'Authorization: Basic dG9kby1iYWNrZW5kOjFWTlRsQ3ZzaHJjWkQ0Zm0wZUpqVE9QZWN2d210M0x5' \
     --header 'Content-Type: application/x-www-form-urlencoded' \
     --data-urlencode 'grant_type=password' \
     --data-urlencode 'username=public' \
     --data-urlencode 'password=todo'
```

Der zugehörige Public Key, mit dem die JWTs signiert sind, lautet 
```
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyn2vP592Ju/iKXQW1DCrSTXyQXyo11Qed1SdzFWC+mRtdgioKibzYMBt2MfAJa6YoyrVNgOtGvK659MjHALtotPQGmis1VVvBeMFdfh+zyFJi8NPqgBTXz6bQfnu85dbxVAg95J+1Ud0m4IUXME1ElOyp1pi88+w0C6ErVcFCyEDS3uAajBY6vBIuPrlokbl6RDcvR9zX85s+R/s7JeP1XV/e8gbnYgZwxcn/6+7moHPDl4LqvVDKnDq9n4W6561s8zzw8EoAwwYXUC3ZPe2/3DcUCh+zTF2nOy8HiN808CzqLq1VeD13q9DgkAmBWFNSaXb6vK6RIQ9+zr2cwdXiwIDAQAB
-----END PUBLIC KEY-----
```

Hier die (leicht gekürzte) Konfiguration der Realm, die Sie unter 
[https://jupiter.fh-swf.de/keycloak/realms/webentwicklung/.well-known/openid-configuration](https://jupiter.fh-swf.de/keycloak/realms/webentwicklung/.well-known/openid-configuration) abrufen können:

```JSON
{
    "issuer": "https://jupiter.fh-swf.de/keycloak/realms/webentwicklung",
    "authorization_endpoint": "https://jupiter.fh-swf.de/keycloak/realms/webentwicklung/protocol/openid-connect/auth",
    "token_endpoint": "https://jupiter.fh-swf.de/keycloak/realms/webentwicklung/protocol/openid-connect/token",
    "introspection_endpoint": "https://jupiter.fh-swf.de/keycloak/realms/webentwicklung/protocol/openid-connect/token/introspect",
    "userinfo_endpoint": "https://jupiter.fh-swf.de/keycloak/realms/webentwicklung/protocol/openid-connect/userinfo",
    "end_session_endpoint": "https://jupiter.fh-swf.de/keycloak/realms/webentwicklung/protocol/openid-connect/logout",
    "grant_types_supported": [
        "authorization_code",
        "implicit",
        "refresh_token",
        "password",
        "client_credentials",
        "urn:ietf:params:oauth:grant-type:device_code",
        "urn:openid:params:grant-type:ciba"
    ],
    "response_types_supported": [
        "code",
        "none",
        "id_token",
        "token",
        "id_token token",
        "code id_token",
        "code token",
        "code id_token token"
    ],

    "response_modes_supported": [
        "query",
        "fragment",
        "form_post",
        "query.jwt",
        "fragment.jwt",
        "form_post.jwt",
        "jwt"
    ],
    "token_endpoint_auth_methods_supported": [
        "private_key_jwt",
        "client_secret_basic",
        "client_secret_post",
        "tls_client_auth",
        "client_secret_jwt"
    ],
    "introspection_endpoint_auth_methods_supported": [
        "private_key_jwt",
        "client_secret_basic",
        "client_secret_post",
        "tls_client_auth",
        "client_secret_jwt"
    ],
    "claims_supported": [
        "aud",
        "sub",
        "iss",
        "auth_time",
        "name",
        "given_name",
        "family_name",
        "preferred_username",
        "email",
        "acr"
    ],
    "claim_types_supported": [
        "normal"
    ],
    "claims_parameter_supported": true,
    "scopes_supported": [
        "openid",
        "offline_access",
        "web-origins",
        "microprofile-jwt",
        "email",
        "profile",
        "address",
        "phone",
        "roles",
        "acr"
    ],
}
```

## Aufgabe 1: Autorisierung der API-Zugriffe via JWT

In dieser Aufgabe sollen die Zugriffe auf das API vor unberechtigten Zugriffen geschützt werden.

### Aufgabe 1.1: Installation und Konfiguration von Passport.js

Installieren Sie `passport` und `passport-jwt`. Konfigurieren Sie Passport so, dass JWTs wahlweise als *Bearer Token* oder in einem Cookie gesendet werden können.
Dabei können Sie folgende Option für sie `JwtStrategy` verwenden:

```Javascript
jwtFromRequest: (req) => {
    let token = ExtractJwt.fromAuthHeaderAsBearerToken()(req);
    if (!token) {
        if (req.cookies.token) {
            token = req.cookies.token
        }
    }
```

### Aufgabe 1.2: Erweiterung des Datenmodells

Sobald Zugriffe mit einem Benutzer erfolgen, ist es sinnvoll, den Benutzer mit in die MongoDB aufzunehmen (warum ist das so?). Erweitern Sie die Datenbankzugriffe so, dass ein Zugriff auf "fremde" Todos verboten ist und mit einem HTTP-Status 403 (*Forbidden*) beantwortet wird.

## Aufgabe 2: Test der Zugriffe

Testen Sie sowohl erlaubte als auch nicht erlaubte Zugriffe mit dem Tool `postman`.

## Aufgabe 4: Login im Frontend
Passen Sie das Frontend so an, dass es sich gegenüber dem Backend authentifiziert. 

Dazu müssen Sie auch die REST-Schnittstelle so erweitern, dass ein Login möglich ist. Insbesondere benötigen Sie:

- Im Frontend eine Methode `checkLogin(response)`, die nach einem `fetch()` den Statuscode 401 verarbeitet: 

    ```Javascript
    /** Check whether we need to login.
     * Check the status of a response object. If the status is 401, construct an appropriate 
     * login URL and redict there.
     * 
     * @param response Response object to check
     * @returns original response object if status is not 401
     */
    function checkLogin(response) {
        // check if we need to login
        if (response.status == 401) {
            console.log("GET %s returned 401, need to log in", API)
            let state = document.cookie
                .split('; ')
                .find((row) => row.startsWith("state="))
                ?.split("=")[1]
            console.log("state: %s", state)
            let params = new URLSearchParams()
            params.append("response_type", "code")
            params.append("redirect_uri", new URL("/oauth_callback", window.location))
            params.append("client_id", "todo-backend")
            params.append("scope", "openid")
            params.append("state", state)
    
            // redirect to login URL with proper parameters
            window.location = LOGIN_URL + "?" + params.toString()
            throw ("Need to log in")
        }
        else return response
    }
    ```

- Eine *Backend-Route* `GET /callback`<br>
   An diese Route wird der Client vom Keycloak-Server weitergeleitet, um das Frontend mit einem JWT zu versorgen.
   Im Anschluss sollte ein Cookie gesetzt werden, das den JWT enthält, und der Benutzer auf die Startseite weitergeleitet werden.


