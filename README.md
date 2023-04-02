## SpringBoot + Apache Shiro + JWT Example 

- Using Apache Shiro security to authenticate and authorize and jwt will be used to validate token for protected endpoint
- Do not mix apache shiro security and spring security in the same application otherwise it would be complex to debug and handle application.
- Create a SecurityManager instance and configure it with a Realm that knows how to authenticate users. We then bind the SecurityManager instance to the current thread using SecurityUtils.setSecurityManager(). Next, we create a UsernamePasswordToken instance with the user's credentials and get the Subject instance for the current thread using SecurityUtils.getSubject(). Finally, we attempt to authenticate the user by calling Subject.login(token). If the authentication succeeds, we can proceed with the user's request. If the authentication fails, an AuthenticationException will be thrown
- Java 11
- Spring boot 2.7.3
- H2 database
- Below is the curl command
- Check user from ImportUserData class
- Role management in the endpoint is missing. I will update later. ***



- **Public endpoint**

```http
  curl --location --request GET 'http://localhost:8080/public'
```

- **User Login endpoint and fetch the token and use in the protected endpoint**

```http
  curl --location --request POST 'http://localhost:8080/login' \
--header 'Content-Type: application/json' \
--data-raw '{
    "username" : "hunain",
    "password" : "password"
}'
```

- **Admin endpoint**

```http
  curl --location --request GET 'http://localhost:8080/api/admin' \
--header 'Authorization: Bearer dummy' \
--data-raw ''
```
