package com.sm.config.security.shiro;

import com.sm.entity.User;
import com.sm.service.UserService;
import org.apache.shiro.authc.*;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.util.ByteSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.util.Set;

public class ShiroRealm extends AuthorizingRealm {

    @Autowired
    private UserService userService;


    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
        SimpleAuthorizationInfo authorizationInfo = new SimpleAuthorizationInfo();
        User user = (User) principals.getPrimaryPrincipal();
        Set<String> roles = userService.getRoles(user.getId());
        authorizationInfo.setRoles(roles);
        return authorizationInfo;
    }

    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        UsernamePasswordToken upToken = (UsernamePasswordToken) token;
        String password = new String((char[]) token.getCredentials());
        User user = userService.findByUsername(upToken.getUsername());
        if (user == null) {
            throw new UnknownAccountException("Invalid username or password");
        }
        boolean passwordMatches = BCrypt.checkpw(password, user.getPassword());

        if (!passwordMatches) {
            throw new IncorrectCredentialsException("Invalid username or password");
        }

        SimpleAuthenticationInfo authInfo = new SimpleAuthenticationInfo(user.getUsername(),
                password, getName());
     //   authInfo.setCredentialsSalt(ByteSource.Util.bytes(user.getSalt()));
        return authInfo;
    }
}
