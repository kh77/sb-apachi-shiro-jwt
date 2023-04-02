package com.sm.service;


import com.sm.entity.Role;
import com.sm.entity.User;
import com.sm.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Set;

@Service
@Slf4j
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public User findByUsername(String username) {
        return userRepository.findByUsernameIgnoreCase(username).orElseThrow(() -> new RuntimeException("User is not exist"));
    }

//    implements UserDetailsService is not used in Apache Shiro in the same way as in Spring Security
//    Apache Shiro has its own concept of a realm, which is responsible for loading user details
//    and performing authentication and authorization checks. Realms can be implemented in various ways, such as by loading user details from a database or other data source.
//    @Override
//    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
//        User user = findByUsername(username);
//        var roles = Stream.of(user.getRole()).map(x -> new SimpleGrantedAuthority(x.name())).collect(Collectors.toList());
//        return new org.springframework.security.core.userdetails.User(user.getUsername(), user.getPassword(), roles);
//    }

    public Set<String> getRoles(Long id) {
        Role role = userRepository.findById(id).get().getRole();
        return Set.of(role.name());
    }

    public Set<String> getRoles(String username) {
        Role role = userRepository.findByUsernameIgnoreCase(username).get().getRole();
        return Set.of(role.name());
    }

    public void registerUser(String username, String password) {
        User user = new User();
        user.setUsername(username);
        user.setPassword(passwordEncoder.encode(password));
        user.setRole(Role.USER);
        create(user);
    }

    public void create(User user) {
        userRepository.save(user);
    }
}
