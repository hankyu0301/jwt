package org.hankyu.jwt.config.auth;

import lombok.RequiredArgsConstructor;
import org.hankyu.jwt.model.User;
import org.hankyu.jwt.repository.UserRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

//http://localhost:8080/login
@Service
@RequiredArgsConstructor
public class PrincipalDeatilsService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        System.out.println("PrincipalDetailsService loadUserByUsername()####### " );
        User userEntity = userRepository.findByUsername(username);
        System.out.println("loadUserByUsername :" + userEntity);
        return new PrincipalDetails(userEntity);
    }
}
