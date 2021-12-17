package org.hankyu.jwt.config.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import org.hankyu.jwt.config.auth.PrincipalDetails;
import org.hankyu.jwt.model.User;
import org.hankyu.jwt.repository.UserRepository;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.parameters.P;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class JwtAuthorizationFilter extends BasicAuthenticationFilter {

    private UserRepository userRepository;
    //시큐리티가 가지고 있는 필터중 권한이나 인증이 필요한 특정 주소를 요청했을 때 거쳐야하는
    // BasicAuthenticationFilter를 상속받음.


    public JwtAuthorizationFilter(AuthenticationManager authenticationManager, UserRepository userRepository) {
        super(authenticationManager);
        this.userRepository = userRepository;
    }

    //인증,권한이 필요한 주소요청이 있을 때 해당 필터를 거쳐야함.
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        System.out.println("BasicAuthenticationFilter 호출됨");
        String jwtHeader = request.getHeader("Authorization");
        System.out.println("jwtHeader : " +jwtHeader);

        if(jwtHeader ==null || !jwtHeader.startsWith("Bearer")) {
            chain.doFilter(request,response);
            return;
        }

        String jwtToken = request.getHeader("Authorization").replace("Bearer ","");
        String username = JWT.require(Algorithm.HMAC512("jang")).build()
                .verify(jwtToken).getClaim("username").asString();

        //사인 정상
        if(username != null) {
            User userEntity = userRepository.findByUsername(username);

            //JWT 토큰 서명을 통해서 서명이 정상이면 Authentication 객체를 만들어준다.
            PrincipalDetails principalDetails = new PrincipalDetails(userEntity);
            Authentication authentication = new UsernamePasswordAuthenticationToken(principalDetails,null, principalDetails.getAuthorities());

            //세션에 Authentication 객체를 저장
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }
        chain.doFilter(request, response);
    }
}
