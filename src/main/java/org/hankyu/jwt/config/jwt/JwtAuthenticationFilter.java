package org.hankyu.jwt.config.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.hankyu.jwt.config.auth.PrincipalDetails;
import org.hankyu.jwt.model.User;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.IOException;
import java.util.Date;

@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;

    //username, password를 받아서 AuthenticationManager를 이용해서 로그인 시도함.
    //로그인 시도하면 PrincipalDetailsService의 loadUserByUsername()실행됨.
    //PrincipalDetails를 세션에 담고(권한 관리를 위해서), JWT토큰을 만들어서 응답.
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException {

        try {
/*            BufferedReader br = request.getReader();
            String input = null;
            while((input = br.readLine()) != null) {
                System.out.println(input);
            }
            System.out.println(request.getInputStream());*/
            ObjectMapper om = new ObjectMapper();
            User user = om.readValue(request.getInputStream(),User.class);
            System.out.println(user);

            UsernamePasswordAuthenticationToken authenticationToken =
                    new UsernamePasswordAuthenticationToken(user.getUsername(),user.getPassword());

            Authentication authentication =
                    authenticationManager.authenticate(authenticationToken);

            PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
            System.out.println("Authentication :" +principalDetails.getUser().getUsername());

            //return 하면 authentication 객체가 session 영역에 저장됨.
            //return은 권한 관리를 security가 대신 해주기 때문에 편의성을 위해 하는 것임.
            //굳이 JWT token을 사용하면서 세션을 만들 이유가 없음. 근데 단지 권한 처리 때문에 session에 넣음
            return authentication;
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    //attemptAuthentication실행 후 인증이 성공하면 JWT 토큰 만들기
    //JWT토큰 만들어서 request요청한 사용자에게 JWT토큰을 response
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response,
                                            FilterChain chain, Authentication authResult)
                                            throws IOException, ServletException {
        PrincipalDetails principalDetails = (PrincipalDetails) authResult.getPrincipal();

        //HMAC512
        String jwtToken = JWT.create()
                            .withSubject("jangToken")
                            .withExpiresAt(new Date(System.currentTimeMillis()+(1000*60*10) ))
                            .withClaim("id",principalDetails.getUser().getId())
                            .withClaim("username",principalDetails.getUser().getUsername())
                            .sign(Algorithm.HMAC512("jang"));

        response.addHeader("Authorization", "Bearer "+jwtToken);
    }
}
