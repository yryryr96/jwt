package com.cos.jwt.config.jwt;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

// 스프링 시큐리티 필터에 UsernamePasswordAuthenticationFilter 가 있음
// default로 /login 요청해서 username, password 전송하면 (post) 
// UsernamePasswordAuthenticationFilter 동작

// ====흐름====
// 1. /login 요청
// 2. 시큐리티의 UsernamePasswordAuthenticationFilter에서
// 3. attemptAuthentication 메서드 실행
// 4. attemptAuthentication 메서드에서 AuthenticationManager 를 사용해 로그인 시도
// 5. PrincipalDetailsService 실행 -> loadUserByUsername 메서드 실행

@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;

    // /login 요청 시 로그인 시도를 위해 실행되는 함수
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        System.out.println("로그인 시도중 attemptAuthentication()");

        // 1. username, password 받아서

        // 2. 로그인 시도. authenticationManager 를 사용해 로그인을 시도하면
        // PrincipalDetailsService 호출 -> loadUserByUsername() 실행

        // 3. PrincipalDetails를 세션에 담고 (권한 관리를 위해서)

        // 4. JWT토큰을 생성하여 응답
        return super.attemptAuthentication(request, response);
    }
}
