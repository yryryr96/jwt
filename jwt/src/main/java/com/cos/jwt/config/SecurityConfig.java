package com.cos.jwt.config;

import com.cos.jwt.filter.MyFilter3;
import com.cos.jwt.config.jwt.JwtAuthenticationFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.context.SecurityContextHolderFilter;
import org.springframework.web.filter.CorsFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final CorsFilter corsFilter;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        // 따로 빈으로 등록한 필터는 시큐리티 필터보다 늦게 실행된다. -> 시큐리티 필터가 먼저 실행된다.
        // 시큐리티 필터에도 순서가 있는데 특정 필터 전에 실행하기 위해서는 addFilterBefore, 후에 실행되기 위해서는 addFilterAfter 사용
        http.addFilterBefore(new MyFilter3(), SecurityContextHolderFilter.class);
        http.csrf(CsrfConfigurer::disable);
        http.sessionManagement((sessionManagement) ->
                sessionManagement.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
        http.authorizeHttpRequests((authorize) ->
                        authorize
                                .requestMatchers("/api/v1/user/**").hasAnyRole("USER", "ADMIN", "MANAGER")
                                .requestMatchers("/api/v1/manager/**").hasAnyRole("MANAGER", "ADMIN")
                                .requestMatchers("/api/v1/admin/**").hasAnyRole( "ADMIN")
                                .anyRequest().permitAll()
                )
                .formLogin((formLogin) ->
                        formLogin.disable() // 폼 태그를 이용한 로그인을 하지 않겠다.
                )
                .httpBasic((httpBasic) ->
                    httpBasic.disable() // 헤더에 ID, PW 를 담아서 보내는 방식(httpBasic)을 사용하지 않겠다.
                )
        ;
        new MyCustomDsl().configure(http);

        return http.build();
    }

    public class MyCustomDsl extends AbstractHttpConfigurer<MyCustomDsl, HttpSecurity> {

        @Override
        public void configure(HttpSecurity http) throws Exception {

            AuthenticationManager authenticationManager = http.getSharedObject(AuthenticationManager.class);
            http
                    .addFilter(corsFilter)
                    .addFilter(new JwtAuthenticationFilter(authenticationManager));
//                    .addFilter(new JwtAuthenticationFilter());
        }
    }
}
