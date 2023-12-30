package com.cos.jwt.config;

import com.cos.jwt.config.auth.PrincipalDetailsService;
import com.cos.jwt.config.jwt.JwtAuthorizationFilter;
import com.cos.jwt.filter.MyFilter3;
import com.cos.jwt.config.jwt.JwtAuthenticationFilter;
import com.cos.jwt.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.filter.CorsFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final CorsFilter corsFilter;
    private final PrincipalDetailsService principalDetailsService;
    private final UserRepository userRepository;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        // 따로 빈으로 등록한 필터는 시큐리티 필터보다 늦게 실행된다. -> 시큐리티 필터가 먼저 실행된다.
        // 시큐리티 필터에도 순서가 있는데 특정 필터 전에 실행하기 위해서는 addFilterBefore, 후에 실행되기 위해서는 addFilterAfter 사용
//        http.addFilterBefore(new MyFilter3(), SecurityContextHolderFilter.class);
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

            AuthenticationManagerBuilder sharedObject = http.getSharedObject(AuthenticationManagerBuilder.class);
            sharedObject.userDetailsService(principalDetailsService);
            AuthenticationManager authenticationManager = sharedObject.build();

            // 만들어준 authenticationManager  시큐리티에 등록
            http.authenticationManager(authenticationManager);
            http
                    .addFilter(corsFilter)
                    .addFilter(new JwtAuthenticationFilter(authenticationManager))
                    .addFilter(new JwtAuthorizationFilter(authenticationManager, userRepository));
        }
    }
}
