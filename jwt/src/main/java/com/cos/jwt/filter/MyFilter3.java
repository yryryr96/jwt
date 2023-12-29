package com.cos.jwt.filter;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.io.PrintWriter;

public class MyFilter3 implements Filter {

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {

        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse res = (HttpServletResponse) response;
        System.out.println("필터3");

        // 토큰 'cos'를 만들어줘야 한다. id,pw가 정상적으로 들어와서 로그인이 완료되면 토큰을 만들고 반환
        // 요청할 때 마다 Authorization header에 토큰 값을 value로 담아서 요청
        // 넘어온 토큰이 서버에서 만든 토큰이 맞는지만 검증하면 된다. (RSA, HS256)
        if (req.getMethod().equals("POST")) {
            System.out.println("POST요청");
            String headerAuth = req.getHeader("Authorization");
            System.out.println(headerAuth);

            if (headerAuth.equals("cos")) {
                chain.doFilter(req, res); // 다음 필터 진행
            } else {
                PrintWriter out = res.getWriter();
                out.println("인증안됨");
            }
        }

    }
}
