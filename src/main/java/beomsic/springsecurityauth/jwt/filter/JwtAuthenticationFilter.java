package beomsic.springsecurityauth.jwt.filter;

import beomsic.springsecurityauth.jwt.JwtTokenService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.apache.logging.log4j.util.Strings;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final String HEADER_AUTHORIZATION = "Authorization";
    private final JwtTokenService jwtTokenService;

    // todo : OCI를 지키도록 코드 수정 예정
    // 토큰이 필요하지 않은 API URL에 대해서 배열로 구성한다.
    private static final List<String> list = Arrays.asList(
            "/user/login",  // 로그인 페이지의 URL을 추가합니다.
            "/login",
            "auth/login",// 로그인 페이지의 URL을 추가합니다.
            "/reissue",
            "/css/**",
            "/js/**",
            "/images/**",
            "/favicon.ico"
    );

    @Override
    protected void doFilterInternal(HttpServletRequest request, @NonNull HttpServletResponse response,
                                    @NonNull FilterChain filterChain) throws ServletException, IOException {

        if(isSkipAuthentication(request)) {
            filterChain.doFilter(request, response);
            return;
        }

        String accessToken = extractToken(request);

        if(accessToken.isEmpty()) {
            filterChain.doFilter(request, response);
            return;
        }

        jwtTokenService.validateToken(accessToken);
        setAuthentication(accessToken);
        filterChain.doFilter(request, response);
    }

    private boolean isSkipAuthentication(HttpServletRequest request) {
        return list.contains(request.getRequestURI()) ||
                request.getMethod().equalsIgnoreCase("OPTIONS");
    }

    private void setAuthentication(String accessToken) {
        Authentication authentication = jwtTokenService.getAuthentication(accessToken);
        SecurityContextHolder.getContext().setAuthentication(authentication);
    }

    private String extractToken(HttpServletRequest request) {
        String token = request.getHeader(HEADER_AUTHORIZATION);
        if(StringUtils.hasText(token)) {
            return token;
        }
        return Strings.EMPTY;
    }
}
