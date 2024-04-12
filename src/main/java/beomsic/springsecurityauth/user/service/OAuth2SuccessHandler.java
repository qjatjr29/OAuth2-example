package beomsic.springsecurityauth.user.service;

import beomsic.springsecurityauth.user.domain.AuthToken;
import beomsic.springsecurityauth.user.domain.oauth.CustomOAuth2User;
import beomsic.springsecurityauth.user.domain.oauth.Provider;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class OAuth2SuccessHandler implements AuthenticationSuccessHandler {

    private final AuthService authService;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {

        Object principal = authentication.getPrincipal();
        CustomOAuth2User oauth = null;

        // todo:  코드 수정 필수
        if(principal instanceof OidcUser) {
            // google
            oauth = Provider.GOOGLE.convertToUser((OidcUser) principal);
        }
        else if(principal instanceof OAuth2User) {
            // kakao
            oauth = Provider.KAKAO.convertToUser((OAuth2User) principal);
        }

        AuthToken authToken = authService.login(oauth);

        SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken(authToken, null, null));

        // success url 지정
        request.getRequestDispatcher("/auth/login").forward(request, response);

    }

}
