package beomsic.springsecurityauth.common.annotation;

import beomsic.springsecurityauth.jwt.JwtTokenService;
import lombok.RequiredArgsConstructor;
import org.springframework.core.MethodParameter;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.support.WebDataBinderFactory;
import org.springframework.web.context.request.NativeWebRequest;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.method.support.ModelAndViewContainer;

@Component
@RequiredArgsConstructor
public class LoginUserArgumentResolver implements HandlerMethodArgumentResolver {

    private static final String AUTHORIZATION_HEADER = "Authorization";
    private final JwtTokenService jwtTokenService;

       @Override
    public Long resolveArgument(MethodParameter parameter, ModelAndViewContainer mavContainer,
                                NativeWebRequest webRequest, WebDataBinderFactory binderFactory) throws Exception {
        String token = getTokenFromRequest(webRequest);
        return jwtTokenService.extractId(token);
    }

    @Override
    public boolean supportsParameter(MethodParameter parameter) {
        return parameter.hasParameterAnnotation(LoginUser.class);
    }

    private String getTokenFromRequest(NativeWebRequest webRequest) {
        String token = webRequest.getHeader(AUTHORIZATION_HEADER);

        // todo: custom exception
        if (token == null || token.isEmpty()) {
            throw new RuntimeException();
        }
        return token;
    }
}
