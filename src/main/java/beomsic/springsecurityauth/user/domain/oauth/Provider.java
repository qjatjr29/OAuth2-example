package beomsic.springsecurityauth.user.domain.oauth;

import static java.lang.String.format;

import java.util.Map;
import org.springframework.security.oauth2.core.user.OAuth2User;

public enum Provider {
    GOOGLE {
        @Override
        public CustomOAuth2User convertToUser(OAuth2User oAuth2User) {
            return CustomOAuth2User.builder()
                    .oauth2UserId(format("%s_%s", name(), oAuth2User.getAttribute("sub")))
                    .provider(GOOGLE)
                    .email(oAuth2User.getAttribute("email"))
                    .name(oAuth2User.getAttribute("name"))
                    .build();
        }
    },
    NAVER {
        @Override
        public CustomOAuth2User convertToUser(OAuth2User oAuth2User) {

            Map<String, Object> resp = oAuth2User.getAttribute("response");

            return CustomOAuth2User.builder()
                    .oauth2UserId(format("%s_%s", name(), resp.get("id")))
                    .provider(NAVER)
                    .email("" + resp.get("email"))
                    .name("" + resp.get("name"))
                    .build();
        }
    },
    KAKAO {
        @Override
        public CustomOAuth2User convertToUser(OAuth2User oAuth2User) {
            Map<String, Object> account = oAuth2User.getAttribute("kakao_account");
            Map<String, Object> profile = (Map<String, Object>) account.get("profile");

            return CustomOAuth2User.builder()
                    .oauth2UserId(format("%s_%s", name(), oAuth2User.getAttribute("id")))
                    .provider(KAKAO)
                    .email("" + account.get("email"))
                    .name("" + profile.get("nickname"))
                    .build();
        }
    };


    public abstract CustomOAuth2User convertToUser(OAuth2User oAuth2User);
}
