package beomsic.springsecurityauth.user.service;

import beomsic.springsecurityauth.jwt.JwtTokenService;
import beomsic.springsecurityauth.user.domain.AuthToken;
import beomsic.springsecurityauth.user.domain.Role;
import beomsic.springsecurityauth.user.domain.User;
import beomsic.springsecurityauth.user.domain.UserRepository;
import beomsic.springsecurityauth.user.domain.oauth.CustomOAuth2User;
import beomsic.springsecurityauth.user.domain.oauth.OAuth2UserRepository;
import java.util.Date;
import java.util.concurrent.TimeUnit;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional
@RequiredArgsConstructor
public class AuthService {

    private static final String REFRESH_TOKEN_PREFIX = "REFRESH_TOKEN-";

    private final UserRepository userRepository;
    private final OAuth2UserRepository oAuth2UserRepository;
    private final JwtTokenService jwtTokenService;
    private final RedisTemplate<String, Object> redisTemplate;

    public AuthToken login(CustomOAuth2User oAuth2User) {
        CustomOAuth2User oAuthUser = findOrCreateUser(oAuth2User);
        return generateToken(oAuthUser.getUserId());
    }

    public AuthToken reissue(String refreshToken) {

        jwtTokenService.validateToken(refreshToken);
        Long userId = jwtTokenService.extractId(refreshToken);

        String refreshInRedis = (String) redisTemplate.opsForValue().get(REFRESH_TOKEN_PREFIX + userId);

        // 로그아웃 되었는지 확인(이미 유효시간이 지나 삭제됨)
        if (refreshInRedis == null) {
            throw new RuntimeException();
            // todo
            // throw new UnAuthorizedException(ErrorCode.EXPIRED_VERIFICATION_TOKEN);
        }

        // 입력받은 토큰과 레디스의 토큰 값이 같은지 확인
        if (!refreshInRedis.equals(refreshToken)) {
            throw new RuntimeException();
            // todo
            // throw new UnAuthorizedException(ErrorCode.INVALID_VERIFICATION_TOKEN);
        }

        // 레디스에 저장된 refresh token 삭제
        redisTemplate.delete(REFRESH_TOKEN_PREFIX + userId);

        // 토큰 새로 생성 후 저장.
        return generateToken(userId);
    }

    private CustomOAuth2User findOrCreateUser(CustomOAuth2User oAuth2User) {
        return oAuth2UserRepository.findById(oAuth2User.getOauth2UserId())
                .orElseGet(() -> {
                    Long userId = registerUser(oAuth2User);
                    return registerOAuthUser(oAuth2User, userId);
                });
    }

    private CustomOAuth2User registerOAuthUser(CustomOAuth2User oAuth2User, Long userId) {
        oAuth2User.registerUserId(userId);
        return oAuth2UserRepository.save(oAuth2User);
    }

    private Long registerUser(CustomOAuth2User oAuth2User) {
        User user = User.builder()
                .email(oAuth2User.getEmail())
                .name(oAuth2User.getName())
                .createdAt(oAuth2User.getCreatedAt())
                .build();
        user.addAuthority(Role.USER);
        userRepository.save(user);

        return user.getUserId();
    }

    private AuthToken generateToken(Long id) {

        String accessToken = jwtTokenService.generateAccessToken(id);
        String refreshToken = jwtTokenService.generateRefreshToken(id);

        saveRefreshTokenInRedis(id, refreshToken);
        return new AuthToken(accessToken, refreshToken);
    }

    private void saveRefreshTokenInRedis(Long userId, String refreshToken) {
        redisTemplate.opsForValue()
                .set(REFRESH_TOKEN_PREFIX + userId,
                        refreshToken,
                        jwtTokenService.getTokenExpiredIn(refreshToken) - new Date().getTime(),
                        TimeUnit.MILLISECONDS);

    }
}
