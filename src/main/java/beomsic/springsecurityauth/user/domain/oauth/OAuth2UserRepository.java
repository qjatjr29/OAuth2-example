package beomsic.springsecurityauth.user.domain.oauth;

import org.springframework.data.jpa.repository.JpaRepository;

public interface OAuth2UserRepository extends JpaRepository<CustomOAuth2User, String> {
}
