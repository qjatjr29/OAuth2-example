package beomsic.springsecurityauth.user.domain.oauth;

import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.io.Serializable;
import java.time.LocalDateTime;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Table(name = "oauth2_user")
@Entity
@AllArgsConstructor
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Getter
@Builder
public class CustomOAuth2User implements Serializable {

    @Id
    private String oauth2UserId;

    private Long userId;

    private String name;
    private String email;

    @Enumerated(EnumType.STRING)
    private Provider provider;

    @Builder.Default
    private LocalDateTime createdAt = LocalDateTime.now();

    public void registerUserId(Long userId) {
        this.userId = userId;
    }
}
