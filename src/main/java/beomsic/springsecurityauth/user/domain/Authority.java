package beomsic.springsecurityauth.user.domain;

import jakarta.persistence.Embeddable;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;

@Embeddable
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class Authority implements GrantedAuthority {

    @Enumerated(EnumType.STRING)
    private Role role;

    public Authority(Role role) {
        this.role = role;
    }

    @Override
    public String getAuthority() {
        return role.getRole();
    }
}
