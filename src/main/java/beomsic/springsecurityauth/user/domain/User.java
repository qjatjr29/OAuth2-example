package beomsic.springsecurityauth.user.domain;

import jakarta.persistence.CollectionTable;
import jakarta.persistence.ElementCollection;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.Table;
import java.io.Serializable;
import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.Set;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.SQLDelete;
import org.hibernate.annotations.SQLRestriction;

@Table(name = "users")
@Entity
@SQLRestriction("is_deleted = false")
@SQLDelete(sql = "UPDATE user SET is_deleted = true WHERE id = ?")
@Getter
@Builder
@AllArgsConstructor
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class User implements Serializable {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long userId;

    private String email;
    private String name;

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "authority", joinColumns = @JoinColumn(name = "user_id"))
    @Builder.Default
    private Set<Authority> authorities = new HashSet<>();

    @Builder.Default
    private LocalDateTime createdAt = LocalDateTime.now();

    @Builder.Default
    private Boolean isDeleted = Boolean.FALSE;

    public void addAuthority(Role role) {
        this.authorities.add(new Authority(role));
    }
}
