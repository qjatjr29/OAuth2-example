package beomsic.springsecurityauth.user.service;

import beomsic.springsecurityauth.user.controller.dto.UserDetailResponse;
import beomsic.springsecurityauth.user.domain.User;
import beomsic.springsecurityauth.user.domain.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;

    @Transactional(readOnly = true)
    public UserDetailResponse findById(Long userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException());

        return new UserDetailResponse(user.getUserId(), user.getEmail(), user.getName(), user.getCreatedAt());
    }

    public void deleteById(Long userId, Long loginId) {
        // todo : 권한 관련 exception 추가
        if(!loginId.equals(userId)) {
            throw new RuntimeException();
        }
        userRepository.deleteById(userId);
    }

}
