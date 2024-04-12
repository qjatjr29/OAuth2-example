package beomsic.springsecurityauth.user.controller.dto;

import java.time.LocalDateTime;

public record UserDetailResponse(Long id, String email, String name, LocalDateTime createdAt) {
}