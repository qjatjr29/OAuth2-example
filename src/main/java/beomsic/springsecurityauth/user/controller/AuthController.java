package beomsic.springsecurityauth.user.controller;

import beomsic.springsecurityauth.common.presentation.ApiResponse;
import beomsic.springsecurityauth.common.presentation.ApiResponseMessage;
import beomsic.springsecurityauth.user.domain.AuthToken;
import beomsic.springsecurityauth.user.service.AuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PreAuthorize("isAuthenticated()")
    @GetMapping("/login")
    public Object login(@AuthenticationPrincipal Object user) {
        return user;
    }

    @PostMapping("/reissue")
    public ApiResponse<AuthToken> reissueToken(@RequestHeader("RefreshToken") String refreshToken) {
        AuthToken authToken = authService.reissue(refreshToken);
        return new ApiResponse<>(ApiResponseMessage.SUCCESS_REQUEST, authToken);
    }
}
