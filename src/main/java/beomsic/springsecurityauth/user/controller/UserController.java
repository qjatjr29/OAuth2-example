package beomsic.springsecurityauth.user.controller;

import beomsic.springsecurityauth.common.annotation.LoginUser;
import beomsic.springsecurityauth.common.presentation.ApiResponse;
import beomsic.springsecurityauth.common.presentation.ApiResponseMessage;
import beomsic.springsecurityauth.user.controller.dto.UserDetailResponse;
import beomsic.springsecurityauth.user.service.UserService;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/users")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    @GetMapping("")
    public ApiResponse<UserDetailResponse> getMyInfo(@NonNull @LoginUser Long loginId) {
        UserDetailResponse response = userService.findById(loginId);
        return new ApiResponse<>(ApiResponseMessage.SUCCESS_REQUEST, response);
    }

    @GetMapping("/{userId}")
    public ApiResponse<UserDetailResponse> findById(@PathVariable("userId") Long userId) {
        UserDetailResponse response = userService.findById(userId);
        return new ApiResponse<>(ApiResponseMessage.SUCCESS_REQUEST, response);
    }

    @DeleteMapping("/{userId}")
    public ApiResponse<Void> delete(@PathVariable("userId") Long userId, @NonNull @LoginUser Long loginId) {
        userService.deleteById(userId, loginId);
        return new ApiResponse<>(ApiResponseMessage.SUCCESS_REQUEST);
    }

}
