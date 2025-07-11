package com.example.userServiceTask.clients;

import com.example.dto.user.CreateUserDto;
import com.example.dto.user.UserResponseDto;
import com.example.dto.user.UserUpdateDto;
import com.example.service.UserService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;

@Component
public class UserServiceClient implements UserService {

    private static final String CREATE_URL = "/create";
    private static final String UPDATE_URL = "/update";
    private static final String DELETE_BY_ID_URL = "/{id}";
    private static final String GET_BY_ID_URL = "/{id}";


    private final WebClient client;
    private final String userServiceUrl;

    public UserServiceClient(final WebClient client,
                             final @Value("${userService.url}") String userServiceUrl) {
        this.client = client;
        this.userServiceUrl = userServiceUrl;
    }

    @Override
    public UserResponseDto createUser(final CreateUserDto createUserDto) {
        return client.post()
                .uri(userServiceUrl + CREATE_URL)
                .bodyValue(createUserDto)
                .retrieve()
                .bodyToMono(UserResponseDto.class)
                .block();
    }

    @Override
    public UserResponseDto updateUser(final UserUpdateDto userUpdateDto) {
        return client.put()
                .uri(userServiceUrl + UPDATE_URL)
                .bodyValue(userUpdateDto)
                .retrieve()
                .bodyToMono(UserResponseDto.class)
                .block();
    }

    @Override
    public UserResponseDto findUserById(final Long id) {
        return client.get()
                .uri(userServiceUrl + GET_BY_ID_URL, id)
                .retrieve()
                .bodyToMono(UserResponseDto.class)
                .block();
    }

    @Override
    public UserResponseDto deleteUser(final Long id) {
        return client.delete()
                .uri(userServiceUrl + DELETE_BY_ID_URL, id)
                .retrieve()
                .bodyToMono(UserResponseDto.class)
                .block();
    }
}
