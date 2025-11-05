package ru.job4j.auth.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.RestClient;

@Configuration
public class AuthApplicationConfiguration {

    @Bean
    public RestClient restClient() {
        return RestClient.builder()
                .build();
    }
}
