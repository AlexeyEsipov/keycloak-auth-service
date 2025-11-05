package ru.job4j.auth.service;

import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;

@FeignClient(name = "resource", url = "http://localhost:8100")
public interface FeignServiceClient {

    @PostMapping("admin/add")
    ResponseEntity<Long> addUser(@RequestHeader(name = "Authorization") String token);

    @DeleteMapping("/admin/remove/{userId}")
    ResponseEntity<HttpStatus> deleteUser(@RequestHeader(name = "Authorization") String token, String userId);

}
