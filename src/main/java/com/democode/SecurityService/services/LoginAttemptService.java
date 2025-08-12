package com.democode.SecurityService.services;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.util.concurrent.TimeUnit;

@Service
public class LoginAttemptService {

    private static final int MAX_ATTEMPTS = 5;
    private static final long BLOCK_TIME = 15; // minutes

    @Autowired
    private StringRedisTemplate redisTemplate;

    public void loginFailed(String key) {
        String redisKey = "login:attempts:" + key;
        Long attempts = redisTemplate.opsForValue().increment(redisKey);
        if (attempts != null && attempts == 1) {
            redisTemplate.expire(redisKey, BLOCK_TIME, TimeUnit.MINUTES);
        }
    }

    public boolean isBlocked(String key) {
        String redisKey = "login:attempts:" + key;
        String val = redisTemplate.opsForValue().get(redisKey);
        return val != null && Integer.parseInt(val) >= MAX_ATTEMPTS;
    }

    public void loginSucceeded(String key) {
        String redisKey = "login:attempts:" + key;
        redisTemplate.delete(redisKey);
    }
}