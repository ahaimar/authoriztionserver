package io.getarrays.authoriztionserver.service;

import io.getarrays.authoriztionserver.model.entity.User;

public interface UserService {

    User getUserByEmail(String email);

    void resetLoginAttempts(String userUuid);

    void updateLoginAttempts(String email);

    void setListLogin(Long userId);

    void addLoginDevice(Long userid, String deviceName, String client, String idAddress);

    boolean verifyQrCode(String userUuid, String code);
}
