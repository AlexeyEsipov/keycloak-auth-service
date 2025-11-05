package ru.job4j.auth.service;

import jakarta.annotation.PostConstruct;
import jakarta.ws.rs.core.Response;
import lombok.extern.slf4j.Slf4j;
import org.keycloak.OAuth2Constants;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.admin.client.resource.UsersResource;
import org.keycloak.representations.idm.AbstractUserRepresentation;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import ru.job4j.auth.model.CreateUserRequest;
import ru.job4j.auth.model.LoginPassword;
import ru.job4j.auth.model.UserResponse;

import java.util.*;

@Service
@Slf4j
public class UserService {
    @Value("${keycloak.realm}")
    private String realm;

    @Value("${keycloak.auth-server-url}")
    private String serverURL;

    @Value("${keycloak.service.client}")
    private String serviceClientID;

    @Value("${keycloak.credentials.secret}")
    private String serviceClientSecret;

    private static Keycloak keycloak;

    private static UsersResource usersResource;

    private static RealmResource realmResource;

    private final AuthUserService authUserService;

    private final FeignServiceClient feignServiceClient;




    public UserService(AuthUserService authUserService, FeignServiceClient feignServiceClient) {
        this.authUserService = authUserService;
        this.feignServiceClient = feignServiceClient;
    }


    @PostConstruct
    public Keycloak initKeycloak() {
        if (keycloak == null) {
            keycloak = KeycloakBuilder.builder()
                    .realm(realm)
                    .serverUrl(serverURL)
                    .clientId(serviceClientID)
                    .clientSecret(serviceClientSecret)
                    .grantType(OAuth2Constants.CLIENT_CREDENTIALS)
                    .build();
            realmResource = keycloak.realm(realm);
            usersResource = realmResource.users();
        }
        return keycloak;
    }

    public String registrationUser(CreateUserRequest user) {
        String userId = createUserInit(user);
        if (Objects.isNull(userId)) {
            return null;
        }
        UserResponse userResponse = authUserService.authUserWithoutSession(user.login(), user.password());
        String accessToken = userResponse.accessToken();
        Long appUserId = receiveUserIdFromRecoursesService(accessToken);
        removeRoles(userId, "init");
        addRoles(userId, "user");
        changeAttribute(userId, appUserId);
        return userId;
    }

    public UserResponse authUser(LoginPassword user) {
        return authUserService.authUser(user.login(), user.password());
    }

    public void deleteUser(String appUserId, String accessToken) {
        Optional<String> user = usersResource.searchByAttributes("app-user-id:" + appUserId)
                .stream()
                .findFirst()
                .map(AbstractUserRepresentation::getId);
        if (user.isPresent()) {
            String userUUID = user.get();
            deleteUserByUserAppIdInResoursesService(appUserId, accessToken);
            usersResource.get(userUUID).logout();
            usersResource.get(userUUID).remove();
        }
    }

    private String createUserInit(CreateUserRequest user) {
        String login = user.login();
        String userId = null;
        // проверяем, что пользователь с таким username не зарегистрирован в Keycloak:
        boolean notExist = usersResource.searchByAttributes("username:" + login)
                .stream()
                .noneMatch(el -> login.equals(el.getUsername()));
        //если регистрация не найдена, то создаем объект UserRepresentation и наполняем его данными
        if (notExist) {
            String password = user.password();
            UserRepresentation kcUser = new UserRepresentation();
            kcUser.setCredentials(Collections.singletonList(createPasswordCredentials(password)));
            kcUser.setUsername(login);
            kcUser.setEmail(user.email());
            kcUser.setFirstName(user.firstName());
            kcUser.setLastName(user.lastName());
            kcUser.setEnabled(true);
            kcUser.setEmailVerified(true);
            //создание пользователя в Keycloak происходит в этой строке:
            try (Response response = usersResource.create(kcUser)) {
                // далее мы извлекаем заголовок Location из ответа и получаем идентификационный
                // номер пользователя, так называемый subject:
                userId = ((String) response.getMetadata().get("Location").get(0)).split("users/")[1];
                addRoles(userId,"init");
            } catch (Exception e) {
                log.info("Пользователь не создан: {}", login);
            }
        }
        log.info("Пользователь создан: {} - {}", userId, login);
        return userId;
    }

    private void addRoles(String userId, String role) {
        if (Objects.isNull(userId) || Objects.isNull(role)) {
            return;
        }
        // создаем список, в котором будем хранить роли
        List<RoleRepresentation> kcRoles = new ArrayList<>();
        // Из RealmResource извлекаем RolesResource и далее извлекаем список RoleRepresentation
        realmResource.roles().list()
                .stream()
                // ищем нужную нам роль
                .filter(el -> role.equals(el.getName()))
                .findFirst()
                .ifPresentOrElse(
                        // если роль найдена, то
                        el -> {
                            // добавляем роль в список ролей
                            kcRoles.add(el);
                            // из UsersResource извлекаем нужного нап пользователя
                            usersResource.get(userId)
                                    // получаем все его роли
                                    .roles()
                                    // нам нужны роли уровня realm
                                    .realmLevel()
                                    // добавляем список ролей
                                    .add(kcRoles);
                        },
                        // если роль не найдена, то ничего не выполняем
                        () -> {}
                );
    }

    private void removeRoles(String userId, String role) {
        if (Objects.isNull(userId) || Objects.isNull(role)) {
            return;
        }
        List<RoleRepresentation> kcRoles = new ArrayList<>();
        realmResource.roles().list()
                .stream()
                .filter(el -> role.equals(el.getName()))
                .findFirst()
                .ifPresentOrElse(
                        el -> {
                            kcRoles.add(el);
                            usersResource.get(userId).roles().realmLevel().remove(kcRoles);
                        },
                        () -> {}
                );
    }

    private CredentialRepresentation createPasswordCredentials(String password) {
        CredentialRepresentation passwordCredentials = new CredentialRepresentation();
        passwordCredentials.setTemporary(false);
        passwordCredentials.setType(CredentialRepresentation.PASSWORD);
        passwordCredentials.setValue(password);
        return passwordCredentials;
    }

    private Long receiveUserIdFromRecoursesService(String accessToken) {
        String header = "Bearer " + accessToken;
        ResponseEntity<Long> response = feignServiceClient.addUser(header);
        return response.getBody();
    }

    private void deleteUserByUserAppIdInResoursesService(String appUserId, String accessToken) {
        String header = "Bearer " + accessToken;
        feignServiceClient.deleteUser(header, appUserId);
    }

    public void logout(String userUUID) {
        usersResource.get(userUUID).logout();
    }

    private void changeAttribute(String userUUID, Long appUserId) {
        UserRepresentation userRepresentation = usersResource.get(userUUID).toRepresentation();
        Map<String, List<String>> attributes = userRepresentation.getAttributes();
        if (Objects.isNull(attributes)) {
            attributes = new HashMap<>();
        }
        attributes.put("app-user-id", List.of(String.valueOf(appUserId)));
        userRepresentation.setAttributes(attributes);
        usersResource.get(userUUID).update(userRepresentation);
    }

    public UserResponse  refresh(String userRefreshToken) {
        return authUserService.refresh(userRefreshToken);
    }
}
