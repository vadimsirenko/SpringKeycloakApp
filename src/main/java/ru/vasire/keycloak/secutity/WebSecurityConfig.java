package ru.vasire.keycloak.secutity;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority;
import org.springframework.security.oauth2.core.user.OAuth2UserAuthority;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.session.RegisterSessionAuthenticationStrategy;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;

import java.util.Collection;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class WebSecurityConfig {

    private final KeycloakLogoutHandler keycloakLogoutHandler;
    private final JwtAuthConverter jwtAuthConverter;

    public static final String ADMIN = "admin";
    public static final String USER = "user";

    public static final String BOOK_REGISTER = "book_register";
    public static final String BOOK_READER = "book_reader";


    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http
             /* ServerLogoutSuccessHandler handler */) throws Exception {
        http.authorizeHttpRequests()
                .requestMatchers(HttpMethod.GET, "/api/test/anonymous", "/api/test/anonymous/**").permitAll()
                .requestMatchers(HttpMethod.GET, "/api/test/admin", "/api/test/admin/**").hasRole(BOOK_REGISTER)
                .requestMatchers(HttpMethod.GET, "/api/test/user").hasAnyRole(BOOK_REGISTER, BOOK_READER)
                .requestMatchers(HttpMethod.GET, "/info", "/").hasAnyRole(ADMIN, USER)
                .requestMatchers(HttpMethod.GET, "/admin").hasAnyRole(ADMIN)
                .requestMatchers(HttpMethod.GET, "/employee").hasAnyRole(BOOK_REGISTER)
                .requestMatchers(HttpMethod.GET, "/employee/*").hasAnyRole(BOOK_REGISTER, BOOK_READER)
                .requestMatchers(HttpMethod.GET, "/**").hasAnyRole(USER, ADMIN)
                .anyRequest().authenticated()
                .and()
                .oauth2Login()
                .and()
                .logout()
                .addLogoutHandler(keycloakLogoutHandler)
                .logoutSuccessUrl("/");
        http
                .oauth2ResourceServer()
                .jwt()
                .jwtAuthenticationConverter(jwtAuthConverter);
        return http.build();

    }


    /**
     * Объект сопоставления, реализующий инерфейс {@link  GrantedAuthoritiesMapper},
     * который внедряется в уровень аутентификации для преобразования полномочий,
     * сформированных в разделе описания разрешений для области (realm_access) сервиса Keycloak,
     * в те, которые будут использоваться в объекте аутентификации.
     * @return Возвращает список разрешений {@link  GrantedAuthority} из раздела описания разрешений для области (realm_access) сервиса Keycloak
     * @see GrantedAuthority
     */
    @Bean
    @SuppressWarnings("unchecked")
    public GrantedAuthoritiesMapper userAuthoritiesMapperForKeycloak() {
        return authorities -> {
            Set<GrantedAuthority> mappedAuthorities = new HashSet<>();
            var authority = authorities.iterator().next();
            boolean isOidc = authority instanceof OidcUserAuthority;

            if (isOidc) {
                var oidcUserAuthority = (OidcUserAuthority) authority;
                var userInfo = oidcUserAuthority.getUserInfo();

                if (userInfo.hasClaim("realm_access")) {
                    var realmAccess = userInfo.getClaimAsMap("realm_access");
                    var roles = (Collection<String>) realmAccess.get("roles");
                    mappedAuthorities.addAll(generateAuthoritiesFromClaim(roles));
                }
            } else {
                var oauth2UserAuthority = (OAuth2UserAuthority) authority;
                Map<String, Object> userAttributes = oauth2UserAuthority.getAttributes();

                if (userAttributes.containsKey("realm_access")) {
                    var realmAccess =  (Map<String,Object>) userAttributes.get("realm_access");
                    var roles =  (Collection<String>) realmAccess.get("roles");
                    mappedAuthorities.addAll(generateAuthoritiesFromClaim(roles));
                }
            }

            return mappedAuthorities;
        };
    }

    /**
     * Формирование списка разрешений из списка ролей
     * @param roles Список ролей
     * @return Возвращает список разрешений {@link  GrantedAuthority}
     * @see GrantedAuthority
     */
    private Collection<GrantedAuthority> generateAuthoritiesFromClaim(Collection<String> roles) {
        return roles.stream()
                .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
                .collect(Collectors.toList());
    }

    @Bean
    protected SessionAuthenticationStrategy sessionAuthenticationStrategy() {
        return new RegisterSessionAuthenticationStrategy(new SessionRegistryImpl());
    }

    @Bean
    public AuthenticationManager authenticationManager(HttpSecurity http) throws Exception {
        return http.getSharedObject(AuthenticationManagerBuilder.class)
                .build();
    }

}