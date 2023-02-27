package ru.vasire.keycloak.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import ru.vasire.keycloak.model.Employee;

import static org.hibernate.query.sqm.tree.SqmNode.log;

@Controller
@RequestMapping("/")
@RequiredArgsConstructor
public class HomeController {

    private final WebClient.Builder employeeClient;

    @GetMapping("/admin")
    public String home(Model model, @AuthenticationPrincipal OAuth2User user) {
        String name = user.getAttribute("name");
        String email = user.getAttribute("email");
        model.addAttribute("name", name);
        model.addAttribute("email", email);
        return "admin";
    }

    @GetMapping("/info")
    public String info(Model model, @AuthenticationPrincipal OAuth2User user) {
        String login = user.getName();
        String name = user.getAttribute("given_name");
        String email = user.getAttribute("email");
        model.addAttribute("login", login);
        model.addAttribute("name", name);
        model.addAttribute("email", email);
        return "info";
    }

    @GetMapping("/")
    public String getAuthentication(
            Model model, @RegisteredOAuth2AuthorizedClient OAuth2AuthorizedClient authorizedClient)
    {
        Mono<Employee[]> response  = employeeClient.build().get().uri("http://localhost:8989/employee")
                .header("Authorization", "Bearer " + authorizedClient.getAccessToken().getTokenValue())
                .retrieve()
                .bodyToMono(Employee[].class)
                .doOnError(error -> log.errorf("An error has occurred {s}", error.getMessage()))
                .log();

        var epmList = response.block();
        model.addAttribute("employees", epmList);
        return "employee";
    }
}