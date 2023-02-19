package ru.vasire.keycloak.controller;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping("/")
public class HomeController {

    @GetMapping
    public String home(Model model, @AuthenticationPrincipal OAuth2User user) {
        String name = user.getAttribute("name");
        String email = user.getAttribute("email");
        model.addAttribute("name", name);
        model.addAttribute("email", email);
        return "home";
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
}