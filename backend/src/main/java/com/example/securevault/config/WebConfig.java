package com.example.securevault.config;

import com.example.securevault.auth.AuthInterceptor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class WebConfig implements WebMvcConfigurer {

    private final AuthInterceptor authInterceptor;

    @Value("${app.cors.allowed-origin}")
    private String allowedOrigin;

    public WebConfig(AuthInterceptor authInterceptor) {
        this.authInterceptor = authInterceptor;
    }

    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/api/**")
                .allowedOrigins(allowedOrigin)
                .allowedMethods("GET", "POST", "DELETE", "OPTIONS")
                .allowedHeaders("*");
    }

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        // Only the vault endpoints require a session; /api/auth/** stays open.
        registry.addInterceptor(authInterceptor)
                .addPathPatterns("/api/files/**", "/api/search/**");
    }
}
