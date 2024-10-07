package org.example.expert.aop;

import io.jsonwebtoken.Claims;
import jakarta.servlet.http.HttpServletRequest;
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.example.expert.config.JwtUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;

@Aspect
@Component
public class AdminLogAspect {

    private static final Logger logger = LoggerFactory.getLogger(AdminLogAspect.class.getName());
    private final HttpServletRequest request;
    private final JwtUtil jwtUtil;

    public AdminLogAspect(HttpServletRequest request, JwtUtil jwtUtil) {
        this.request = request;
        this.jwtUtil = jwtUtil;
    }

    @Before("execution(* org.example.expert.domain.comment.controller.CommentAdminController.deleteComment())")
    public void logDeleteComment(JoinPoint joinPoint) {
        logAdminAccess(joinPoint);
    }

    @Before("execution(* org.example.expert.domain.user.controller.UserAdminController.changeUserRole())")
    public void logChangeUserRole(JoinPoint joinPoint) {
        logAdminAccess(joinPoint);
    }

    private void logAdminAccess(JoinPoint joinPoint) {

        String authHeader = request.getHeader("Authorization");
        String bearerToken = jwtUtil.substringToken(authHeader);

        Claims claims = jwtUtil.extractClaims(bearerToken);

        String userId = claims.getSubject();
        String requestUrl = request.getRequestURI();
        LocalDateTime requestTime = LocalDateTime.now();

        logger.info("Log Admin Access User Id : " + userId +
                "Request Time : " + requestTime +
                "URL : " + requestUrl +
                "Method : " + joinPoint.getSignature().getName());
    }
}
