package com.br.keycloak.controller;

import lombok.extern.log4j.Log4j2;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Log4j2
@RestController
@RequestMapping(value = "/security")
public class SecurityResource {

    /**
     * endpoint sem nenhuma validação de role
     */
    @GetMapping
    public ResponseEntity<Void> isAuthenticated() {
        log.warn("GET SecurityResource isAuthenticated: Usuario autenticado.");
        return ResponseEntity.ok().build();
    }

    /**
     * endpoint onde o usuario tem que ter a role user
     */
    @GetMapping(value = "/has-role")
    @PreAuthorize("hasAnyAuthority('ROLE_USER')")//Validar se no token o cliente da requisição possui permissões para acessar aquele método.
    public ResponseEntity<Void> isUser() {
        log.warn("GET SecurityResource isUser: isUser autenticado.");
        return ResponseEntity.ok().build();
    }

    /**
     * endpoint onde o usuario tem que ter a role admin
     */
    @GetMapping(value = "/is-admin")
    @PreAuthorize("hasAnyAuthority('ROLE_ADMIN')")//Validar se no token o cliente da requisição possui permissões para acessar aquele método
    public ResponseEntity<Void> isAdmin() {
        log.warn("GET SecurityResource isAdmin: isAdmin autenticado.");
        return ResponseEntity.ok().build();
    }

}