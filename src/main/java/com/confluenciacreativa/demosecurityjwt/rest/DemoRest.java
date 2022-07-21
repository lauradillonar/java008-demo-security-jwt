package com.confluenciacreativa.demosecurityjwt.rest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("")
public class DemoRest {

    private static final Logger logger = LoggerFactory.getLogger(DemoRest.class);

    @GetMapping("/mensaje")
    public ResponseEntity<?> getMensaje(){

        var auth = SecurityContextHolder.getContext().getAuthentication();

        logger.info("Datos del Usuario: {}", auth.getPrincipal());
        logger.info("Datos de los Permisos {}", auth.getAuthorities());
        logger.info("Está autenticado {}", auth.isAuthenticated());

        Map<String, String> mensaje = new HashMap<>();
        mensaje.put("contenido", "Hola Mundo");
        return ResponseEntity.ok(mensaje);
    }

    @GetMapping("/admin")
    public ResponseEntity<?> getMensajeAdmin(){

        var auth = SecurityContextHolder.getContext().getAuthentication();
        logger.info("Datos del Usuario: {}", auth.getPrincipal());
        logger.info("Datos de los Permisos {}", auth.getAuthorities());
        logger.info("Está autenticado {}", auth.isAuthenticated());

        Map<String, String> mensaje = new HashMap<>();
        mensaje.put("contenido", "Hola Admin");
        return ResponseEntity.ok(mensaje);
    }

    @GetMapping("/publico")
    public ResponseEntity<?> getMensajePublico(){

        var auth = SecurityContextHolder.getContext().getAuthentication();

        logger.info("Datos del Usuario: {}", auth.getPrincipal());
        logger.info("Datos de los Permisos: {}", auth.getAuthorities());
        logger.info("Está autenticado {}", auth.isAuthenticated());

        Map<String, String> mensaje = new HashMap<>();
        mensaje.put("contenido", "Hola mundo");
        return ResponseEntity.ok(mensaje);
    }
}
