package org.sid.securityservice.sec.web;


import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.Data;
import org.sid.securityservice.sec.JWTUtil;
import org.sid.securityservice.sec.entities.AppRole;
import org.sid.securityservice.sec.entities.AppUser;
import org.sid.securityservice.sec.service.AccountService;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.security.Principal;
import java.util.*;
import java.util.stream.Collectors;

@RestController
public class AccountRestController {

    private AccountService accountService;

    public AccountRestController(AccountService accountService) {
        this.accountService = accountService;
    }

    @GetMapping(path = "/users")
    @PostAuthorize("hasAuthority('USER')")
    public List<AppUser> appUsers(){

        return accountService.listUsers();

    }

    @PostMapping(path = "/users")
    @PostAuthorize("hasAuthority('ADMIN')")
    public AppUser saveUser(@RequestBody AppUser appUser){
        return  accountService.addNewUser(appUser);

    }

    @PostMapping(path = "/roles")
    @PostAuthorize("hasAuthority('ADMIN')")
    public AppRole saveRole(@RequestBody AppRole appRole){
        return accountService.addNewRole(appRole);

    }

    @PostMapping(path = "/addRoleToUser")
    @PostAuthorize("hasAuthority('ADMIN')")
    public void  addRoleToUser(@RequestBody RoleUserForm roleUserForm){
        accountService.addRoleToUser(roleUserForm.getUsername(), roleUserForm.getRoleName());

    }

    @GetMapping(path = "/refreshToken")
    public void refreshToken(HttpServletRequest request, HttpServletResponse response) throws  Exception{
        String authToken  = request.getHeader(JWTUtil.AUTH_HEADER);
        if(authToken !=null && authToken.startsWith("Bearer")){
            try {
                // On va enlever le mot Bearer de jwt (le refresh token reçu), donc les 7 premier caractère
                String  jwt = authToken.substring(JWTUtil.PREFIX.length());
                // utilisation de la même clé secrete pour vérifier
                Algorithm  algorithm = Algorithm.HMAC256(JWTUtil.SECRET);
                JWTVerifier jwtVerifier = JWT.require(algorithm).build();
                // le decodedJWT va contenir les claims
                DecodedJWT decodedJWT = jwtVerifier.verify(jwt);
                // Recupérer l'username et les roles pas besoin de mot de passe, car on a  le jwt
                String username = decodedJWT.getSubject();
                // on charge l'user a nouveau au cas où il s subi des modification
                AppUser appUser = accountService.loadUserByUsername(username);
                // on va créer les composante de JWT
               // On va regénere un nouveau accèss token
                String jwtAccessToken = JWT.create()
                        .withSubject(appUser.getUsername())
                        .withExpiresAt(new Date(System.currentTimeMillis() + JWTUtil.EXPIRE_ACCESS_TOKEN))
                        .withIssuer(request.getRequestURL().toString())
                        .withClaim("roles", appUser.getAppRoles().stream().map(r->r.getRoleName()).collect(Collectors.toList()))
                        .sign(algorithm);

                Map<String,String> idToken = new HashMap<>();
                idToken.put("access-toke", jwtAccessToken);
                idToken.put("refresh-token", jwt);
                // on envoie le jwt dans le header
                response.setContentType("application/json");
                new ObjectMapper().writeValue(response.getOutputStream(), idToken);

            }
            catch (Exception e){
               throw e;
            }

        }
        else{
            throw  new RuntimeException("Refresh token required !!!");
        }

    }


    // Consulter le profil du l'user  connécter par exemple

    @GetMapping(path = "/profile")
    public  AppUser profile(Principal  principal){
        return  accountService.loadUserByUsername(principal.getName());

    }
}


@Data
class RoleUserForm{

    private String username;
    private String roleName;
}
