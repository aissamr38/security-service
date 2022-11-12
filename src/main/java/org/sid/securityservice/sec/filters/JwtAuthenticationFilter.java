package org.sid.securityservice.sec.filters;

import ch.qos.logback.core.net.SyslogOutputStream;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.sid.securityservice.sec.JWTUtil;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;



public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private AuthenticationManager authenticationManager;

    public JwtAuthenticationFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
     }


    // redifinir la méthode attemptAuthentication quand l'user se tente de s'authentifier
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        System.out.println("attemptAuthentication");
        String username = request.getParameter("user");
        String password = request.getParameter("pwd");
        System.out.println(username);
        System.out.println(password);
        //stocker le username et password dans cet objet
        UsernamePasswordAuthenticationToken authenticationToken =
                new UsernamePasswordAuthenticationToken(username,password);
        //il va mantenant cheker si l'user et pswd coréspondent bien , si oui il va aussi charger les roles de l'user
        return authenticationManager.authenticate(authenticationToken);
    }


    // quand l'authentification à réussi
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        System.out.println("successfulAuthentication");
       // permet de retourner l'user authentifié
        User user = (User) authResult.getPrincipal();

        // utiliser un algorithme pour la signature

        Algorithm algorithm = Algorithm.HMAC256(JWTUtil.SECRET);
        // on va créer les composante de JWT
        String jwtAccessToken = JWT.create()
                .withSubject(user.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis() + JWTUtil.EXPIRE_ACCESS_TOKEN))
                .withIssuer(request.getRequestURL().toString())
                .withClaim("roles", user.getAuthorities().stream().map(ga->ga.getAuthority()).collect(Collectors.toList()))
                .sign(algorithm);


        // on a pas besoin de récuperer les roles etc ...
        String jwtRefreshToken = JWT.create()
                .withSubject(user.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis() + JWTUtil.EXPIRE_REFRESH_TOKEN))
                .withIssuer(request.getRequestURL().toString())
                .sign(algorithm);

        Map<String,String> idToken = new HashMap<>();
        idToken.put("access-toke", jwtAccessToken);
        idToken.put("refresh-token", jwtRefreshToken);
        // on envoie le jwt dans le header
        response.setContentType("application/json");
        new ObjectMapper().writeValue(response.getOutputStream(), idToken);

    }
}
