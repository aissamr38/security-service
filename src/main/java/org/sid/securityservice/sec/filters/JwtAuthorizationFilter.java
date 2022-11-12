package org.sid.securityservice.sec.filters;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;
import org.sid.securityservice.sec.JWTUtil;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;

public class JwtAuthorizationFilter extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        if (request.getServletPath().equals("/")){
            filterChain.doFilter(request,response);
        }
        else {
            String authorizationToken = request.getHeader(JWTUtil.AUTH_HEADER);
            if(authorizationToken !=null && authorizationToken.startsWith(JWTUtil.PREFIX)){

                try {
                    // On va enlever le mot Bearer de jwt reçu, donc les 7 premier caractère
                    String  jwt = authorizationToken.substring(JWTUtil.PREFIX.length());
                    // utilisation de la même clé secrete pour vérifier
                    Algorithm  algorithm = Algorithm.HMAC256(JWTUtil.SECRET);
                    JWTVerifier jwtVerifier = JWT.require(algorithm).build();
                    // le decodedJWT va contenir les claims
                    DecodedJWT decodedJWT = jwtVerifier.verify(jwt);
                    // Recupérer l'username et les roles pas besoin de mot de passe, car on a  le jwt
                    String username = decodedJWT.getSubject();
                    String[] roles = decodedJWT.getClaim("roles").asArray(String.class);

                    Collection<GrantedAuthority>  authorities = new ArrayList<>();
                    for (String role :roles){
                        authorities.add(new SimpleGrantedAuthority(role));
                    }
                    // Maintenant on va authentifier l'user
                    UsernamePasswordAuthenticationToken authenticationToken =
                            new UsernamePasswordAuthenticationToken(username, null, authorities);
                    SecurityContextHolder.getContext().setAuthentication(authenticationToken);

                    // maintenant on va lui dire à springSécurity  de passer au filter suivant,
                    filterChain.doFilter(request,response);


                }
                catch (Exception e){
                    response.setHeader("error-message", e.getMessage());
                    response.sendError(HttpServletResponse.SC_FORBIDDEN);
                }

            }
            else {
                // le la condition e haut n'est pas satissfaite on va demande débrouille toi,
                // => si la requêt neccesite un authentification il va la rejeter sinon il va passer au filter suivant
                filterChain.doFilter(request, response);
            }
        }

    }
}
