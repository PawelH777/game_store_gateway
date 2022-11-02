package org.example.gateway;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.function.Predicate;

@Component
public class AuthGatewayFilterFactory extends AbstractGatewayFilterFactory<AuthGatewayFilterFactory.Config> {
    public AuthGatewayFilterFactory() {
        super(Config.class);
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();

            final List<String> apiEndpoints = List.of("/orders", "/orders/*");

            Predicate<ServerHttpRequest> isApiSecured = r -> apiEndpoints.stream()
                    .noneMatch(uri -> r.getURI().getPath().contains(uri));

            if (isApiSecured.test(request)) {
                if (!request.getHeaders().containsKey("Authorization")) {
                    return prepareErrorResponse(exchange, HttpStatus.UNAUTHORIZED);
                }

                final String authHeaderValue = request.getHeaders().getOrEmpty("Authorization").get(0);

                if(authHeaderValue == null || !authHeaderValue.startsWith("Bearer ")) {
                    return prepareErrorResponse(exchange, HttpStatus.BAD_REQUEST);
                }

                final String token = authHeaderValue.substring(7);

                Claims claims;
                try {
                    claims = Jwts.parser().setSigningKey("secret").parseClaimsJws(token).getBody();
                } catch (final Exception ex) {
                    return prepareErrorResponse(exchange, HttpStatus.BAD_REQUEST);
                }
                exchange.getRequest().mutate().header("id", String.valueOf(claims.get("id"))).build();
            }

            return chain.filter(exchange);
        };
    }

    private Mono<Void> prepareErrorResponse(ServerWebExchange exchange, HttpStatus errorStatus) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(errorStatus);

        return response.setComplete();
    }

    public static class Config {
    }

}
