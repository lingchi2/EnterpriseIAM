package com.enterpriseiam.authorization;

import java.time.Clock;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.Optional;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

@Component
public class EnvironmentAttributeResolver {
    private final Clock clock;
    private final ZoneId zone;

    public EnvironmentAttributeResolver(Clock clock, AbacProperties properties) {
        this.clock = clock;
        this.zone = ZoneId.of(properties.zoneId());
    }

    public Optional<EnvironmentAttributes> resolve() {
        if (!(RequestContextHolder.getRequestAttributes() instanceof ServletRequestAttributes attributes)) {
            return Optional.empty();
        }
        // Never use Forwarded/X-Forwarded-For. Configure server.forward-headers-strategy=none.
        String remoteAddress = attributes.getRequest().getRemoteAddr();
        if (!NumericIpAddress.isLiteral(remoteAddress)) {
            return Optional.empty();
        }
        return Optional.of(new EnvironmentAttributes(ZonedDateTime.now(clock).withZoneSameInstant(zone),
                remoteAddress));
    }
}
