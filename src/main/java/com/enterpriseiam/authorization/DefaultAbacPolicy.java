package com.enterpriseiam.authorization;

import com.enterpriseiam.security.identity.IamPrincipal;
import java.time.LocalTime;
import java.time.ZoneId;
import java.util.List;
import org.springframework.security.web.util.matcher.IpAddressMatcher;
import org.springframework.stereotype.Component;

@Component
public class DefaultAbacPolicy implements AbacPolicy {
    private final AbacProperties properties;
    private final List<IpAddressMatcher> networks;
    private final ZoneId zone;

    public DefaultAbacPolicy(AbacProperties properties) {
        this.properties = properties;
        this.zone = ZoneId.of(properties.zoneId());
        networks = properties.allowedCidrs().stream().map(IpAddressMatcher::new).toList();
    }

    @Override
    public boolean permits(IamPrincipal subject, ResourceAttributes resource,
            EnvironmentAttributes environment, ResourceAction action) {
        if (subject == null || resource == null || environment == null || action == null
                || subject.clearanceLevel() < 0 || resource.classification() < 0
                || resource.classification() > 4 || subject.clearanceLevel() > 4
                || subject.clearanceLevel() < resource.classification()
                || !subject.permissions().contains(action.requiredPermission())) {
            return false;
        }
        boolean owner = subject.userId().equals(resource.ownerId());
        boolean department = subject.department().equals(resource.department());
        boolean relationship = action == ResourceAction.READ ? owner || department : owner && department;
        if (!relationship || environment.time() == null
                || !NumericIpAddress.isLiteral(environment.remoteAddress())) {
            return false;
        }
        var time = environment.time().withZoneSameInstant(zone);
        LocalTime localTime = time.toLocalTime();
        return properties.allowedDays().contains(time.getDayOfWeek())
                && !localTime.isBefore(properties.openingTime())
                && localTime.isBefore(properties.closingTime())
                && networks.stream().anyMatch(network -> network.matches(environment.remoteAddress()));
    }
}
