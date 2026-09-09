package com.enterpriseiam.authorization;

import java.time.DayOfWeek;
import java.time.LocalTime;
import java.time.ZoneId;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.security.web.util.matcher.IpAddressMatcher;
import org.springframework.validation.annotation.Validated;

/** Server-controlled policy. Empty networks intentionally deny every network. */
@Validated
@ConfigurationProperties("iam.abac")
public record AbacProperties(
        @DefaultValue("UTC") String zoneId,
        @DefaultValue({"MONDAY", "TUESDAY", "WEDNESDAY", "THURSDAY", "FRIDAY"})
        Set<DayOfWeek> allowedDays,
        @DefaultValue("09:00") LocalTime openingTime,
        @DefaultValue("17:00") LocalTime closingTime,
        @DefaultValue List<String> allowedCidrs) {

    public AbacProperties {
        ZoneId.of(Objects.requireNonNull(zoneId, "ABAC zone is required"));
        allowedDays = Set.copyOf(Objects.requireNonNull(allowedDays, "ABAC days are required"));
        Objects.requireNonNull(openingTime, "ABAC opening time is required");
        Objects.requireNonNull(closingTime, "ABAC closing time is required");
        if (!openingTime.isBefore(closingTime)) {
            throw new IllegalArgumentException("ABAC opening time must precede closing time on the same day");
        }
        allowedCidrs = List.copyOf(Objects.requireNonNull(allowedCidrs, "ABAC networks are required"));
        allowedCidrs.forEach(AbacProperties::validateCidr);
    }

    private static void validateCidr(String cidr) {
        String[] parts = cidr.split("/", -1);
        if (parts.length > 2 || !NumericIpAddress.isLiteral(parts[0])) {
            throw new IllegalArgumentException("ABAC networks must contain numeric IP literals");
        }
        if (parts.length == 2) {
            if (!parts[1].matches("[0-9]{1,3}")) {
                throw new IllegalArgumentException("Invalid ABAC network prefix");
            }
            int prefix = Integer.parseInt(parts[1]);
            int maxPrefix = parts[0].contains(":") ? 128 : 32;
            if (prefix > maxPrefix) {
                throw new IllegalArgumentException("ABAC network prefix exceeds address width");
            }
        }
        new IpAddressMatcher(cidr);
    }
}
