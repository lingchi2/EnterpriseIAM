package com.enterpriseiam.authorization;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

import com.enterpriseiam.security.identity.IamPrincipal;
import java.time.DayOfWeek;
import java.time.LocalTime;
import java.time.ZonedDateTime;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

class DefaultAbacPolicyTest {
    private static final UUID SUBJECT = UUID.randomUUID();
    private static final UUID OTHER = UUID.randomUUID();
    private static final DefaultAbacPolicy POLICY = new DefaultAbacPolicy(properties(
            List.of("10.0.0.0/8", "2001:db8:1::/48")));

    @ParameterizedTest
    @CsvSource({
            "READ, true, Engineering, 2, true",
            "READ, false, Engineering, 2, true",
            "READ, true, Finance, 2, true",
            "READ, false, Finance, 2, false",
            "READ, true, Engineering, 3, false",
            "WRITE, true, Engineering, 2, true",
            "WRITE, false, Engineering, 2, false",
            "WRITE, true, Finance, 2, false",
            "WRITE, true, Engineering, 3, false"
    })
    void requiresPermissionClearanceAndActionSpecificRelationship(ResourceAction action,
            boolean owner, String department, short classification, boolean expected) {
        var resource = new ResourceAttributes(UUID.randomUUID(), owner ? SUBJECT : OTHER,
                department, classification);
        assertThat(POLICY.permits(subject(Set.of(action.requiredPermission())), resource,
                environment("2026-10-23T12:00:00Z", "10.2.3.4"), action)).isEqualTo(expected);
    }

    @Test
    void adminRoleNeverBypassesPermissionOrClearance() {
        var resource = new ResourceAttributes(UUID.randomUUID(), SUBJECT, "Engineering", (short) 2);
        assertThat(POLICY.permits(subject(Set.of()), resource,
                environment("2026-10-23T12:00:00Z", "10.2.3.4"), ResourceAction.READ)).isFalse();
        assertThat(POLICY.permits(subject(Set.of("RESOURCE:READ")),
                new ResourceAttributes(resource.id(), SUBJECT, "Engineering", (short) 4),
                environment("2026-10-23T12:00:00Z", "10.2.3.4"), ResourceAction.READ)).isFalse();
    }

    @ParameterizedTest
    @CsvSource({
            "2026-10-23T08:59:59Z, 10.2.3.4, false",
            "2026-10-23T09:00:00Z, 10.2.3.4, true",
            "2026-10-23T16:59:59Z, 10.2.3.4, true",
            "2026-10-23T17:00:00Z, 10.2.3.4, false",
            "2026-10-24T12:00:00Z, 10.2.3.4, false",
            "2026-10-23T12:00:00Z, 11.2.3.4, false",
            "2026-10-23T12:00:00Z, 2001:db8:1::42, true",
            "2026-10-23T12:00:00Z, 2001:db8:2::42, false",
            "2026-10-23T12:00:00Z, localhost, false"
    })
    void enforcesTimeBoundariesWeekdaysAndIpv4Ipv6Networks(String instant, String address, boolean expected) {
        assertThat(POLICY.permits(subject(Set.of("RESOURCE:READ")), resource(),
                environment(instant, address), ResourceAction.READ)).isEqualTo(expected);
    }

    @Test
    void convertsToConfiguredTimezoneBeforeApplyingHours() {
        var policy = new DefaultAbacPolicy(new AbacProperties("Asia/Almaty", Set.of(DayOfWeek.FRIDAY),
                LocalTime.of(9, 0), LocalTime.of(17, 0), List.of("10.0.0.0/8")));
        assertThat(policy.permits(subject(Set.of("RESOURCE:READ")), resource(),
                environment("2026-10-23T04:00:00Z", "10.0.0.1"), ResourceAction.READ)).isTrue();
        assertThat(policy.permits(subject(Set.of("RESOURCE:READ")), resource(),
                environment("2026-10-23T12:00:00Z", "10.0.0.1"), ResourceAction.READ)).isFalse();
    }

    @Test
    void emptyAllowlistDeniesAllRequests() {
        assertThat(new DefaultAbacPolicy(properties(List.of())).permits(
                subject(Set.of("RESOURCE:READ")), resource(),
                environment("2026-10-23T12:00:00Z", "10.0.0.1"), ResourceAction.READ)).isFalse();
    }

    @ParameterizedTest
    @ValueSource(strings = {"localhost", "example.com/24", "10.0.0.0/33", "2001:db8::/129",
            "10.0.0.0/-1", "10.0.0.0/", "10.0.0.1/32/32", ":::/32", "127.1", "01.2.3.4"})
    void rejectsInvalidNetworkConfigurationAtStartup(String cidr) {
        assertThatIllegalArgumentException().isThrownBy(() -> properties(List.of(cidr)));
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"localhost", " 10.1.2.3", "10.1.2.3 ", "256.1.1.1", "[::1]",
            "fe80::1%eth0", "1:2:3:4:5:6:7", "1:2:3:4:5:6:7:8:9", ":::", "1::2::3", ":1::2", "1::2:"})
    void malformedRemoteAddressesCannotReachNameResolution(String address) {
        assertThat(NumericIpAddress.isLiteral(address)).isFalse();
    }

    @ParameterizedTest
    @ValueSource(strings = {"0.0.0.0", "255.255.255.255", "::", "::1", "2001:db8::42",
            "1:2:3:4:5:6:7:8", "::ffff:192.0.2.1"})
    void recognizesNumericAddressLiterals(String address) {
        assertThat(NumericIpAddress.isLiteral(address)).isTrue();
    }

    @Test
    void rejectsInvalidHoursAndZone() {
        assertThatIllegalArgumentException().isThrownBy(() -> new AbacProperties("UTC",
                Set.of(DayOfWeek.FRIDAY), LocalTime.NOON, LocalTime.NOON, List.of()));
        assertThatIllegalArgumentException().isThrownBy(() -> new AbacProperties("UTC",
                Set.of(DayOfWeek.FRIDAY), LocalTime.of(17, 0), LocalTime.of(9, 0), List.of()));
        org.junit.jupiter.api.Assertions.assertThrows(java.time.DateTimeException.class,
                () -> new AbacProperties("Invalid/Zone", Set.of(DayOfWeek.FRIDAY),
                        LocalTime.of(9, 0), LocalTime.of(17, 0), List.of()));
    }

    static AbacProperties properties(List<String> networks) {
        return new AbacProperties("UTC", Set.of(DayOfWeek.MONDAY, DayOfWeek.TUESDAY,
                DayOfWeek.WEDNESDAY, DayOfWeek.THURSDAY, DayOfWeek.FRIDAY),
                LocalTime.of(9, 0), LocalTime.of(17, 0), networks);
    }

    private static IamPrincipal subject(Set<String> permissions) {
        return new IamPrincipal(SUBJECT, "analyst@example.com", "Engineering", (short) 2,
                Set.of("ADMIN"), permissions);
    }

    private static ResourceAttributes resource() {
        return new ResourceAttributes(UUID.randomUUID(), SUBJECT, "Engineering", (short) 2);
    }

    private static EnvironmentAttributes environment(String time, String address) {
        return new EnvironmentAttributes(ZonedDateTime.parse(time), address);
    }
}
